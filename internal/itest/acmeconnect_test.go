// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectlistener"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
)

// TestACME_ConnectListenerHostname (#934): the ACME job obtains the certificate of a TLS CONNECT
// listener's hostname, whose HTTP-01 challenge the gateways of the listener's group answer, and
// those gateways' snapshots carry it, no other's; it renews it when due; an uploaded certificate of
// the org that covers the name takes its place; once the hostname lies under no verified domain of
// the org any more, it is not renewed and its row says why; once the listener is gone, it is not
// renewed either.
func TestACME_ConnectListenerHostname(t *testing.T) {
	p := newDataPlane(t)
	c := p.c
	port80 := freeTCPUDPPort(t)
	http80 := addr(port80)
	p.stopGateway()
	p.gwCfg.Listen.HTTP = &http80
	p.startGateway(t)
	_, port443, _ := net.SplitHostPort(p.gwCfg.Listen.TCP)
	tlsPort, _ := strconv.Atoi(port443)
	const name = "proxy.example.com"

	dns, err := acmetest.StartDNS([]string{"example.com"}, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Close)
	pebble, err := acmetest.Start(acmetest.Options{HTTPPort: port80, TLSPort: tlsPort, Resolver: dns.Addr, Validity: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pebble.Close)
	if _, err := settings.UpdateInstance(c.Sys, c.DB, &rpmgrv1.InstanceSettings{AcmeDirectoryUrl: proto.String(pebble.DirectoryURL),
		AcmeEmail: proto.String("ops@example.com")}, &fieldmaskpb.FieldMask{Paths: []string{"acme_directory_url", "acme_email"}}, 0); err != nil {
		t.Fatal(err)
	}
	group := c.DB.Client().Gateway.GetX(c.Sys, p.gatewayID).GatewayGroupID
	listenerPort := freeTCPUDPPort(t)
	var dom *ent.Domain
	var route, listener string
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		d, err := domains.Claim(c.Sys, tx, c.Org, "example.com", true)
		if err != nil {
			return nil, err
		}
		if dom, err = tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Save(c.Sys); err != nil {
			return nil, err
		}
		if _, err := routes.AddPool(c.Sys, tx, c.Org, group, routes.TCP, listenerPort, listenerPort); err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("proxy").SetType("tcp").SetGatewayGroupID(group).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteTCP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetListenerMode(routetcp.ListenerModeHTTPConnect).Exec(c.Sys); err != nil {
			return nil, err
		}
		l, err := routes.JoinListener(c.Sys, tx, r, routes.Listener{Mode: connectlistener.AuthModeTLSBasic, Hostname: name}, listenerPort,
			[]string{"db.internal"})
		if err != nil {
			return nil, err
		}
		route, listener = r.ID, l.ID
		return []string{r.ID, l.ID}, tx.RouteTCP.Update().Where(routetcp.RouteID(r.ID)).SetConnectListenerID(l.ID).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}

	storage := acme.NewChallengeStorage(acme.NewStorage(c.DB, c.Sys, c.Sealer(), lease.New(c.DB, "ctn_test", nil), nil),
		c.Sessions, acme.GatewaysServing(c.DB, c.Sys))
	t.Cleanup(storage.Close)
	m := acme.NewManager(acme.ManagerOptions{DB: c.DB, Sys: c.Sys, Sealer: c.Sealer(), Storage: storage, TrustedRoots: pebble.ServerRoots,
		DisableARI: true, RenewalWindowRatio: 0.9, Logger: c.Logs.Logger(), RetryFirst: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	waitFor(t, "the certificate of the listener's hostname was never obtained", func() bool {
		_ = m.Sync(ctx)
		row := acmeRow(t, p, name)
		return row != nil && row.Status == certificate.StatusActive && len(row.ContentSha256) > 0
	})
	first := acmeRow(t, p, name)

	// The gateway of the listener's group gets it for the hostname, a gateway of another group not.
	other := c.DB.Client().GatewayGroup.Create().SetOrgID(c.Org).SetName("elsewhere").SaveX(c.Sys).ID
	elsewhere := c.DB.Client().Gateway.Create().SetOrgID(c.Org).SetGatewayGroupID(other).SetName("gw-elsewhere").SetSlot(1).
		SetTunnelEndpoints([]string{"gw-elsewhere.example:443"}).SaveX(c.Sys).ID
	served := func(gw string) []string {
		var names []string
		if err := store.ReadTx(c.Sys, c.DB, func(tx *ent.Tx, _ store.Revision) error {
			rs, err := certs.Gateway(c.Sys, tx, snapshot.Agent{Identity: pki.Identity{Org: c.Org, Kind: pki.KindGateway, ID: gw},
				Capabilities: gateway.Capabilities})
			for _, r := range rs {
				if r.GetId() == first.ID {
					names = append(names, r.GetGatewayCertificate().GetHostnames()...)
				}
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return names
	}
	if got := served(p.gatewayID); !slices.Equal(got, []string{name}) {
		t.Fatalf("the listener's gateway serves the certificate for %v", got)
	}
	if got := served(elsewhere); len(got) != 0 {
		t.Fatalf("a gateway of another group got the listener's certificate: %v", got)
	}

	// With 90 % of its one-minute lifetime as the renewal window, it is due after 6 s.
	var renewed *ent.Certificate
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(2 * time.Second) {
		_ = m.Sync(ctx)
		renewed = acmeRow(t, p, name)
		if string(renewed.ContentSha256) != string(first.ContentSha256) || time.Now().After(deadline) {
			break
		}
	}
	if string(renewed.ContentSha256) == string(first.ContentSha256) || renewed.Status != certificate.StatusActive || renewed.ID != first.ID {
		t.Fatalf("the listener's certificate was not renewed in its row: %+v", renewed)
	}

	// An uploaded certificate of the org that covers the name takes its place: ACME leaves the
	// name alone. The row is written without a revision, so no gateway is sent it.
	upload := c.DB.Client().Certificate.Create().SetOrgID(c.Org).SetSource(certificate.SourceUploaded).SetSans([]string{"*.example.com"}).
		SetNotBefore(time.Now()).SetNotAfter(time.Now().Add(24 * time.Hour)).SetChain([]byte{1}).SetKeyEnc([]byte{2}).
		SetContentSha256([]byte{3}).SaveX(c.Sys)
	if _, err := m.RenewAsync(ctx, c.Org, name); !errors.Is(err, acme.ErrNotWanted) {
		t.Fatalf("a renewal on demand of a name an upload covers: %v", err)
	}
	c.DB.Client().Certificate.DeleteOne(upload).ExecX(c.Sys)

	// The domain is no longer verified: no renewal, the reason, and the certificate stays.
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		return []string{dom.ID}, tx.Domain.UpdateOne(dom).SetStatus(domain.StatusPending).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * time.Second) // due again
	if err := m.Sync(ctx); err != nil && !errors.Is(err, acme.ErrConnectNotVerified) {
		t.Logf("sync: %v", err)
	}
	after := acmeRow(t, p, name)
	if string(after.ContentSha256) != string(renewed.ContentSha256) || after.LastError != acme.ErrConnectNotVerified.Error() ||
		after.Status != certificate.StatusActive {
		t.Fatalf("an unverified listener hostname: %+v", after)
	}
	if _, err := m.RenewAsync(ctx, c.Org, name); !errors.Is(err, acme.ErrConnectNotVerified) {
		t.Fatalf("a renewal on demand of an unverified listener hostname: %v", err)
	}

	// Verified again, but the listener is gone with its last route: no renewal.
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		if err := tx.Domain.UpdateOne(dom).SetStatus(domain.StatusVerified).Exec(c.Sys); err != nil {
			return nil, err
		}
		r, err := tx.Route.Get(c.Sys, route)
		if err != nil {
			return nil, err
		}
		if err := routes.Delete(c.Sys, tx, r); err != nil {
			return nil, err
		}
		if n, err := tx.ConnectListener.Query().Where(connectlistener.ID(listener)).Count(c.Sys); err != nil || n != 0 {
			return nil, errors.Join(err, errors.New("the listener outlived its last route"))
		}
		return []string{dom.ID, route, listener}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RenewAsync(ctx, c.Org, name); !errors.Is(err, acme.ErrNotWanted) {
		t.Fatalf("a renewal on demand of a removed listener's hostname: %v", err)
	}
	_ = m.Sync(ctx)
	if gone := acmeRow(t, p, name); string(gone.ContentSha256) != string(after.ContentSha256) {
		t.Fatalf("the hostname of a removed listener was renewed: %+v", gone)
	}
}
