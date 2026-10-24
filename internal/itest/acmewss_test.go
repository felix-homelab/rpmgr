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

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// TestACME_WSSHostname (#636): the ACME job obtains the certificate of a gateway's WSS hostname,
// whose HTTP-01 challenge that gateway answers, and the gateway's snapshot carries it; it renews
// it when due; once the hostname lies under no verified domain of the gateway's org any more, the
// certificate is not renewed and its row says why, while the certificate it has stays.
func TestACME_WSSHostname(t *testing.T) {
	p := newDataPlane(t)
	c := p.c
	port80 := freeTCPUDPPort(t)
	http80 := addr(port80)
	p.stopGateway()
	p.gwCfg.Listen.HTTP = &http80
	p.startGateway(t)
	_, port443, _ := net.SplitHostPort(p.gwCfg.Listen.TCP)
	tlsPort, _ := strconv.Atoi(port443)

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
	var dom *ent.Domain
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		d, err := domains.Claim(c.Sys, tx, c.Org, "example.com", true)
		if err != nil {
			return nil, err
		}
		if dom, err = tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Save(c.Sys); err != nil {
			return nil, err
		}
		gw, err := routes.SetWSSHostname(c.Sys, tx, p.gatewayID, "tunnel.example.com")
		if err != nil {
			return nil, err
		}
		return []string{gw.ID}, nil
	}); err != nil {
		t.Fatal(err)
	}

	storage := acme.NewChallengeStorage(acme.NewStorage(c.DB, c.Sys, c.Sealer(), lease.New(c.DB, "ctn_test", nil), nil),
		c.Sessions, acme.GatewaysServing(c.DB, c.Sys))
	t.Cleanup(storage.Close)
	m := acme.NewManager(acme.ManagerOptions{DB: c.DB, Sys: c.Sys, Sealer: c.Sealer(), Storage: storage, TrustedRoots: pebble.ServerRoots,
		DisableARI: true, RenewalWindowRatio: 0.9, Logger: c.Logs.Logger(), RetryFirst: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	waitFor(t, "the certificate of the WSS hostname was never obtained", func() bool {
		_ = m.Sync(ctx)
		row := acmeRow(t, p, "tunnel.example.com")
		return row != nil && row.Status == certificate.StatusActive && len(row.ContentSha256) > 0
	})
	first := acmeRow(t, p, "tunnel.example.com")

	// The gateway's snapshot carries it for the WSS hostname.
	if err := store.ReadTx(c.Sys, c.DB, func(tx *ent.Tx, _ store.Revision) error {
		rs, err := certs.Gateway(c.Sys, tx, snapshot.Agent{Identity: pki.Identity{Org: c.Org, Kind: pki.KindGateway, ID: p.gatewayID}})
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(rs, func(r *agentv1.Resource) bool { return r.GetId() == first.ID }) {
			return errors.New("the gateway's snapshot lacks the WSS certificate")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// With 90 % of its one-minute lifetime as the renewal window, it is due after 6 s.
	var renewed *ent.Certificate
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(2 * time.Second) {
		_ = m.Sync(ctx)
		renewed = acmeRow(t, p, "tunnel.example.com")
		if string(renewed.ContentSha256) != string(first.ContentSha256) || time.Now().After(deadline) {
			break
		}
	}
	if string(renewed.ContentSha256) == string(first.ContentSha256) || renewed.Status != certificate.StatusActive || renewed.ID != first.ID {
		t.Fatalf("the WSS certificate was not renewed in its row: %+v", renewed)
	}

	// The domain is no longer verified: no renewal, the reason, and the certificate stays.
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		return []string{dom.ID}, tx.Domain.UpdateOne(dom).SetStatus(domain.StatusPending).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * time.Second) // due again
	if err := m.Sync(ctx); err != nil && !errors.Is(err, acme.ErrWSSNotVerified) {
		t.Logf("sync: %v", err)
	}
	after := acmeRow(t, p, "tunnel.example.com")
	if string(after.ContentSha256) != string(renewed.ContentSha256) || after.LastError != acme.ErrWSSNotVerified.Error() ||
		after.Status != certificate.StatusActive {
		t.Fatalf("an unverified WSS hostname: %+v", after)
	}
	if _, err := m.RenewAsync(ctx, after.OrgID, "tunnel.example.com"); !errors.Is(err, acme.ErrWSSNotVerified) {
		t.Fatalf("a renewal on demand of an unverified WSS hostname: %v", err)
	}
}
