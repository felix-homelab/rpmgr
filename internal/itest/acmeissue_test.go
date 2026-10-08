// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// TestACME_Issuance: the controller's ACME job obtains the certificate of an http route in acme
// mode from a real ACME server (in-process Pebble), whose validation the gateway role answers
// over its control session; the certificate reaches the gateway, which then serves HTTPS with it;
// a renewal replaces it; a wildcard hostname gets no certificate and the reason; a hostname the
// CA cannot validate gets a failed row with the CA's error; the ACME client goes through the
// configured proxy.
func TestACME_Issuance(t *testing.T) {
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
	dns.SetA("unreachable.example.com", net.IPv4(127, 0, 0, 2)) // nothing listens there
	pebble, err := acmetest.Start(acmetest.Options{HTTPPort: port80, TLSPort: tlsPort, Resolver: dns.Addr, Validity: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pebble.Close)
	if _, err := settings.UpdateInstance(c.Sys, c.DB, &rpmgrv1.InstanceSettings{AcmeDirectoryUrl: proto.String(pebble.DirectoryURL),
		AcmeEmail: proto.String("ops@example.com")}, &fieldmaskpb.FieldMask{Paths: []string{"acme_directory_url", "acme_email"}}, 0); err != nil {
		t.Fatal(err)
	}

	app := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello over acme")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ln) }()
	t.Cleanup(func() { _ = app.Close() })
	appPort := ln.Addr().(*net.TCPAddr).Port
	if err := writePolicy(p, appPort); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		tcp, err := tx.Route.Get(c.Sys, p.routeID)
		if err != nil {
			return nil, err
		}
		d, err := domains.Claim(c.Sys, tx, c.Org, "example.com", true)
		if err != nil {
			return nil, err
		}
		if err := tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(c.Sys); err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("web").SetType("http").SetGatewayGroupID(tcp.GatewayGroupID).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteHTTP.Create().SetOrgID(c.Org).SetRouteID(r.ID).Exec(c.Sys); err != nil { // acme mode by default
			return nil, err
		}
		for _, h := range []string{"app.example.com", "*.wild.example.com", "unreachable.example.com"} {
			if _, err := routes.AddHostname(c.Sys, tx, r.ID, h, ""); err != nil {
				return nil, err
			}
		}
		return []string{r.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(p.connector).SetKind("address").
			SetHost("127.0.0.1").SetPort(appPort).SetUpstreamProtocol(routetarget.UpstreamProtocolHTTP).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}

	var proxied atomic.Int64
	storage := acme.NewChallengeStorage(acme.NewStorage(c.DB, c.Sys, c.Sealer(), lease.New(c.DB, "ctn_test", nil), nil),
		c.Sessions, acme.GatewaysServing(c.DB, c.Sys))
	t.Cleanup(storage.Close)
	m := acme.NewManager(acme.ManagerOptions{DB: c.DB, Sys: c.Sys, Sealer: c.Sealer(), Storage: storage, TrustedRoots: pebble.ServerRoots,
		DisableARI: true, RenewalWindowRatio: 0.9,
		Proxy: func(*http.Request) (*url.URL, error) { proxied.Add(1); return nil, nil }})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// The gateway acknowledges challenges only once its control session is up.
	waitFor(t, "the certificate of app.example.com was never obtained", func() bool {
		_ = m.Sync(ctx)
		row := acmeRow(t, p, "app.example.com")
		return row != nil && row.Status == certificate.StatusActive && len(row.ContentSha256) > 0
	})
	first := acmeRow(t, p, "app.example.com")
	if proxied.Load() == 0 {
		t.Fatal("the ACME client never asked for its proxy")
	}
	if w := acmeRow(t, p, "*.wild.example.com"); w == nil || w.Status != certificate.StatusFailed || w.LastError != acme.ErrWildcard.Error() {
		t.Fatalf("the wildcard: %+v", w)
	}
	if u := acmeRow(t, p, "unreachable.example.com"); u == nil || u.Status != certificate.StatusFailed || u.LastError == "" {
		t.Fatalf("a name the CA cannot validate: %+v", u)
	}

	// The gateway serves the certificate, which chains to Pebble's root.
	roots, err := pebble.IssuanceRoots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, p.gwCfg.Listen.TCP)
		}}}
	var body string
	waitFor(t, "the gateway does not serve the ACME certificate", func() bool {
		resp, err := client.Get("https://app.example.com/")
		if err != nil {
			body = err.Error()
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		body = string(b)
		return resp.StatusCode == http.StatusOK
	})
	if body != "hello over acme" {
		t.Fatalf("body %q", body)
	}

	// With 90 % of its one-minute lifetime as the renewal window, the certificate is due after 6 s.
	var renewed *ent.Certificate
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(2 * time.Second) {
		_ = m.Sync(ctx) // the two failing names fail again
		renewed = acmeRow(t, p, "app.example.com")
		if string(renewed.ContentSha256) != string(first.ContentSha256) || time.Now().After(deadline) {
			break
		}
	}
	if string(renewed.ContentSha256) == string(first.ContentSha256) || renewed.Status != certificate.StatusActive || renewed.ID != first.ID {
		t.Fatalf("the certificate was not renewed in its row: %+v", renewed)
	}
}

// writePolicy allows the connector to reach ports of 127.0.0.1.
func writePolicy(p *dataPlane, ports ...int) error {
	list := make([]string, len(ports))
	for i, port := range ports {
		list[i] = strconv.Itoa(port)
	}
	return os.WriteFile(p.conCfg.PolicyFile, []byte("version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: ["+
		strings.Join(list, ", ")+"]\n"), 0o600)
}

// acmeRow returns the ACME certificate row of a hostname, or nil.
func acmeRow(t *testing.T, p *dataPlane, name string) *ent.Certificate {
	t.Helper()
	var row *ent.Certificate
	if err := store.ReadTx(p.c.Sys, p.c.DB, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		row, err = certs.ACMERow(p.c.Sys, tx, p.c.Org, name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return row
}
