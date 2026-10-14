// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
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

// TestACME_FailedNameRetries (docs/04-security.md, "Controller certificates"): a hostname the CA
// cannot validate fails once at the CA, then waits 1, 2, 4 … minutes by the clock, and every retry
// rehearses at the test CA, so that the CA sees no further order for it: not from a later pass,
// not from "Renew now", which retries at once, and not from a controller that starts anew, which
// takes the failed row's hostname as failed. Once DNS points at the gateway, the next retry passes
// the test CA and the CA issues the certificate.
func TestACME_FailedNameRetries(t *testing.T) {
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
	const name = "late.example.com"
	dns.SetA(name, net.IPv4(127, 0, 0, 2)) // DNS does not point at the gateway yet
	ca, err := acmetest.Start(acmetest.Options{HTTPPort: port80, TLSPort: tlsPort, Resolver: dns.Addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Close)
	testCA, err := acmetest.Start(acmetest.Options{HTTPPort: port80, TLSPort: tlsPort, Resolver: dns.Addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(testCA.Close)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.ServerCertPEM())
	roots.AppendCertsFromPEM(testCA.ServerCertPEM())
	if _, err := settings.UpdateInstance(c.Sys, c.DB, &rpmgrv1.InstanceSettings{AcmeDirectoryUrl: proto.String(ca.DirectoryURL),
		AcmeEmail: proto.String("ops@example.com")}, &fieldmaskpb.FieldMask{Paths: []string{"acme_directory_url", "acme_email"}}, 0); err != nil {
		t.Fatal(err)
	}
	acmeHTTPRoute(t, p, name)

	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	storage := acme.NewChallengeStorage(acme.NewStorage(c.DB, c.Sys, c.Sealer(), lease.New(c.DB, "ctn_test", nil), nil),
		c.Sessions, acme.GatewaysServing(c.DB, c.Sys))
	t.Cleanup(storage.Close)
	logs := &lockedBuffer{} // to see when "Renew now" has ended
	manager := func() *acme.Manager {
		return acme.NewManager(acme.ManagerOptions{DB: c.DB, Sys: c.Sys, Sealer: c.Sealer(), Storage: storage, TrustedRoots: roots,
			DisableARI: true, TestCA: testCA.DirectoryURL, Now: clock, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	}
	m := manager()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	orders := func() (int, int) { return ca.OrdersFor(name), testCA.OrdersFor(name) }

	// The first attempt orders at the CA and fails.
	if err := m.Sync(ctx); err == nil {
		t.Fatal("the first attempt for a name DNS does not point at the gateway succeeded")
	}
	if row := acmeRow(t, p, name); row == nil || row.Status != certificate.StatusFailed {
		t.Fatalf("the failed name's row: %+v", row)
	}
	atCA, atTest := orders()
	if atCA == 0 || atTest != 0 {
		t.Fatalf("after the first attempt: %d orders at the CA, %d at the test CA; want some and none", atCA, atTest)
	}
	retry := func(what string) {
		t.Helper()
		_ = m.Sync(ctx)
		ca2, test2 := orders()
		if ca2 != atCA || test2 <= atTest {
			t.Fatalf("%s: orders at the CA %d → %d, at the test CA %d → %d; want the CA's unchanged and the test CA's more", what, atCA, ca2, atTest, test2)
		}
		atTest = test2
	}
	still := func(what string) {
		t.Helper()
		_ = m.Sync(ctx)
		if ca2, test2 := orders(); ca2 != atCA || test2 != atTest {
			t.Fatalf("%s: orders at the CA %d → %d, at the test CA %d → %d; want none", what, atCA, ca2, atTest, test2)
		}
	}

	// It waits a minute, then two, and each retry rehearses at the test CA, where it fails.
	still("a pass before the first wait is over")
	advance(acme.RetryFirst)
	retry("the first retry")
	advance(acme.RetryFirst)
	still("a pass one minute into the two-minute wait")
	advance(acme.RetryFirst)
	retry("the second retry")

	// A controller that starts anew knows nothing of the failures but the failed row, and rehearses.
	m = manager()
	retry("the first pass of a new manager")

	// "Renew now" does not wait for the four minutes now due, and rehearses too.
	if started, err := m.RenewAsync(ctx, c.Org, name); err != nil || !started {
		t.Fatalf("renew now: %t %v", started, err)
	}
	waitFor(t, "renew now never failed", func() bool { return strings.Contains(logs.String(), "route certificate not renewed") })
	if ca2, test2 := orders(); ca2 != atCA || test2 <= atTest {
		t.Fatalf("renew now: orders at the CA %d → %d, at the test CA %d → %d; want the CA's unchanged and the test CA's more",
			atCA, ca2, atTest, test2)
	}
	_, atTest = orders()

	// Once DNS points at the gateway, the next retry passes the test CA, and the CA issues.
	dns.SetA(name, net.IPv4(127, 0, 0, 1))
	waitFor(t, "the certificate was not obtained once DNS pointed at the gateway", func() bool {
		advance(acme.RetryMax)
		_ = m.Sync(ctx)
		row := acmeRow(t, p, name)
		return row != nil && row.Status == certificate.StatusActive && len(row.ContentSha256) > 0
	})
	if ca2, test2 := orders(); ca2 <= atCA || test2 <= atTest {
		t.Fatalf("orders at the CA %d → %d, at the test CA %d → %d; want more at both", atCA, ca2, atTest, test2)
	}
	atCA, atTest = orders()
	advance(acme.RetryMax)
	still("a pass once the certificate is there")
}

// lockedBuffer is a buffer that a logger writes and a test reads at the same time.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// acmeHTTPRoute adds an http route in acme mode with the hostnames, under the verified domain
// example.com, whose target is a local web server the connector's policy allows.
func acmeHTTPRoute(t *testing.T, p *dataPlane, hostnames ...string) {
	t.Helper()
	c := p.c
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
		for _, h := range hostnames {
			if _, err := routes.AddHostname(c.Sys, tx, r.ID, h, ""); err != nil {
				return nil, err
			}
		}
		return []string{r.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(p.connector).SetKind("address").
			SetHost("127.0.0.1").SetPort(appPort).SetUpstreamProtocol(routetarget.UpstreamProtocolHTTP).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
}
