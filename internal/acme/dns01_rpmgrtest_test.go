// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package acme_test

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/dnsadapter"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsratebudget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const (
	cfToken = "a-token-of-the-test-0123456789"
	cfTD    = "rpmgr-teststor"
	marker  = "rpmgr " + cfTD + " acme"
)

// The zones of the fake account, which the fake DNS serves too.
var cfZones = []string{"example.com", "held.test", "disabled.test", "shared.test"}

type dnsClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *dnsClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *dnsClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// dns01Env is an instance with a test CA, a fake Cloudflare account whose zones a fake
// authoritative DNS serves, and two orgs.
type dns01Env struct {
	t         *testing.T
	db        *store.DB
	sys       context.Context
	clk       *dnsClock
	cf        *cftest.Server
	sealer    *secret.Sealer
	store     *acme.Storage
	pebble    *acmetest.Pebble
	orgA      string
	orgB      string
	zone      map[string]cftest.Zone // of the fake account, by name
	prov      map[string]string      // provider row of each org
	resolvers []string

	mu      sync.Mutex
	markers map[string]bool // the comments of the TXT records the CA looked at
}

func newDNS01Env(t *testing.T) *dns01Env {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	e := &dns01Env{t: t, db: db, sys: storetest.SystemCtx(t), clk: &dnsClock{t: time.Now()}, zone: map[string]cftest.Zone{},
		prov: map[string]string{}, markers: map[string]bool{}}
	e.orgA, e.orgB = storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
	e.cf = cftest.New(t, cfToken)
	for _, z := range cfZones {
		e.zone[z] = e.cf.AddZone(z)
	}
	kek, _ := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	e.sealer, _ = secret.NewSealer(kek)
	for _, org := range []string{e.orgA, e.orgB} {
		pid := ids.New("dnp")
		sealed, err := e.sealer.Seal(providers.SecretContext(pid), secret.New(cfToken))
		if err != nil {
			t.Fatal(err)
		}
		db.Client().DNSProvider.Create().SetID(pid).SetOrgID(org).SetKind("cloudflare").SetName("cf").SetCredentialEnc(sealed).ExecX(e.sys)
		e.prov[org] = pid
	}
	srv, err := acmetest.StartDNS(cfZones, e.txt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	// Nothing listens for HTTP-01 or TLS-ALPN-01: a name outside a managed zone cannot be issued.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	e.pebble, err = acmetest.Start(acmetest.Options{HTTPPort: closed, TLSPort: closed, Resolver: srv.Addr, Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.pebble.Close)
	if _, err := settings.UpdateInstance(e.sys, db, &rpmgrv1.InstanceSettings{AcmeDirectoryUrl: proto.String(e.pebble.DirectoryURL),
		AcmeEmail: proto.String("ops@example.com")}, &fieldmaskpb.FieldMask{Paths: []string{"acme_directory_url", "acme_email"}}, 0); err != nil {
		t.Fatal(err)
	}
	e.store = acme.NewStorage(db, e.sys, e.sealer, lease.New(db, "ctn_test", nil), nil)
	t.Cleanup(e.store.Close)
	e.resolvers = []string{srv.Addr}
	return e
}

// txt is the fake DNS's TXT answer: the content of every TXT record at fqdn in the fake account.
func (e *dns01Env) txt(fqdn string) []string {
	var out []string
	for _, z := range e.zone {
		for _, r := range e.cf.Records(z.ID) {
			if r.Type == "TXT" && r.Name == fqdn {
				out = append(out, r.Content)
				e.mu.Lock()
				e.markers[r.Comment] = true
				e.mu.Unlock()
			}
		}
	}
	return out
}

// managedZone makes zone a managed zone of org in the given state.
func (e *dns01Env) managedZone(org, name string, state dnszone.SyncState) *ent.DNSZone {
	e.t.Helper()
	return e.db.Client().DNSZone.Create().SetOrgID(org).SetDNSProviderID(e.prov[org]).SetProviderZoneID(e.zone[name].ID).SetName(name).
		SetSyncState(state).SaveX(e.sys)
}

// route creates an enabled http route of org in acme mode with the hostnames, and verifies the
// domains they lie under.
func (e *dns01Env) route(org string, apexes []string, hostnames ...string) {
	e.t.Helper()
	c := e.db.Client()
	for _, a := range apexes {
		c.Domain.Create().SetOrgID(org).SetFqdn(a).SetWildcard(true).SetStatus(domain.StatusVerified).SetChallengeValue("cv").ExecX(e.sys)
	}
	grp := c.GatewayGroup.Create().SetOrgID(org).SetName("edge-" + strings.ToLower(ids.New("rt")[3:12])).SaveX(e.sys).ID
	if _, err := store.ConfigTx(e.sys, e.db, func(tx *ent.Tx) ([]string, error) {
		r, err := tx.Route.Create().SetOrgID(org).SetName("web-" + strings.ToLower(ids.New("rt")[3:12])).SetType("http").SetGatewayGroupID(grp).Save(e.sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteHTTP.Create().SetOrgID(org).SetRouteID(r.ID).Exec(e.sys); err != nil {
			return nil, err
		}
		for _, h := range hostnames {
			if _, err := routes.AddHostname(e.sys, tx, r.ID, h, ""); err != nil {
				return nil, err
			}
		}
		return []string{r.ID}, nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

// manager returns a Manager with DNS-01 on, whose clocks are the test's.
func (e *dns01Env) manager() *acme.Manager {
	return acme.NewManager(acme.ManagerOptions{DB: e.db, Sys: e.sys, Sealer: e.sealer, Storage: e.store, TrustedRoots: e.pebble.ServerRoots,
		DisableARI: true, RetryFirst: time.Millisecond, Now: e.clk.now,
		DNS: &acme.DNS01{TrustDomain: cfTD, Resolvers: e.resolvers, PropagationTimeout: -1, // the fake has no name servers to ask
			Budget: &budget.Budget{DB: e.db, Now: e.clk.now}, Dial: e.dial}})
}

func (e *dns01Env) dial(_, _ string, tok secret.Value) (dns.Provider, error) {
	return cloudflare.NewForTest(cloudflare.Config{Token: tok, Now: e.clk.now}, e.cf.URL(), e.cf.RootCAs())
}

func (e *dns01Env) row(org, name string) *ent.Certificate {
	e.t.Helper()
	var row *ent.Certificate
	if err := store.ReadTx(e.sys, e.db, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		row, err = certs.ACMERow(e.sys, tx, org, name)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return row
}

// wantIssued fails unless the name has an active ACME certificate.
func (e *dns01Env) wantIssued(org, name string) {
	e.t.Helper()
	if r := e.row(org, name); r == nil || r.Status != certificate.StatusActive || r.LastError != "" || !slices.Contains(r.Sans, name) {
		e.t.Errorf("%s: %+v, want an issued certificate", name, r)
	}
}

// wantFailed fails unless the name has no certificate and the row says why.
func (e *dns01Env) wantFailed(org, name string, reason error) {
	e.t.Helper()
	r := e.row(org, name)
	if r == nil || r.Status != certificate.StatusFailed || !strings.Contains(r.LastError, reason.Error()) {
		e.t.Errorf("%s: %+v, want failed with %q", name, r, reason)
	}
}

// providerRequestsFor counts the requests of the fake account that name the zone.
func (e *dns01Env) providerRequestsFor(zone string) int {
	n := 0
	for _, r := range e.cf.Requests() {
		if strings.Contains(r, e.zone[zone].ID) {
			n++
		}
	}
	return n
}

func (e *dns01Env) txtRecords(zone string) []cftest.Record {
	var out []cftest.Record
	for _, r := range e.cf.Records(e.zone[zone].ID) {
		if r.Type == "TXT" {
			out = append(out, r)
		}
	}
	return out
}

func (e *dns01Env) dns01Used(org string) int {
	row, err := e.db.Client().DNSRateBudget.Query().Where(dnsratebudget.DNSProviderID(e.prov[org])).Only(e.sys)
	if err != nil {
		e.t.Fatal(err)
	}
	return row.Dns01Used
}

// TestACME_DNS01OnlyManagedZones (docs/12-testing-and-quality.md): a hostname in a managed zone of
// the route's org gets its certificate by DNS-01, a wildcard there too; one in a held zone does,
// one in a disabled zone is refused with the reason, and one in another org's zone or in no zone
// never reaches a provider. The challenge TXT carries the marker, is deleted after the order, and
// a record of someone else at the same name stays.
func TestACME_DNS01OnlyManagedZones(t *testing.T) {
	e := newDNS01Env(t)
	e.managedZone(e.orgA, "example.com", dnszone.SyncStateActive)
	e.managedZone(e.orgA, "held.test", dnszone.SyncStateHeld)
	e.managedZone(e.orgA, "disabled.test", dnszone.SyncStateDisabled)
	e.managedZone(e.orgB, "shared.test", dnszone.SyncStateActive)
	e.route(e.orgA, []string{"example.com", "held.test", "disabled.test", "shared.test", "other.example"},
		"app.example.com", "*.example.com", "app.held.test", "app.disabled.test", "app.shared.test", "plain.other.example")
	ex := e.zone["example.com"].ID
	foreign := e.cf.AddRecord(ex, cftest.Record{Type: "TXT", Name: "_acme-challenge.app.example.com", Content: "someone-elses-challenge", TTL: 120})
	other := e.cf.AddRecord(ex, cftest.Record{Type: "TXT", Name: "_acme-challenge.app.example.com", Content: "another-instance", TTL: 120,
		Comment: "rpmgr other-instance acme"})

	if err := e.manager().Sync(e.sys); err == nil {
		t.Fatal("Sync reported no error although names are refused")
	}
	for _, name := range []string{"app.example.com", "*.example.com"} {
		e.wantIssued(e.orgA, name)
	}
	e.wantIssued(e.orgA, "app.held.test")
	e.wantFailed(e.orgA, "app.disabled.test", dnsadapter.ErrZoneDisabled)
	for _, name := range []string{"app.shared.test", "plain.other.example"} {
		if r := e.row(e.orgA, name); r == nil || r.Status != certificate.StatusFailed {
			t.Errorf("%s: %+v, want failed (HTTP-01, which nothing answers)", name, r)
		}
	}

	// Neither a disabled zone nor another org's zone saw a request.
	for _, z := range []string{"disabled.test", "shared.test"} {
		if n := e.providerRequestsFor(z); n != 0 {
			t.Errorf("%d requests named the zone %s", n, z)
		}
	}
	if !e.markers[marker] {
		t.Errorf("the CA looked at TXT records with the comments %v, want %q", e.markers, marker)
	}
	// Every challenge TXT is gone; the two records of others stay as they were.
	if got := e.txtRecords("example.com"); len(got) != 2 || !slices.ContainsFunc(got, func(r cftest.Record) bool { return r.ID == foreign.ID }) ||
		!slices.ContainsFunc(got, func(r cftest.Record) bool { return r.ID == other.ID }) {
		t.Errorf("TXT records in example.com after the orders: %+v", got)
	}
	if got := e.txtRecords("held.test"); len(got) != 0 {
		t.Errorf("TXT records in held.test after the order: %+v", got)
	}
	if n := e.dns01Used(e.orgA); n == 0 || n > budget.Dns01Limit {
		t.Errorf("DNS-01 took %d requests, want some and at most %d", n, budget.Dns01Limit)
	}
}

// DNS-01 clause of TestDNS_RateBudgetAndRetryAfter (docs/12-testing-and-quality.md): a 429 in the
// middle of an order fails it, nothing more is sent before the block ends, the order is retried
// when it has, and DNS-01 never takes more than its half of the window.
func TestDNS_RateBudgetAndRetryAfter(t *testing.T) {
	t.Run("429 with retry-after", func(t *testing.T) {
		e := newDNS01Env(t)
		e.managedZone(e.orgA, "example.com", dnszone.SyncStateActive)
		e.route(e.orgA, []string{"example.com"}, "app.example.com")
		m, replica := e.manager(), e.manager()
		e.cf.Fail(cftest.Fault{Status: 429, RetryAfter: "600"})
		err := m.Sync(e.sys)
		var rl dns.RateLimited
		if !errors.As(err, &rl) {
			t.Fatalf("Sync: %v, want the provider's rate limit", err)
		}
		if r := e.row(e.orgA, "app.example.com"); r == nil || r.Status != certificate.StatusFailed {
			t.Fatalf("the row %+v", r)
		}
		sent := e.cf.Count("")
		// Another replica, which took the job over and knows of the failed row only, finds the same
		// block in the database.
		if err := replica.Sync(e.sys); !errors.As(err, &rl) {
			t.Fatalf("the other replica: %v, want the block", err)
		}
		if n := e.cf.Count(""); n != sent {
			t.Fatalf("the other replica sent %d requests during the block", n-sent)
		}
		// The wait of the retry is the block, not the first minute: nothing is sent before it ends.
		for _, d := range []time.Duration{time.Minute, 5 * time.Minute} {
			e.clk.add(d)
			if err := m.Sync(e.sys); err != nil {
				t.Fatalf("Sync during the block: %v", err)
			}
			if n := e.cf.Count(""); n != sent {
				t.Fatalf("%d requests went to the provider during the block", n-sent)
			}
		}
		e.clk.add(5 * time.Minute) // past the 600 s
		if err := m.Sync(e.sys); err != nil {
			t.Fatalf("Sync after the block: %v", err)
		}
		e.wantIssued(e.orgA, "app.example.com")
		if got := e.txtRecords("example.com"); len(got) != 0 {
			t.Errorf("TXT records left: %+v", got)
		}
	})

	t.Run("the DNS-01 half is spent", func(t *testing.T) {
		e := newDNS01Env(t)
		e.managedZone(e.orgA, "example.com", dnszone.SyncStateActive)
		e.route(e.orgA, []string{"example.com"}, "app.example.com")
		now := e.clk.now()
		e.db.Client().DNSRateBudget.Create().SetOrgID(e.orgA).SetDNSProviderID(e.prov[e.orgA]).SetWindowStartedAt(now).
			SetUsed(budget.Dns01Limit).SetDns01Used(budget.Dns01Limit).ExecX(e.sys)
		m := e.manager()
		err := m.Sync(e.sys)
		var rl dns.RateLimited
		if !errors.As(err, &rl) {
			t.Fatalf("Sync: %v, want the budget's refusal", err)
		}
		if n := e.cf.Count(""); n != 0 {
			t.Fatalf("%d requests went out although DNS-01's half is spent", n)
		}
		if n := e.dns01Used(e.orgA); n != budget.Dns01Limit {
			t.Fatalf("DNS-01 used %d, want it left at %d", n, budget.Dns01Limit)
		}
		// The job's half is untouched: the window has room, but the retry waits for the next one.
		e.clk.add(budget.Window + time.Second)
		if err := m.Sync(e.sys); err != nil {
			t.Fatalf("Sync in the next window: %v", err)
		}
		e.wantIssued(e.orgA, "app.example.com")
		if n := e.dns01Used(e.orgA); n == 0 || n > budget.Dns01Limit {
			t.Fatalf("DNS-01 used %d in the new window, want some and at most %d", n, budget.Dns01Limit)
		}
	})
}

// A wildcard of an acme route needs a managed zone of its org: without one, or after the zone was
// removed, it gets no order and the reason; a wildcard in a zone of another org is no exception.
func TestACME_DNS01WildcardNeedsManagedZone(t *testing.T) {
	e := newDNS01Env(t)
	z := e.managedZone(e.orgA, "example.com", dnszone.SyncStateActive)
	e.managedZone(e.orgB, "shared.test", dnszone.SyncStateActive)
	e.route(e.orgA, []string{"example.com", "shared.test"}, "*.example.com", "*.shared.test")
	e.db.Client().DNSZone.DeleteOneID(z.ID).ExecX(e.sys) // removed before the order
	err := e.manager().Sync(e.sys)
	if !errors.Is(err, acme.ErrWildcard) {
		t.Fatalf("Sync: %v, want %v", err, acme.ErrWildcard)
	}
	e.wantFailed(e.orgA, "*.example.com", acme.ErrWildcard)
	e.wantFailed(e.orgA, "*.shared.test", acme.ErrWildcard)
	if n := e.cf.Count(""); n != 0 {
		t.Errorf("%d requests went to the provider", n)
	}
	if n := e.pebble.NewOrders.Load(); n != 0 {
		t.Errorf("%d orders at the CA", n)
	}
}

// Without DNS-01 (the option unset) every name keeps HTTP-01 and TLS-ALPN-01 and a wildcard has no
// certificate, as before this slice.
func TestACME_DNS01Off(t *testing.T) {
	e := newDNS01Env(t)
	e.managedZone(e.orgA, "example.com", dnszone.SyncStateActive)
	e.route(e.orgA, []string{"example.com"}, "*.example.com")
	m := acme.NewManager(acme.ManagerOptions{DB: e.db, Sys: e.sys, Sealer: e.sealer, Storage: e.store, TrustedRoots: e.pebble.ServerRoots})
	if err := m.Sync(e.sys); !errors.Is(err, acme.ErrWildcard) {
		t.Fatalf("Sync: %v, want %v", err, acme.ErrWildcard)
	}
	e.wantFailed(e.orgA, "*.example.com", acme.ErrWildcard)
}

// The controller's own certificate stays on HTTP-01 and TLS-ALPN-01 even where its name lies in a
// managed zone: it has no DNS-01 solver and asks no provider (D166).
func TestACME_OwnCertificateNeverUsesDNS01(t *testing.T) {
	e := newDNS01Env(t)
	e.managedZone(e.orgA, "example.com", dnszone.SyncStateActive)
	own, err := acme.NewOwn(acme.OwnOptions{DB: e.db, Sys: e.sys, Storage: e.store, Host: "controller.example.com", NoHTTP01: true,
		TrustedRoots: e.pebble.ServerRoots})
	if err != nil {
		t.Fatal(err)
	}
	defer own.Stop()
	if acme.OwnDNS01(own) {
		t.Fatal("the controller's own certificate has a DNS-01 solver")
	}
	ctx, cancel := context.WithTimeout(e.sys, 2*time.Second)
	defer cancel()
	_ = own.Manage(ctx)
	<-ctx.Done()
	if n := e.cf.Count(""); n != 0 {
		t.Fatalf("%d requests went to the provider", n)
	}
}
