// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package job_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/job"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const (
	token = "a-token-of-the-test-0123456789"
	td    = "rpmgr-teststor"
	apex  = "example.com"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// env is one org with an active zone at the fake provider, a gateway group with a CNAME target and
// a verified domain, and two replicas of the job sharing one clock.
type env struct {
	t        *testing.T
	db       *store.DB
	sys      context.Context
	clk      *clock
	fake     *cftest.Server
	org      string
	group    string
	domain   string
	zone     *ent.DNSZone
	sealer   *secret.Sealer
	reserved []string

	mu        sync.Mutex
	applyErrs []error // what the next calls of Apply fail with, in order
	reports   []apply.Report
}

func newEnv(t *testing.T, db *store.DB) *env {
	t.Helper()
	storetest.Init(t, db)
	e := &env{t: t, db: db, sys: storetest.SystemCtx(t), clk: &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}}
	e.org = storetest.Org(t, db, "org-a")
	e.fake = cftest.New(t, token)
	kek, _ := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	e.sealer, _ = secret.NewSealer(kek)
	c := db.Client()
	pid := ids.New("dnp")
	sealed, err := e.sealer.Seal(providers.SecretContext(pid), secret.New(token))
	if err != nil {
		t.Fatal(err)
	}
	c.DNSProvider.Create().SetID(pid).SetOrgID(e.org).SetKind("cloudflare").SetName("cf").SetCredentialEnc(sealed).ExecX(e.sys)
	cz := e.fake.AddZone(apex)
	e.zone = c.DNSZone.Create().SetOrgID(e.org).SetDNSProviderID(pid).SetProviderZoneID(cz.ID).SetName(apex).SetSyncState(dnszone.SyncStateActive).SaveX(e.sys)
	e.group = c.GatewayGroup.Create().SetOrgID(e.org).SetName("edge").SetDNSCname("gw.example.net").SaveX(e.sys).ID
	e.domain = c.Domain.Create().SetOrgID(e.org).SetFqdn(apex).SetWildcard(true).SetStatus(domain.StatusVerified).SetChallengeValue("cv").SaveX(e.sys).ID
	return e
}

func (e *env) dial(_, _ string, tok secret.Value) (dns.Provider, error) {
	p, err := cloudflare.NewForTest(cloudflare.Config{Token: tok, Now: e.clk.now}, e.fake.URL(), e.fake.RootCAs())
	return faulty{p, e}, err
}

// failApply makes the next calls of Apply fail with errs, in order, before the provider is asked.
func (e *env) failApply(errs ...error) {
	e.mu.Lock()
	e.applyErrs = append(e.applyErrs, errs...)
	e.mu.Unlock()
}

type faulty struct {
	dns.Provider
	e *env
}

func (f faulty) Apply(ctx context.Context, zone string, b dns.Batch) error {
	f.e.mu.Lock()
	var err error
	if len(f.e.applyErrs) > 0 {
		err, f.e.applyErrs = f.e.applyErrs[0], f.e.applyErrs[1:]
	}
	f.e.mu.Unlock()
	if err != nil {
		return err
	}
	return f.Provider.Apply(ctx, zone, b)
}

func (e *env) replica(holder string) (*job.Job, *lease.Leases) {
	leases := lease.New(e.db, holder, e.clk.now)
	j := job.New(job.Options{DB: e.db, Leases: leases, Sealer: e.sealer, Dial: e.dial, TrustDomain: td, Now: e.clk.now,
		Budget:   &budget.Budget{DB: e.db, Now: e.clk.now},
		Reserved: func(context.Context) []string { return e.reserved },
		Report: func(_ context.Context, _ *ent.DNSZone, r apply.Report) {
			e.mu.Lock()
			e.reports = append(e.reports, r)
			e.mu.Unlock()
		}})
	return j, leases
}

func (e *env) take(l *lease.Leases) lease.Lease {
	e.t.Helper()
	ls, ok, err := l.TryAcquireFor(e.sys, job.LeaseName, job.LeaseTTL)
	if err != nil || !ok {
		e.t.Fatal("no lease", err)
	}
	return ls
}

// addName creates a DNS name in a configuration transaction, which is a revision.
func (e *env) addName(fqdn string) {
	e.t.Helper()
	_, err := store.ConfigTx(e.sys, e.db, func(tx *ent.Tx) ([]string, error) {
		n, err := tx.DNSName.Create().SetOrgID(e.org).SetFqdn(fqdn).SetGatewayGroupID(e.group).SetDomainID(e.domain).Save(e.sys)
		if err != nil {
			return nil, err
		}
		return []string{n.ID}, nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) revision(changed ...string) {
	e.t.Helper()
	if _, err := store.ConfigTx(e.sys, e.db, func(*ent.Tx) ([]string, error) { return changed, nil }); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) statuses() map[string]string {
	out := map[string]string{}
	for _, s := range e.db.Client().DNSNameStatus.Query().AllX(e.sys) {
		out[s.Name] = string(s.Status)
		if s.Reason != "" {
			out[s.Name] += ":" + s.Reason
		}
	}
	return out
}

func (e *env) zoneRow() *ent.DNSZone { return e.db.Client().DNSZone.GetX(e.sys, e.zone.ID) }

// advance moves the clock by d in steps, renewing the lease as its holder does.
func (e *env) advance(l *lease.Leases, ls lease.Lease, d time.Duration) {
	e.t.Helper()
	for ; d > 0; d -= 10 * time.Second {
		e.clk.add(min(d, 10*time.Second))
		if err := l.Renew(e.sys, ls); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) requests() int { return e.fake.Count("") }

func (e *env) names() []string {
	var out []string
	for _, r := range e.fake.Records(e.zone.ProviderZoneID) {
		out = append(out, r.Name)
	}
	slices.Sort(out)
	return out
}

func eqStatuses(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("statuses %v, want %v", got, want)
	}
	for k, w := range want {
		if !strings.HasPrefix(got[k], w) {
			t.Fatalf("statuses %v, want %v", got, want)
		}
	}
}

// TestDNS_LeaseCheckedBeforeBatch: a replica whose dns lease ends within the safety margin sends no
// batch; its pass leaves a creating row and the name pending, and changes nothing at the provider.
// After the lease ran out and another replica took it, the new holder starts with a full pass and
// publishes.
func TestDNS_LeaseCheckedBeforeBatch(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		e.addName("a.example.com")
		ja, la := e.replica("ctn_a")
		lease1 := e.take(la)
		if lease1.Left(e.clk.now()) != job.LeaseTTL {
			t.Fatalf("lease %v", lease1.Left(e.clk.now()))
		}
		// One second less than the margin is left: the batch is not sent.
		e.clk.add(job.LeaseTTL - job.Margin + time.Second)
		if err := ja.Run(e.sys, lease1); err != nil {
			t.Fatal(err)
		}
		if n := e.fake.Count("POST"); n != 0 || len(e.names()) != 0 {
			t.Fatalf("a batch was sent: %d writes, records %v", n, e.names())
		}
		rows := e.db.Client().DNSRecord.Query().AllX(e.sys)
		if len(rows) != 1 || rows[0].State != dnsrecord.StateCreating {
			t.Fatalf("rows %+v", rows)
		}
		eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "pending"})
		if z := e.zoneRow(); z.ProviderStatus != dnszone.ProviderStatusOk || z.LastSyncedAt != nil {
			t.Errorf("a lease that ends says nothing about the provider: %+v", z)
		}
		// Exactly the margin is enough.
		e.clk.add(time.Second)
		jb, lb := e.replica("ctn_b")
		if _, ok, _ := lb.TryAcquireFor(e.sys, job.LeaseName, job.LeaseTTL); ok {
			t.Fatal("taken before it expired")
		}
		e.clk.add(job.Margin) // the lease of A is over
		lease2 := e.take(lb)
		if lease2.Token != lease1.Token+1 {
			t.Fatalf("token %d after %d", lease2.Token, lease1.Token)
		}
		// A replica that lost the lease writes nothing, whatever its own clock says.
		ja.Sync(e.zone.ID)
		if err := ja.Run(e.sys, lease1); !errors.Is(err, lease.ErrLost) {
			t.Fatalf("the old holder: %v", err)
		}
		if e.fake.Count("POST") != 0 {
			t.Fatal("the old holder sent a batch")
		}
		// The new holder's first tick is a full pass.
		if err := jb.Run(e.sys, lease2); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(e.names(), []string{"a.example.com"}) {
			t.Fatalf("records %v", e.names())
		}
		eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published"})
		rows = e.db.Client().DNSRecord.Query().AllX(e.sys)
		if len(rows) != 1 || rows[0].State != dnsrecord.StateSynced {
			t.Fatalf("rows %+v", rows)
		}
		if z := e.zoneRow(); z.LastSyncedAt == nil {
			t.Error("last_synced_at not set")
		}
		// A handle that was not taken from the database has no expiry, and so sends no batch.
		e.addName("b.example.com")
		jb.Sync(e.zone.ID)
		if err := jb.Run(e.sys, lease.Lease{Name: job.LeaseName, Token: lease2.Token}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(e.names(), []string{"a.example.com"}) {
			t.Fatalf("a batch was sent without a lease expiry: %v", e.names())
		}
	})
}

// TestRun_FullPassOnTakeoverAndTimer: after a full pass, a tick with nothing new asks the provider
// for nothing; the timer and a takeover each start a full pass over every zone, which finds drift
// the revisions never told of; "Sync now" runs one zone at once.
func TestRun_FullPassOnTakeoverAndTimer(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.addName("a.example.com")
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.names(), []string{"a.example.com"}) {
		t.Fatalf("records %v", e.names())
	}
	n := e.requests()
	for range 3 {
		e.clk.add(job.PollEvery)
		if err := j.Run(e.sys, ls); err != nil {
			t.Fatal(err)
		}
		_ = l.Renew(e.sys, ls)
	}
	if e.requests() != n {
		t.Fatalf("%d requests while nothing changed", e.requests()-n)
	}
	// Someone else adds a record; only a full pass looks at the provider.
	e.fake.AddRecord(e.zone.ProviderZoneID, cftest.Record{Type: "TXT", Name: "x.example.com", Content: "hello", TTL: 300})
	e.advance(l, ls, job.FullEvery-3*job.PollEvery-time.Second)
	_ = j.Run(e.sys, ls)
	if e.requests() != n {
		t.Fatal("a full pass before its time")
	}
	e.clk.add(2 * time.Second)
	_ = l.Renew(e.sys, ls)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if e.requests() <= n {
		t.Fatal("the timer started no full pass")
	}
	n = e.requests()
	// A new holder of the lease starts with a full pass, though the timer is not due.
	if err := l.Release(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	ls2 := e.take(l)
	if err := j.Run(e.sys, ls2); err != nil {
		t.Fatal(err)
	}
	if e.requests() <= n {
		t.Fatal("a takeover started no full pass")
	}
	// Sync now.
	n = e.requests()
	j.Sync(e.zone.ID)
	if err := j.Run(e.sys, ls2); err != nil || e.requests() <= n {
		t.Fatalf("sync now: %v, %d requests", err, e.requests()-n)
	}
	j.Sync("dnz_01ARZ3NDEKTSV4RRFFQ69G5FAV") // a zone that does not exist is no error
	if err := j.Run(e.sys, ls2); err != nil {
		t.Fatal(err)
	}
}

// TestRun_Debounce: a revision that touches a source starts a pass only after the debounce, a burst
// of revisions makes one pass, a revision that touches no source or changes nothing the zone
// publishes makes none, and Trigger works like a revision.
func TestRun_Debounce(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	if err := j.Run(e.sys, ls); err != nil { // the first tick is the full pass
		t.Fatal(err)
	}
	tick := func(d time.Duration) {
		t.Helper()
		e.clk.add(d)
		_ = l.Renew(e.sys, ls)
		if err := j.Run(e.sys, ls); err != nil {
			t.Fatal(err)
		}
	}
	// A pass lists once, and once more after it created records, to find their IDs by marker.
	lists := func() int { return e.fake.Count("GET /client/v4/zones/" + e.zone.ProviderZoneID + "/dns_records") }

	e.revision("usr_01ARZ3NDEKTSV4RRFFQ69G5FAV") // not a source
	tick(job.Debounce + time.Second)
	if lists() != 1 {
		t.Fatalf("%d listings after a revision that is no source", lists())
	}
	e.addName("a.example.com")
	tick(time.Second) // seen, debouncing
	if lists() != 1 || len(e.names()) != 0 {
		t.Fatalf("a pass inside the debounce: %d listings", lists())
	}
	e.addName("b.example.com") // a burst
	tick(job.Debounce - time.Second)
	if lists() != 1 {
		t.Fatalf("a pass inside the debounce: %d listings", lists())
	}
	tick(time.Second)
	if lists() != 3 || !slices.Equal(e.names(), []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("%d listings, records %v", lists(), e.names())
	}
	eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published", "b.example.com": "published"})
	// A source revision that changes nothing published: compiled the same, no provider call.
	e.revision("dom_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	tick(job.Debounce)
	if lists() != 3 {
		t.Fatalf("%d listings for an unchanged zone", lists())
	}
	// In-process dns_dirty for a zone: compiled the same too; but a removed name is a change.
	j.Trigger(e.zone.ID)
	e.db.Client().DNSName.Delete().ExecX(e.sys)
	tick(job.Debounce)
	if lists() != 4 || len(e.names()) != 0 {
		t.Fatalf("%d listings, records %v", lists(), e.names())
	}
	if len(e.statuses()) != 0 {
		t.Fatalf("statuses of names without a source: %v", e.statuses())
	}
}

// TestRun_NameStatuses: published, conflict (a foreign record in the way), not_managed with its
// reason (a reserved name), held (a held zone writes nothing), and not_managed (a disabled one).
func TestRun_NameStatuses(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.fake.AddRecord(e.zone.ProviderZoneID, cftest.Record{Type: "A", Name: "taken.example.com", Content: "192.0.2.50", TTL: 300})
	e.reserved = []string{"ctl.example.com"}
	for _, n := range []string{"ok.example.com", "taken.example.com", "ctl.example.com"} {
		e.addName(n)
	}
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	eqStatuses(t, e.statuses(), map[string]string{"ok.example.com": "published", "taken.example.com": "conflict:foreign_address", "ctl.example.com": "not_managed:reserved"})
	if want := []string{"ok.example.com", "taken.example.com"}; !slices.Equal(e.names(), want) {
		t.Fatalf("records %v, want %v", e.names(), want)
	}
	for _, state := range []dnszone.SyncState{dnszone.SyncStateHeld, dnszone.SyncStateDisabled} {
		e.db.Client().DNSZone.UpdateOneID(e.zone.ID).SetSyncState(state).ExecX(e.sys)
		e.db.Client().DNSNameStatus.Delete().ExecX(e.sys)
		j.Sync(e.zone.ID)
		n, writes := e.requests(), e.fake.Count("POST")
		if err := j.Run(e.sys, ls); err != nil {
			t.Fatal(err)
		}
		// A held zone reads the provider to compute its plan, and writes nothing; a disabled one
		// does not read either.
		if e.fake.Count("POST") != writes || (state == dnszone.SyncStateDisabled && e.requests() != n) {
			t.Fatalf("%s zone: a request was made", state)
		}
		want := "held"
		if state == dnszone.SyncStateDisabled {
			want = "not_managed"
		}
		if got := e.statuses()["ok.example.com"]; !strings.HasPrefix(got, want) {
			t.Fatalf("%s zone: ok.example.com is %q", state, got)
		}
	}
}

// TestDNS_BatchFallbackPerRecord_NameStatus is the name-status clause of TestDNS_BatchFallbackPerRecord:
// when the provider refuses one record of a batch, the retry publishes the others and only the
// failing name is error, with the provider's reason; the next pass publishes it once it is valid.
func TestDNS_BatchFallbackPerRecord_NameStatus(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.addName("a.example.com")
	e.addName("b.example.com")
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	// The batch is refused, then the first record alone; the second goes through.
	refused := &dns.ProviderError{Status: 400, Messages: []string{"9005 Content for A record is invalid."}}
	e.failApply(refused, refused)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if got := e.statuses(); !strings.HasPrefix(got["a.example.com"], "error:9005") || got["b.example.com"] != "published" {
		t.Fatalf("statuses %v", got)
	}
	if !slices.Equal(e.names(), []string{"b.example.com"}) {
		t.Fatalf("records %v", e.names())
	}
	j.Sync(e.zone.ID)
	e.clk.add(time.Second)
	_ = l.Renew(e.sys, ls)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published", "b.example.com": "published"})
}

// TestRun_FailStatic: a provider that is unreachable, rate-limits or refuses the token leaves the
// published records and names as they are, sets the zone's provider status, and the next pass that
// succeeds clears it and converges.
func TestRun_FailStatic(t *testing.T) {
	for _, c := range []struct {
		name   string
		fault  cftest.Fault
		status dnszone.ProviderStatus
	}{
		{"unreachable", cftest.Fault{Status: 502}, dnszone.ProviderStatusUnreachable},
		{"rate limited", cftest.Fault{Status: 429, RetryAfter: "60"}, dnszone.ProviderStatusRateLimited},
		{"token refused", cftest.Fault{Status: 401}, dnszone.ProviderStatusPermissionDenied},
		{"no permission", cftest.Fault{Status: 403}, dnszone.ProviderStatusPermissionDenied},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, storetest.Migrated(t, store.SQLite))
			e.addName("a.example.com")
			j, l := e.replica("ctn_a")
			ls := e.take(l)
			if err := j.Run(e.sys, ls); err != nil {
				t.Fatal(err)
			}
			before := e.fake.Records(e.zone.ProviderZoneID)
			e.addName("b.example.com")
			e.fake.Fail(c.fault) // the listing
			j.Sync(e.zone.ID)
			e.clk.add(job.Debounce)
			_ = l.Renew(e.sys, ls)
			if err := j.Run(e.sys, ls); err != nil {
				t.Fatalf("a failing provider is no error of the job: %v", err)
			}
			if !slices.Equal(e.fake.Records(e.zone.ProviderZoneID), before) {
				t.Fatal("the provider changed")
			}
			if z := e.zoneRow(); z.ProviderStatus != c.status {
				t.Fatalf("provider status %s, want %s", z.ProviderStatus, c.status)
			}
			eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published", "b.example.com": "pending"})
			// The next pass converges, once a retry-after of the provider is over: until then the
			// shared budget lends nothing.
			j.Sync(e.zone.ID)
			e.advance(l, ls, time.Minute+time.Second)
			if err := j.Run(e.sys, ls); err != nil {
				t.Fatal(err)
			}
			if z := e.zoneRow(); z.ProviderStatus != dnszone.ProviderStatusOk || z.LastSyncedAt == nil {
				t.Fatalf("zone %+v", z)
			}
			eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published", "b.example.com": "published"})
		})
	}
}

// TestRun_ProviderProblems: a provider whose token cannot be opened leaves the zone as it is; so
// does a failure in the middle of the writes, and the names the writes did not reach are pending.
func TestRun_ProviderProblems(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.addName("a.example.com")
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	sealed := e.db.Client().DNSProvider.Query().OnlyX(e.sys).CredentialEnc
	e.db.Client().DNSProvider.Update().SetCredentialEnc([]byte("not sealed")).ExecX(e.sys)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if e.requests() != 0 || e.zoneRow().ProviderStatus != dnszone.ProviderStatusUnreachable {
		t.Fatalf("%d requests, status %s", e.requests(), e.zoneRow().ProviderStatus)
	}
	eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "pending"})
	// The token is refused in the middle of the pass: nothing is written, and the zone says why.
	e.db.Client().DNSProvider.Update().SetCredentialEnc(sealed).ExecX(e.sys)
	e.failApply(&dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized})
	j.Sync(e.zone.ID)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if len(e.names()) != 0 || e.zoneRow().ProviderStatus != dnszone.ProviderStatusPermissionDenied {
		t.Fatalf("records %v, status %s", e.names(), e.zoneRow().ProviderStatus)
	}
	eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "pending"})
	if rows := e.db.Client().DNSRecord.Query().AllX(e.sys); len(rows) != 1 || rows[0].State != dnsrecord.StateCreating {
		t.Fatalf("rows %+v", rows)
	}
	j.Sync(e.zone.ID)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published"})
	if n := e.db.Client().DNSRecord.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d rows: the creating row was not reused", n)
	}
}

// TestRun_RelinksReportsOrphansAndDrift: the job relinks a creating row whose record carries its
// marker (a crash after the provider call), reports an orphan and never deletes it, puts back a
// change someone else made, and stops correcting a record that changes again within the stop window.
func TestRun_RelinksReportsOrphansAndDrift(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.addName("a.example.com")
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	// The state a crash leaves: the row is creating, the record is at the provider with its marker.
	row := e.db.Client().DNSRecord.Create().SetOrgID(e.org).SetDNSZoneID(e.zone.ID).SetName("a.example.com").SetType("CNAME").
		SetContent("gw.example.net").SetTTL(300).SaveX(e.sys)
	e.fake.AddRecord(e.zone.ProviderZoneID, cftest.Record{Type: "CNAME", Name: "a.example.com", Content: "gw.example.net", TTL: 300, Comment: apply.Marker(td, row.ID)})
	orphan := e.fake.AddRecord(e.zone.ProviderZoneID, cftest.Record{Type: "A", Name: "ghost.example.com", Content: "192.0.2.99", TTL: 300, Comment: apply.Marker(td, "dnr_01ARZ3NDEKTSV4RRFFQ69G5FAV")})
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published"})
	if r := e.db.Client().DNSRecord.GetX(e.sys, row.ID); r.State != dnsrecord.StateSynced || r.ProviderRecordID == nil {
		t.Fatalf("row %+v", r)
	}
	if len(e.reports) != 1 || e.reports[0].Relinked != 1 || len(e.reports[0].Orphans) != 1 || e.reports[0].Orphans[0].ID != orphan.ID {
		t.Fatalf("reports %+v", e.reports)
	}
	if len(e.fake.Records(e.zone.ProviderZoneID)) != 2 || e.fake.Count("POST") != 0 {
		t.Fatal("the relink wrote to the provider")
	}
	// Drift: someone changes the CNAME; the pass puts it back and reports it.
	p, _ := e.dial("", "", secret.New(token))
	edit := func(content string) {
		t.Helper()
		var rec cftest.Record
		for _, r := range e.fake.Records(e.zone.ProviderZoneID) {
			if r.Name == "a.example.com" {
				rec = r
			}
		}
		err := p.Apply(e.sys, e.zone.ProviderZoneID, dns.Batch{Patches: []dns.Record{{ID: rec.ID, Type: rec.Type, Name: rec.Name, Content: content, TTL: rec.TTL, Comment: rec.Comment}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	content := func() string {
		for _, r := range e.fake.Records(e.zone.ProviderZoneID) {
			if r.Name == "a.example.com" {
				return r.Content
			}
		}
		return ""
	}
	e.reports = nil
	edit("other.example.net")
	j.Sync(e.zone.ID)
	e.advance(l, ls, time.Second)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if content() != "gw.example.net" || len(e.reports) != 1 || len(e.reports[0].Corrected) != 1 {
		t.Fatalf("content %q, reports %+v", content(), e.reports)
	}
	e.reports = nil
	edit("another.example.net")
	j.Sync(e.zone.ID)
	e.advance(l, ls, time.Second)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if content() != "another.example.net" || len(e.reports) != 1 || len(e.reports[0].Drifted) != 1 {
		t.Fatalf("content %q, reports %+v", content(), e.reports)
	}
	if r := e.db.Client().DNSRecord.GetX(e.sys, row.ID); r.State != dnsrecord.StateDrifted {
		t.Fatalf("row %+v", r)
	}
	eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published"})
	// The orphan is still there after all of it.
	var found bool
	for _, r := range e.fake.Records(e.zone.ProviderZoneID) {
		found = found || r.ID == orphan.ID
	}
	if !found {
		t.Fatal("the orphan was deleted")
	}
}

// TestDNS_RateBudgetAndRetryAfter_Job is the job clause of TestDNS_RateBudgetAndRetryAfter
// (docs/12-testing-and-quality.md): after a 429 no replica's pass sends a request before the
// retry-after is over, the zone shows rate_limited and its names stay pending, and the pass that
// follows publishes. A pass whose requests the shared window does not lend stops the same way.
func TestDNS_RateBudgetAndRetryAfter_Job(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		e.addName("a.example.com")
		ja, la := e.replica("ctn_a")
		lease1 := e.take(la)
		e.fake.Fail(cftest.Fault{Status: 429, RetryAfter: "120"})
		if err := ja.Run(e.sys, lease1); err != nil {
			t.Fatal(err)
		}
		if n := e.requests(); n != 1 {
			t.Fatalf("%d requests, want the one that was refused", n)
		}
		if z := e.zoneRow(); z.ProviderStatus != dnszone.ProviderStatusRateLimited || z.LastSyncedAt != nil {
			t.Fatalf("zone %+v", z)
		}
		eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "pending"})

		// The lease moves to the other replica after 90 s, thirty before the block ends: its
		// full pass asks the shared budget and sends nothing.
		e.clk.add(job.LeaseTTL)
		jb, lb := e.replica("ctn_b")
		lease2 := e.take(lb)
		if err := jb.Run(e.sys, lease2); err != nil {
			t.Fatal(err)
		}
		if n := e.requests(); n != 1 {
			t.Fatalf("the other replica sent %d requests during the block", n-1)
		}
		if z := e.zoneRow(); z.ProviderStatus != dnszone.ProviderStatusRateLimited {
			t.Fatalf("zone %+v", z)
		}
		if len(e.names()) != 0 {
			t.Fatalf("records %v", e.names())
		}

		// Past the retry-after the pass goes through, and the zone is ok again.
		e.advance(lb, lease2, 31*time.Second)
		jb.Sync(e.zone.ID)
		if err := jb.Run(e.sys, lease2); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(e.names(), []string{"a.example.com"}) {
			t.Fatalf("records %v", e.names())
		}
		if z := e.zoneRow(); z.ProviderStatus != dnszone.ProviderStatusOk || z.LastSyncedAt == nil {
			t.Fatalf("zone %+v", z)
		}
		eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "published"})
	})
}

// A 429 without a Retry-After blocks both replicas for the default of docs/15-dns.md, and a window
// that is spent stops a pass with rate_limited as well, leaving what it has as it is.
func TestDNS_RateBudget_Job429WithoutHeaderAndSpentWindow(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.addName("a.example.com")
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	e.fake.Fail(cftest.Fault{Status: 429})
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	e.advance(l, ls, budget.DefaultBlock-time.Second)
	j.Sync(e.zone.ID)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if n := e.requests(); n != 1 {
		t.Fatalf("%d requests before the default block ended", n)
	}
	e.advance(l, ls, time.Second)
	j.Sync(e.zone.ID)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.names(), []string{"a.example.com"}) {
		t.Fatalf("records %v", e.names())
	}

	// The window is spent, by anyone: the pass is stopped before its first request.
	b := &budget.Budget{DB: e.db, Now: e.clk.now}
	for b.Take(e.sys, e.zone.DNSProviderID, budget.DNS01) == nil {
	}
	for b.Take(e.sys, e.zone.DNSProviderID, budget.Job) == nil {
	}
	e.addName("b.example.com")
	before := e.requests()
	j.Sync(e.zone.ID)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	if e.requests() != before {
		t.Fatal("a request was sent with the window spent")
	}
	if z := e.zoneRow(); z.ProviderStatus != dnszone.ProviderStatusRateLimited {
		t.Fatalf("zone %+v", z)
	}
	if !slices.Equal(e.names(), []string{"a.example.com"}) {
		t.Fatalf("records %v", e.names())
	}
}

// removeName deletes a DNS name in a configuration transaction.
func (e *env) removeName(fqdn string) {
	e.t.Helper()
	_, err := store.ConfigTx(e.sys, e.db, func(tx *ent.Tx) ([]string, error) {
		n, err := tx.DNSName.Query().Where(dnsname.Fqdn(fqdn)).Only(e.sys)
		if err != nil {
			return nil, err
		}
		return []string{n.ID}, tx.DNSName.DeleteOneID(n.ID).Exec(e.sys)
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) setThreshold(n int) {
	e.t.Helper()
	e.db.Client().DNSZone.UpdateOneID(e.zone.ID).SetDeleteThreshold(n).ExecX(e.sys)
}

// approve is what ApproveZonePlan does to the row, after it has compared the hash.
func (e *env) approve(j *job.Job, hash string) {
	e.t.Helper()
	e.db.Client().DNSZone.UpdateOneID(e.zone.ID).SetSyncState(dnszone.SyncStateActive).SetHeldReason("").SetPendingPlanHash(hash).ExecX(e.sys)
}

// preview is the plan an approval would be bound to.
func (e *env) preview(j *job.Job) plan.Plan {
	e.t.Helper()
	p, err := e.dial("cloudflare", "", secret.New(token))
	if err != nil {
		e.t.Fatal(err)
	}
	pl, err := j.Preview(e.sys, e.zone.ID, p)
	if err != nil {
		e.t.Fatal(err)
	}
	return pl
}

// pass runs one forced pass of the zone, renewing the lease.
func (e *env) pass(j *job.Job, l *lease.Leases, ls lease.Lease) {
	e.t.Helper()
	j.Sync(e.zone.ID)
	e.advance(l, ls, time.Second)
	if err := j.Run(e.sys, ls); err != nil {
		e.t.Fatal(err)
	}
}

// TestDNS_DeletionGuard (docs/12-testing-and-quality.md): a pass that removes the address records
// of more names than delete_threshold holds the zone and writes nothing; replacements do not count;
// threshold 0 holds on every removal; the plan is stored with its hash; an approved plan is applied
// once and the approval is used up; a plan that is not the approved one holds the zone again.
func TestDNS_DeletionGuard(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		for _, n := range []string{"a", "b", "c", "d"} {
			e.addName(n + ".example.com")
		}
		j, l := e.replica("ctn_a")
		ls := e.take(l)
		e.setThreshold(2)
		if err := j.Run(e.sys, ls); err != nil {
			t.Fatal(err)
		}
		if len(e.names()) != 4 {
			t.Fatalf("records %v", e.names())
		}
		// Two removals are the threshold: they go through.
		e.removeName("a.example.com")
		e.removeName("b.example.com")
		e.pass(j, l, ls)
		if !slices.Equal(e.names(), []string{"c.example.com", "d.example.com"}) {
			t.Fatalf("two removals at threshold 2: %v", e.names())
		}
		if z := e.zoneRow(); z.SyncState != dnszone.SyncStateActive {
			t.Fatalf("zone %+v", z)
		}

		// A third name makes two removals again, and one more is above the threshold.
		e.setThreshold(1)
		e.removeName("c.example.com")
		e.removeName("d.example.com")
		writes := e.fake.Count("POST")
		e.pass(j, l, ls)
		z := e.zoneRow()
		if z.SyncState != dnszone.SyncStateHeld || z.HeldReason != apply.HeldDeletionGuard || z.PendingPlanHash == "" || len(z.PendingPlan) == 0 {
			t.Fatalf("zone %+v", z)
		}
		if e.fake.Count("POST") != writes || len(e.names()) != 2 {
			t.Fatalf("a held zone was written to: %v", e.names())
		}
		var stored plan.Plan
		if err := json.Unmarshal(z.PendingPlan, &stored); err != nil || stored.Hash != z.PendingPlanHash || len(stored.Deletes) != 2 {
			t.Fatalf("stored plan %+v, %v", stored, err)
		}
		eqStatuses(t, e.statuses(), map[string]string{})
		// The held zone keeps planning, and writes nothing, however often the job looks.
		e.pass(j, l, ls)
		if e.fake.Count("POST") != writes || len(e.names()) != 2 {
			t.Fatal("a held zone was written to")
		}

		// The approval of a plan whose hash is not the current one is the API's to refuse
		// (PLAN_CHANGED); here the row is approved with the current one.
		pl := e.preview(j)
		if pl.Hash != z.PendingPlanHash || len(pl.Deletes) != 2 {
			t.Fatalf("preview %+v is not the stored plan %s", pl, z.PendingPlanHash)
		}
		e.approve(j, pl.Hash)
		e.pass(j, l, ls)
		if len(e.names()) != 0 {
			t.Fatalf("the approved plan was not applied: %v", e.names())
		}
		if z := e.zoneRow(); z.SyncState != dnszone.SyncStateActive || z.PendingPlanHash != "" || len(z.PendingPlan) != 0 {
			t.Fatalf("the approval is not used up: %+v", z)
		}

		// Threshold 0: every removal needs approval; a replacement does not.
		e.setThreshold(0)
		e.addName("e.example.com")
		e.addName("f.example.com")
		e.pass(j, l, ls)
		if len(e.names()) != 2 {
			t.Fatalf("creates need no approval: %v", e.names())
		}
		e.db.Client().GatewayGroup.UpdateOneID(e.group).ClearDNSCname().SetDNSAddresses([]string{"192.0.2.7"}).ExecX(e.sys)
		e.revision("gwg_x")
		e.pass(j, l, ls)
		if z := e.zoneRow(); z.SyncState != dnszone.SyncStateActive {
			t.Fatalf("a replacement (CNAME to address) held the zone at threshold 0: %+v", z)
		}
		var types []string
		for _, r := range e.fake.Records(e.zone.ProviderZoneID) {
			types = append(types, r.Type)
		}
		if !slices.Equal(types, []string{"A", "A"}) {
			t.Fatalf("records %v", e.fake.Records(e.zone.ProviderZoneID))
		}
		e.removeName("e.example.com")
		e.pass(j, l, ls)
		if z := e.zoneRow(); z.SyncState != dnszone.SyncStateHeld || z.HeldReason != apply.HeldDeletionGuard || len(e.names()) != 2 {
			t.Fatalf("threshold 0 and one removal: %+v, %v", z, e.names())
		}
		hash := e.zoneRow().PendingPlanHash

		// What changed after the approval is not approved: the zone is held again, with the new plan.
		e.approve(j, hash)
		e.removeName("f.example.com")
		e.pass(j, l, ls)
		z = e.zoneRow()
		if z.SyncState != dnszone.SyncStateHeld || z.HeldReason != apply.HeldPlanChanged || z.PendingPlanHash == hash || len(e.names()) != 2 {
			t.Fatalf("a changed plan was applied or not held: %+v %v", z, e.names())
		}
	})
}

// TestDNS_RestoreStartsHeld, the job's clauses (docs/12-testing-and-quality.md): after a restore
// every zone is held; the plan lists the records created after the backup as orphaned and the ones
// deleted after it as creates; nothing is written before approval; with --dns-disabled the job does
// not even read the provider.
func TestDNS_RestoreStartsHeld(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		e.addName("a.example.com")
		e.addName("b.example.com")
		j, l := e.replica("ctn_a")
		ls := e.take(l)
		if err := j.Run(e.sys, ls); err != nil {
			t.Fatal(err)
		}
		// The backup had the ledger row of a and of c, and not of b: b was created after it. The
		// record of c was deleted at the provider after the backup.
		recs := e.db.Client().DNSRecord.Query().AllX(e.sys)
		for _, r := range recs {
			if r.Name == "b.example.com" {
				e.db.Client().DNSRecord.DeleteOneID(r.ID).ExecX(e.sys)
			}
		}
		e.db.Client().DNSRecord.Create().SetOrgID(e.org).SetDNSZoneID(e.zone.ID).SetID(ids.New("dnr")).SetName("c.example.com").SetType("CNAME").
			SetContent("gw.example.net").SetTTL(300).SetProviderRecordID("0000000000000000000000000000dead").SetState(dnsrecord.StateSynced).ExecX(e.sys)
		e.addName("c.example.com")

		held, err := holdAll(e, false)
		if err != nil || held != 1 {
			t.Fatalf("held %d zones, %v", held, err)
		}
		z := e.zoneRow()
		if z.SyncState != dnszone.SyncStateHeld || z.HeldReason != apply.HeldRestored {
			t.Fatalf("zone %+v", z)
		}
		writes := e.fake.Count("POST") + e.fake.Count("DELETE") + e.fake.Count("PUT") + e.fake.Count("PATCH")
		e.pass(j, l, ls)
		if w := e.fake.Count("POST") + e.fake.Count("DELETE") + e.fake.Count("PUT") + e.fake.Count("PATCH"); w != writes {
			t.Fatalf("%d writes to a held zone", w-writes)
		}
		z = e.zoneRow()
		var pl plan.Plan
		if err := json.Unmarshal(z.PendingPlan, &pl); err != nil || pl.Hash == "" || pl.Hash != z.PendingPlanHash {
			t.Fatalf("stored plan %+v, %v", pl, err)
		}
		if len(pl.Orphans) != 1 || pl.Orphans[0].Name != "b.example.com" {
			t.Errorf("orphans %+v, want the record of b, created after the backup", pl.Orphans)
		}
		if len(pl.Creates) != 1 || pl.Creates[0].Name != "c.example.com" {
			t.Errorf("creates %+v, want c, deleted after the backup", pl.Creates)
		}
		if len(pl.Deletes) != 0 || len(pl.Updates) != 0 {
			t.Errorf("plan %+v", pl)
		}
		eqStatuses(t, e.statuses(), map[string]string{"a.example.com": "held", "b.example.com": "held", "c.example.com": "held"})

		// --dns-disabled: the job does nothing in the zone, not even a listing.
		if _, err := holdAll(e, true); err != nil {
			t.Fatal(err)
		}
		z = e.zoneRow()
		if z.SyncState != dnszone.SyncStateDisabled || z.HeldReason != "" || z.PendingPlanHash != "" || len(z.PendingPlan) != 0 {
			t.Fatalf("zone %+v", z)
		}
		seen := e.requests()
		e.pass(j, l, ls)
		if e.requests() != seen {
			t.Fatalf("%d requests to the provider of a disabled zone", e.requests()-seen)
		}
		// The approval of a held zone is the API's; a disabled zone cannot be approved there.
	})
}

func holdAll(e *env, disabled bool) (n int, err error) {
	err = store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		var err error
		n, err = apply.HoldAll(e.sys, tx, disabled)
		return err
	})
	return n, err
}

// An adopted record is rewritten by the next pass to what the sources want, and gets the marker; it
// is no drift: nothing is reported as corrected, and the name is published. A record that is adopted
// at a name whose source is gone is deleted like any owned record.
func TestRun_AdoptedRecordIsRewrittenWithItsMarker(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		e.addName("app.example.com")
		foreign := e.fake.AddRecord(e.zone.ProviderZoneID, cftest.Record{Type: "CNAME", Name: "app.example.com", Content: "old.example.net", TTL: 3600, Comment: "by hand"})
		j, l := e.replica("ctn_a")
		ls := e.take(l)
		if err := j.Run(e.sys, ls); err != nil {
			t.Fatal(err)
		}
		eqStatuses(t, e.statuses(), map[string]string{"app.example.com": "conflict:foreign_address"})
		if r := e.fake.Records(e.zone.ProviderZoneID); len(r) != 1 || r[0].Content != "old.example.net" {
			t.Fatalf("a foreign record was touched: %+v", r)
		}

		var row *ent.DNSRecord
		err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
			var err error
			row, err = apply.Adopt(e.sys, tx, apply.Zone{ID: e.zone.ID, OrgID: e.org, Name: apex, ProviderID: e.zone.ProviderZoneID},
				dns.Record{ID: foreign.ID, Type: "CNAME", Name: "app.example.com", Content: "old.example.net", TTL: 3600, Comment: "by hand"}, e.clk.now())
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		orig, ok := apply.OriginalOf(row)
		if !ok || orig.Content != "old.example.net" || orig.Comment != "by hand" || orig.TTL != 3600 || orig.Type != "CNAME" {
			t.Fatalf("original %+v %v", orig, ok)
		}
		if _, ok := apply.OriginalOf(&ent.DNSRecord{}); ok {
			t.Error("a row that was not adopted has an original")
		}
		e.pass(j, l, ls)
		recs := e.fake.Records(e.zone.ProviderZoneID)
		if len(recs) != 1 || recs[0].ID != foreign.ID || recs[0].Content != "gw.example.net" || recs[0].Comment != apply.Marker(td, row.ID) {
			t.Fatalf("records %+v", recs)
		}
		eqStatuses(t, e.statuses(), map[string]string{"app.example.com": "published"})
		got := e.db.Client().DNSRecord.GetX(e.sys, row.ID)
		if got.State != dnsrecord.StateSynced || got.LastSyncedAt == nil || got.CorrectedAt != nil || got.Content != "gw.example.net" || got.AdoptedFrom == "" {
			t.Fatalf("row %+v", got)
		}
		for _, r := range e.reports {
			if len(r.Corrected)+len(r.Drifted)+len(r.Orphans) > 0 {
				t.Errorf("an adoption was reported as drift: %+v", r)
			}
		}
		if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("dns_record.drift")).CountX(e.sys); n != 0 {
			t.Errorf("%d drift entries for an adoption", n)
		}

		// Adopted and already as wanted: the first pass still puts the marker on, and only that.
		e.addName("same.example.com")
		same := e.fake.AddRecord(e.zone.ProviderZoneID, cftest.Record{Type: "CNAME", Name: "same.example.com", Content: "gw.example.net", TTL: 300})
		var row2 *ent.DNSRecord
		_ = store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
			var err error
			row2, err = apply.Adopt(e.sys, tx, apply.Zone{ID: e.zone.ID, OrgID: e.org, Name: apex, ProviderID: e.zone.ProviderZoneID},
				dns.Record{ID: same.ID, Type: "CNAME", Name: "same.example.com", Content: "gw.example.net", TTL: 300}, e.clk.now())
			return err
		})
		e.pass(j, l, ls)
		for _, r := range e.fake.Records(e.zone.ProviderZoneID) {
			if r.ID == same.ID && (r.Comment != apply.Marker(td, row2.ID) || r.Content != "gw.example.net") {
				t.Errorf("the record adopted as wanted: %+v", r)
			}
		}
		if got := e.db.Client().DNSRecord.GetX(e.sys, row2.ID); got.LastSyncedAt == nil || got.CorrectedAt != nil {
			t.Errorf("row %+v", got)
		}
	})
}

// "Sync now": a request in the zone's row, which another replica wrote, makes the lease holder's
// next tick a full pass of that zone, once per request; without one a tick with nothing new reads
// nothing.
func TestRun_SyncRequestedInTheRow(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.addName("a.example.com")
	j, l := e.replica("ctn_a")
	ls := e.take(l)
	if err := j.Run(e.sys, ls); err != nil {
		t.Fatal(err)
	}
	tick := func() int {
		e.advance(l, ls, time.Second)
		n := e.requests()
		if err := j.Run(e.sys, ls); err != nil {
			t.Fatal(err)
		}
		return e.requests() - n
	}
	if n := tick(); n != 0 {
		t.Fatalf("an idle tick sent %d requests", n)
	}
	ask := func() {
		e.db.Client().DNSZone.UpdateOneID(e.zone.ID).SetSyncRequestedAt(e.clk.now()).ExecX(e.sys)
	}
	ask()
	if n := tick(); n == 0 {
		t.Fatal("a request for a pass was not honoured")
	}
	if n := tick(); n != 0 {
		t.Fatalf("the same request was honoured twice: %d requests", n)
	}
	e.clk.add(time.Second)
	ask()
	if n := tick(); n == 0 {
		t.Fatal("a second request was not honoured")
	}
}

// A release that ReleaseRecord asked for, on any replica, is carried out by the replica that holds
// the lease and by no one else: the marker comes off, or the adopted original goes back, and then
// the row goes. A lease that will not outlast the write stops it before the write, and the next
// holder does it. A restore that cannot be carried out is cleared with its reason.
func TestRun_ReleaseRequestedIsCarriedOutUnderTheLease(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		e.addName("app.example.com")
		e.addName("kept.example.com")
		foreign := e.fake.AddRecord(e.zone.ProviderZoneID, cftest.Record{Type: "CNAME", Name: "app.example.com", Content: "old.example.net", TTL: 3600, Comment: "by hand"})
		ja, la := e.replica("ctn_a")
		lease1 := e.take(la)
		var adopted *ent.DNSRecord
		if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
			var err error
			adopted, err = apply.Adopt(e.sys, tx, apply.Zone{ID: e.zone.ID, OrgID: e.org, Name: apex, ProviderID: e.zone.ProviderZoneID},
				dns.Record{ID: foreign.ID, Type: "CNAME", Name: "app.example.com", Content: "old.example.net", TTL: 3600, Comment: "by hand"}, e.clk.now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := ja.Run(e.sys, lease1); err != nil { // rewrites the adopted record, creates kept
			t.Fatal(err)
		}
		recOf := func(id string) cftest.Record {
			for _, r := range e.fake.Records(e.zone.ProviderZoneID) {
				if r.ID == id {
					return r
				}
			}
			return cftest.Record{}
		}
		if r := recOf(foreign.ID); r.Content != "gw.example.net" || r.Comment != apply.Marker(td, adopted.ID) {
			t.Fatalf("the adopted record: %+v", r)
		}
		var keptRow *ent.DNSRecord
		for _, r := range e.db.Client().DNSRecord.Query().AllX(e.sys) {
			if r.Name == "kept.example.com" {
				keptRow = r
			}
		}
		keptID := recOf(e.fake.Records(e.zone.ProviderZoneID)[1].ID).ID

		// The requests come in through the database, as from the API on another replica. The lease
		// of this replica is about to end: nothing is written, the rows stay.
		e.db.Client().DNSRecord.UpdateOneID(adopted.ID).SetReleaseRequested("restore").ExecX(e.sys)
		e.db.Client().DNSRecord.UpdateOneID(keptRow.ID).SetReleaseRequested("keep").ExecX(e.sys)
		writes := e.fake.Count("POST")
		e.clk.add(job.LeaseTTL - job.Margin + time.Second)
		ja.Sync(e.zone.ID)
		if err := ja.Run(e.sys, lease1); err != nil {
			t.Fatal(err)
		}
		if e.fake.Count("POST") != writes || e.db.Client().DNSRecord.Query().CountX(e.sys) != 2 {
			t.Fatalf("a lease that ends wrote: %d writes, %d rows", e.fake.Count("POST")-writes, e.db.Client().DNSRecord.Query().CountX(e.sys))
		}
		// Another replica takes the lease and carries both out; the old holder cannot.
		jb, lb := e.replica("ctn_b")
		e.clk.add(job.Margin)
		lease2 := e.take(lb)
		ja.Sync(e.zone.ID)
		if err := ja.Run(e.sys, lease1); !errors.Is(err, lease.ErrLost) {
			t.Fatalf("the old holder: %v", err)
		}
		if err := jb.Run(e.sys, lease2); err != nil {
			t.Fatal(err)
		}
		if r := recOf(foreign.ID); r.Content != "old.example.net" || r.Comment != "by hand" || r.TTL != 3600 {
			t.Fatalf("restored record %+v", r)
		}
		if r := recOf(keptID); r.Comment != "" || r.Content != "gw.example.net" {
			t.Fatalf("kept record %+v", r)
		}
		if n := e.db.Client().DNSRecord.Query().CountX(e.sys); n != 0 {
			t.Fatalf("%d rows after the releases", n)
		}
		if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("dns_record.release")).CountX(e.sys); n != 2 {
			t.Errorf("%d release entries", n)
		}
		// Released records are foreign now: the pass leaves them alone, and the name is a conflict.
		e.pass(jb, lb, lease2)
		if r := recOf(foreign.ID); r.Content != "old.example.net" {
			t.Fatalf("a released record was written again: %+v", r)
		}

		// A restore that cannot be carried out is cleared, with its reason, and writes nothing.
		row := e.db.Client().DNSRecord.Create().SetOrgID(e.org).SetDNSZoneID(e.zone.ID).SetName("x.example.com").SetType("A").SetContent("192.0.2.1").SetTTL(300).
			SetProviderRecordID(foreign.ID).SetState(dnsrecord.StateSynced).SetReleaseRequested("restore").SaveX(e.sys)
		e.pass(jb, lb, lease2)
		got := e.db.Client().DNSRecord.GetX(e.sys, row.ID) // the pass that follows may rewrite the row's reason
		if got.ReleaseRequested != "" || e.db.Client().AuditEntry.Query().Where(auditentry.Action("dns_record.release")).CountX(e.sys) != 2 {
			t.Fatalf("row %+v", got)
		}
	})
}
