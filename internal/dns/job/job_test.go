// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package job_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/job"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
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
	p, err := cloudflare.NewForTest(cloudflare.Config{Token: tok}, e.fake.URL(), e.fake.RootCAs())
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
		Reserved: func(context.Context) []string { return e.reserved }})
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
		if e.requests() != n || e.fake.Count("POST") != writes {
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
			// The next pass converges.
			j.Sync(e.zone.ID)
			e.clk.add(time.Second)
			_ = l.Renew(e.sys, ls)
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

var _ = apply.Marker
