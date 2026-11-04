// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package budget_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsratebudget"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const token = "a-token-of-the-test-0123456789"

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

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

type env struct {
	db       *store.DB
	sys      context.Context
	org      string
	provider string
}

func newEnv(t *testing.T, db *store.DB) *env {
	t.Helper()
	storetest.Init(t, db)
	e := &env{db: db, sys: storetest.SystemCtx(t), provider: ids.New("dnp")}
	e.org = storetest.Org(t, db, "org-a")
	db.Client().DNSProvider.Create().SetID(e.provider).SetOrgID(e.org).SetKind("cloudflare").SetName("cf").SetCredentialEnc([]byte("sealed")).ExecX(e.sys)
	return e
}

// replica is a Budget with a clock of its own, as a controller process has.
func (e *env) replica(c *clock) *budget.Budget { return &budget.Budget{DB: e.db, Now: c.now} }

func limited(err error) (dns.RateLimited, bool) {
	var rl dns.RateLimited
	return rl, errors.As(err, &rl)
}

// TestDNS_RateBudgetAndRetryAfter, the job clause (docs/12-testing-and-quality.md): two replicas,
// two Budgets on one database, taking at once never take more than the window lends; after a 429
// no request is taken by either until the retry-after is over. The clause of the job itself, that
// its pass sends nothing meanwhile, is TestDNS_RateBudgetAndRetryAfter_Job in internal/dns/job.
func TestDNS_RateBudgetAndRetryAfter(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		ca, cb := &clock{t: t0}, &clock{t: t0}
		a, b := e.replica(ca), e.replica(cb)
		var granted, refused atomic.Int64
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := a
				if i%2 == 1 {
					r = b
				}
				for range budget.Limit / 4 {
					err := r.Take(e.sys, e.provider, budget.Job)
					if err == nil {
						granted.Add(1)
						continue
					}
					if _, ok := limited(err); !ok {
						t.Errorf("take: %v", err)
						return
					}
					refused.Add(1)
				}
			}()
		}
		wg.Wait()
		if granted.Load() != budget.Limit || refused.Load() != 2*budget.Limit-budget.Limit {
			t.Fatalf("granted %d and refused %d of %d asked, want exactly %d granted", granted.Load(), refused.Load(), 2*budget.Limit, budget.Limit)
		}
		if st, err := b.Status(e.sys, e.provider); err != nil || st.Used != budget.Limit || st.Blocked != 0 {
			t.Fatalf("status %+v, %v", st, err)
		}
		err := b.Take(e.sys, e.provider, budget.Job)
		if rl, ok := limited(err); !ok || !rl.Until.Equal(t0.Add(budget.Window)) {
			t.Fatalf("a spent window answers with its end: %v", err)
		}
		// The window ends, on either replica's clock, and takes start again.
		ca.add(budget.Window)
		cb.add(budget.Window)
		if err := b.Take(e.sys, e.provider, budget.Job); err != nil {
			t.Fatalf("after the window: %v", err)
		}

		// A 429 of the provider blocks every replica until its retry-after, to the second.
		until := ca.now().Add(90 * time.Second)
		if err := a.Block(e.sys, e.provider, until); err != nil {
			t.Fatal(err)
		}
		cb.add(89 * time.Second)
		if rl, ok := limited(b.Take(e.sys, e.provider, budget.Job)); !ok || !rl.Until.Equal(until) {
			t.Fatalf("the other replica took during the block: %v", rl)
		}
		if st, _ := b.Status(e.sys, e.provider); st.Blocked != time.Second {
			t.Fatalf("blocked for %v", st.Blocked)
		}
		cb.add(time.Second)
		if err := b.Take(e.sys, e.provider, budget.Job); err != nil {
			t.Fatalf("after the block: %v", err)
		}
		// A shorter block never shortens one that holds.
		long := cb.now().Add(10 * time.Minute)
		_ = a.Block(e.sys, e.provider, long)
		_ = a.Block(e.sys, e.provider, cb.now().Add(time.Minute))
		if rl, ok := limited(b.Take(e.sys, e.provider, budget.Job)); !ok || !rl.Until.Equal(long) {
			t.Fatalf("a shorter block replaced the longer: %v", rl)
		}
	})
}

// TestRateBudget_DNS01HalfOfTheWindow: a DNS-01 taker gets at most half of the window, the job the
// rest, and neither takes the other's share by being first.
func TestRateBudget_DNS01HalfOfTheWindow(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		b := e.replica(&clock{t: t0})
		n := 0
		for b.Take(e.sys, e.provider, budget.DNS01) == nil {
			n++
		}
		if n != budget.Dns01Limit {
			t.Fatalf("DNS-01 took %d, want %d", n, budget.Dns01Limit)
		}
		if _, ok := limited(b.Take(e.sys, e.provider, budget.DNS01)); !ok {
			t.Fatal("DNS-01 went over its half")
		}
		m := 0
		for b.Take(e.sys, e.provider, budget.Job) == nil {
			m++
		}
		if m != budget.Limit-budget.Dns01Limit {
			t.Fatalf("the job took %d after DNS-01, want %d", m, budget.Limit-budget.Dns01Limit)
		}
		// The half is of the window: a spent half does not block the job that has requests left.
		e2 := newEnv2(t, db)
		b2 := e.replica(&clock{t: t0})
		for range budget.Dns01Limit {
			if err := b2.Take(e.sys, e2, budget.DNS01); err != nil {
				t.Fatal(err)
			}
		}
		if err := b2.Take(e.sys, e2, budget.Job); err != nil {
			t.Fatalf("the job after DNS-01 spent its half: %v", err)
		}
		// A provider's budget is its own.
		if err := b2.Take(e.sys, e.provider, budget.Job); err == nil {
			t.Fatal("another provider's spent budget lent a request")
		}
	})
}

func newEnv2(t *testing.T, db *store.DB) string {
	t.Helper()
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-b")
	id := ids.New("dnp")
	db.Client().DNSProvider.Create().SetID(id).SetOrgID(org).SetKind("cloudflare").SetName("cf2").SetCredentialEnc([]byte("sealed")).ExecX(sys)
	return id
}

// TestRateBudget_ClockSkew: replicas whose clocks differ by seconds, or by more than a window,
// stay within the budget and are never locked out for good.
func TestRateBudget_ClockSkew(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		ahead, behind := &clock{t: t0.Add(2 * time.Minute)}, &clock{t: t0}
		fast, slow := e.replica(ahead), e.replica(behind)
		// The fast replica opens the window and spends it.
		for range budget.Limit {
			if err := fast.Take(e.sys, e.provider, budget.Job); err != nil {
				t.Fatal(err)
			}
		}
		// The slow replica sees a window that starts in its future, and stays inside it.
		rl, ok := limited(slow.Take(e.sys, e.provider, budget.Job))
		if !ok || !rl.Until.Equal(t0.Add(2*time.Minute+budget.Window)) {
			t.Fatalf("the slow replica: %v", rl)
		}
		// Five minutes later by the slow clock the window is not over for it: it started two
		// minutes ahead. The budget is never wider than it says.
		behind.add(budget.Window)
		if _, ok := limited(slow.Take(e.sys, e.provider, budget.Job)); !ok {
			t.Fatal("the slow replica opened a window the fast one still holds")
		}
		behind.add(2 * time.Minute)
		if err := slow.Take(e.sys, e.provider, budget.Job); err != nil {
			t.Fatalf("after the window by the slow clock: %v", err)
		}
		// A fast replica far ahead of a window never locks the others out.
		far := &clock{t: behind.now().Add(budget.Window + time.Hour)}
		if err := e.replica(far).Take(e.sys, e.provider, budget.Job); err != nil {
			t.Fatal(err)
		}
		if err := slow.Take(e.sys, e.provider, budget.Job); err != nil {
			t.Fatalf("a window from the far future locked the budget: %v", err)
		}
		// A block is cut to MaxBlock, from the clock of whoever wrote it.
		if err := fast.Block(e.sys, e.provider, ahead.now().Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		row := db.Client().DNSRateBudget.Query().Where(dnsratebudget.DNSProviderID(e.provider)).OnlyX(e.sys)
		if !row.BlockedUntil.Equal(ahead.now().Add(budget.MaxBlock)) {
			t.Fatalf("blocked until %v, want %v", row.BlockedUntil, ahead.now().Add(budget.MaxBlock))
		}
	})
}

// A 429 without a Retry-After blocks for the default of docs/15-dns.md, and a Retry-After for the
// time it names, for every replica; the budget's own refusal blocks nothing.
func TestRateBudget_429WithAndWithoutRetryAfter(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		clk := &clock{t: t0}
		fake := cftest.New(t, token)
		dial := func(b *budget.Budget) dns.Provider {
			c, err := cloudflare.NewForTest(cloudflare.Config{Token: secret.New(token), Now: clk.now}, fake.URL(), fake.RootCAs())
			if err != nil {
				t.Fatal(err)
			}
			return b.Wrap(c, e.provider, budget.Job)
		}
		a, b := e.replica(clk), e.replica(clk)
		pa, pb := dial(a), dial(b)

		fake.Fail(cftest.Fault{Status: 429})
		_, err := pa.ListZones(e.sys)
		if rl, ok := limited(err); !ok || !rl.Until.Equal(t0.Add(budget.DefaultBlock)) {
			t.Fatalf("a 429 without Retry-After: %v", err)
		}
		before := fake.Count("")
		clk.add(budget.DefaultBlock - time.Second)
		for _, p := range []dns.Provider{pa, pb} {
			if _, err := p.ListZones(e.sys); err == nil {
				t.Fatal("a request went out during the block")
			}
		}
		if fake.Count("") != before {
			t.Fatalf("%d requests reached the provider during the block", fake.Count("")-before)
		}
		var own budget.Refused
		if _, err := pb.ListZones(e.sys); !errors.As(err, &own) {
			t.Fatalf("the other replica: %v", err)
		}
		clk.add(time.Second)
		if _, err := pb.ListZones(e.sys); err != nil {
			t.Fatalf("after the block: %v", err)
		}

		// With a Retry-After the block ends where the provider said.
		fake.Fail(cftest.Fault{Status: 429, RetryAfter: "42"})
		if _, err := pb.ListZones(e.sys); err == nil {
			t.Fatal("no error for a 429")
		}
		clk.add(41 * time.Second)
		if _, err := pa.ListZones(e.sys); err == nil {
			t.Fatal("a request went out before the retry-after")
		}
		clk.add(time.Second)
		if _, err := pa.ListZones(e.sys); err != nil {
			t.Fatalf("after the retry-after: %v", err)
		}

		// A provider that names no time at all gets the default from the wrapper.
		fp := &fixed{err: dns.RateLimited{}}
		w := a.Wrap(fp, e.provider, budget.Job)
		if _, err := w.ListZones(e.sys); err == nil {
			t.Fatal("no error")
		}
		if st, _ := a.Status(e.sys, e.provider); st.Blocked != budget.DefaultBlock {
			t.Fatalf("blocked for %v, want the default %v", st.Blocked, budget.DefaultBlock)
		}
	})
}

// fixed is a provider that fails every call.
type fixed struct{ err error }

func (f *fixed) Verify(context.Context) (dns.TokenInfo, error)             { return dns.TokenInfo{}, f.err }
func (f *fixed) ListZones(context.Context) ([]dns.Zone, error)             { return nil, f.err }
func (f *fixed) ListRecords(context.Context, string) ([]dns.Record, error) { return nil, f.err }
func (f *fixed) Apply(context.Context, string, dns.Batch) error            { return f.err }
func (f *fixed) Caps() dns.Capabilities                                    { return dns.Capabilities{} }

func TestRateBudget_UnknownProviderAndCancelledContext(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		b := e.replica(&clock{t: t0})
		if err := b.Take(e.sys, ids.New("dnp"), budget.Job); err == nil {
			t.Fatal("a request was lent to a provider that does not exist")
		} else if _, ok := limited(err); ok {
			t.Fatalf("a missing provider is no rate limit: %v", err)
		}
		if err := b.Block(e.sys, ids.New("dnp"), t0.Add(time.Minute)); err == nil {
			t.Fatal("a block of a provider that does not exist")
		}
		ctx, cancel := context.WithCancel(e.sys)
		cancel()
		if err := b.Take(ctx, e.provider, budget.Job); err == nil {
			t.Fatal("a request was lent to a cancelled context")
		}
		if st, err := b.Status(e.sys, ids.New("dnp")); err != nil || st.Used != 0 {
			t.Fatalf("status of a provider without a budget: %+v, %v", st, err)
		}
	})
}
