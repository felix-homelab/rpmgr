// SPDX-License-Identifier: Apache-2.0

package lease_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// clock is a settable clock shared by the replicas of a test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newClock() *clock { return &clock{t: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)} }

func acquire(t *testing.T, l *lease.Leases, name string) lease.Lease {
	t.Helper()
	ls, ok, err := l.TryAcquire(context.Background(), name)
	if err != nil || !ok {
		t.Fatalf("TryAcquire(%s): %v, %v", name, ok, err)
	}
	return ls
}

// TestMutualExclusion: of many concurrent attempts by two replicas, exactly one takes the lease.
func TestMutualExclusion(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		clk := newClock()
		replicas := []*lease.Leases{lease.New(db, "ctn_a", clk.now), lease.New(db, "ctn_b", clk.now)}
		var won atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, ok, err := replicas[i%2].TryAcquire(context.Background(), "acme")
				if err != nil {
					t.Errorf("TryAcquire: %v", err)
				}
				if ok {
					won.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("%d attempts took the lease, want 1", won.Load())
		}
	})
}

// TestTakeoverAfterExpiry: once a lease expired, another replica takes it with a higher fencing
// token, and the former holder can neither renew, release nor fence with it.
func TestTakeoverAfterExpiry(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		clk := newClock()
		a, b := lease.New(db, "ctn_a", clk.now), lease.New(db, "ctn_b", clk.now)
		la := acquire(t, a, "rollups")
		if la.Token != 1 {
			t.Fatalf("first token %d", la.Token)
		}
		clk.add(lease.TTL - time.Millisecond)
		if _, ok, _ := b.TryAcquire(ctx, "rollups"); ok {
			t.Fatal("taken 1 ms before expiry")
		}
		clk.add(time.Millisecond)
		lb := acquire(t, b, "rollups")
		if lb.Token != 2 {
			t.Fatalf("takeover token %d, want 2", lb.Token)
		}
		if err := a.Renew(ctx, la); !errors.Is(err, lease.ErrLost) {
			t.Errorf("former holder renewed: %v", err)
		}
		if err := a.Release(ctx, la); !errors.Is(err, lease.ErrLost) {
			t.Errorf("former holder released: %v", err)
		}
		if err := store.WriteTx(ctx, db, func(tx *ent.Tx) error { return a.Fence(ctx, tx, la) }); !errors.Is(err, lease.ErrLost) {
			t.Errorf("former holder fenced: %v", err)
		}
		if err := b.Renew(ctx, lb); err != nil {
			t.Errorf("new holder renews: %v", err)
		}
		if _, ok, _ := a.TryAcquire(ctx, "rollups"); ok {
			t.Error("the former holder took a renewed lease")
		}
	})
}

// TestReacquireGetsNewToken: a holder that lost a lease and took it again cannot use its old one.
func TestReacquireGetsNewToken(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		clk := newClock()
		a := lease.New(db, "ctn_a", clk.now)
		old := acquire(t, a, "purge")
		clk.add(lease.TTL)
		cur := acquire(t, a, "purge")
		if cur.Token != old.Token+1 {
			t.Fatalf("tokens %d then %d", old.Token, cur.Token)
		}
		if err := a.Renew(ctx, old); !errors.Is(err, lease.ErrLost) {
			t.Errorf("renewed with the old token: %v", err)
		}
		if err := a.Renew(ctx, cur); err != nil {
			t.Errorf("renew with the current token: %v", err)
		}
		clk.add(lease.TTL - time.Second)
		if err := a.Renew(ctx, cur); err != nil {
			t.Errorf("renew before expiry: %v", err)
		}
		clk.add(lease.TTL)
		if err := a.Renew(ctx, cur); !errors.Is(err, lease.ErrLost) {
			t.Errorf("renew after expiry: %v", err)
		}
	})
}

func TestReleaseLetsOthersIn(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		clk := newClock()
		a, b := lease.New(db, "ctn_a", clk.now), lease.New(db, "ctn_b", clk.now)
		la := acquire(t, a, "checkpoints")
		if err := a.Release(context.Background(), la); err != nil {
			t.Fatal(err)
		}
		if lb := acquire(t, b, "checkpoints"); lb.Token != 2 {
			t.Errorf("token after a release: %d", lb.Token)
		}
		if err := a.Release(context.Background(), la); !errors.Is(err, lease.ErrLost) {
			t.Errorf("second release: %v", err)
		}
	})
}

// TestFence_WorkOfALostLeaseIsNotCommitted: work committed with Fence lands while the lease is
// held and is rolled back once another replica has it.
func TestFence_WorkOfALostLeaseIsNotCommitted(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		clk := newClock()
		a, b := lease.New(db, "ctn_a", clk.now), lease.New(db, "ctn_b", clk.now)
		la := acquire(t, a, "rollups")
		org := storetest.Org(t, db, "org-a")
		sys := storetest.SystemCtx(t)
		work := func(name string) error {
			return store.WriteTx(sys, db, func(tx *ent.Tx) error {
				if err := tx.GatewayGroup.Create().SetOrgID(org).SetName(name).Exec(sys); err != nil {
					return err
				}
				return a.Fence(sys, tx, la)
			})
		}
		if err := work("held"); err != nil {
			t.Fatalf("work under a held lease: %v", err)
		}
		clk.add(lease.TTL)
		acquire(t, b, "rollups")
		if err := work("lost"); !errors.Is(err, lease.ErrLost) {
			t.Fatalf("work under a lost lease: %v", err)
		}
		if n := db.Client().GatewayGroup.Query().CountX(sys); n != 1 {
			t.Errorf("%d groups committed, want only the one from the held lease", n)
		}

		// Expired without a takeover, and an old token after the same holder took it again.
		c := lease.New(db, "ctn_c", clk.now)
		lc := acquire(t, c, "purge")
		clk.add(lease.TTL)
		fence := func(l lease.Lease) error {
			return store.WriteTx(sys, db, func(tx *ent.Tx) error { return c.Fence(sys, tx, l) })
		}
		if err := fence(lc); !errors.Is(err, lease.ErrLost) {
			t.Errorf("fence with an expired lease: %v", err)
		}
		again := acquire(t, c, "purge")
		if err := fence(lc); !errors.Is(err, lease.ErrLost) {
			t.Errorf("fence with the old token after a re-acquire: %v", err)
		}
		if err := fence(again); err != nil {
			t.Errorf("fence with the current token: %v", err)
		}
	})
}

// TestRun: the job runs on the replica that holds the lease, under an audited system scope, and
// the lease is released when the replica stops.
func TestRun(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		a, b := lease.New(db, "ctn_a", nil), lease.New(db, "ctn_b", nil)
		var runsA, runsB atomic.Int32
		job := func(n *atomic.Int32) lease.Job {
			return lease.Job{Name: "rollups", Reason: "roll up route traffic", Every: 10 * time.Millisecond,
				Run: func(ctx context.Context, _ lease.Lease) error {
					if _, err := db.Client().GatewayGroup.Query().Count(ctx); err != nil {
						return err // the system scope is in ctx
					}
					n.Add(1)
					return nil
				}}
		}
		ctxA, stopA := context.WithCancel(context.Background())
		doneA := make(chan struct{})
		go func() { defer close(doneA); a.Run(ctxA, job(&runsA), func(err error) { t.Errorf("A: %v", err) }) }()
		deadline := time.Now().Add(5 * time.Second)
		for runsA.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		ctxB, stopB := context.WithCancel(context.Background())
		doneB := make(chan struct{})
		go func() { defer close(doneB); b.Run(ctxB, job(&runsB), nil) }()
		time.Sleep(100 * time.Millisecond)
		stopA()
		<-doneA
		stopB()
		<-doneB
		if runsA.Load() < 3 || runsB.Load() != 0 {
			t.Fatalf("runs: A %d, B %d; want A ≥ 3 and B 0 while A holds the lease", runsA.Load(), runsB.Load())
		}
		if _, ok, err := b.TryAcquire(context.Background(), "rollups"); err != nil || !ok {
			t.Errorf("after A stopped, B takes the lease: %v, %v", ok, err)
		}
		grants := db.Client().AuditEntry.Query().Where(auditentry.Action("system_scope.grant"),
			auditentry.ActorID("rollups")).CountX(storetest.SystemCtx(t))
		if grants != 1 {
			t.Errorf("%d audited grants for the job, want 1", grants)
		}
		if _, err := audit.Verify(storetest.SystemCtx(t), db, ""); err != nil {
			t.Error(err)
		}
	})
}
