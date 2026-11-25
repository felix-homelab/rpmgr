// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestRetryWait: after one failure the wait is the first one, and each further failure doubles
// it, up to RetryMax and no further, however many failures follow; a shorter first wait doubles
// alike.
func TestRetryWait(t *testing.T) {
	for _, c := range []struct {
		failures    int
		first, want time.Duration
	}{
		{1, acme.RetryFirst, time.Minute},
		{2, acme.RetryFirst, 2 * time.Minute},
		{3, acme.RetryFirst, 4 * time.Minute},
		{9, acme.RetryFirst, 256 * time.Minute},
		{10, acme.RetryFirst, acme.RetryMax},
		{1000, acme.RetryFirst, acme.RetryMax},
		{1, time.Millisecond, time.Millisecond},
		{4, time.Millisecond, 8 * time.Millisecond},
	} {
		if got := acme.RetryWait(c.failures, c.first); got != c.want {
			t.Errorf("after %d failures from %s: %s, want %s", c.failures, c.first, got, c.want)
		}
	}
}

// scopedCtx returns a context with a system scope, which ends with cancel, as the controller's
// system context and a lease job's context do.
func scopedCtx(t *testing.T, parent context.Context) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, err := authz.System(parent, "acme-test", "test the acme job",
		func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return context.WithCancel(ctx)
}

// TestSync_ReadsUnderTheJobContext (issue 1206): on a stop the system context ends a moment before
// the job context, which is its child. Sync reads under the context it is given, so a stop of the
// job ends it with a context error that lease takes for a shutdown, and a system context that
// ended first does not fail a pass of a job that still runs.
func TestSync_ReadsUnderTheJobContext(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	newManager := func(sys context.Context) *acme.Manager {
		return acme.NewManager(acme.ManagerOptions{DB: db, Sys: sys, Sealer: sealer(t)})
	}

	t.Run("a live job context and a live system context", func(t *testing.T) {
		sys, cancelSys := scopedCtx(t, context.Background())
		defer cancelSys()
		job, cancelJob := scopedCtx(t, context.Background())
		defer cancelJob()
		if err := newManager(sys).Sync(job); err != nil {
			t.Fatalf("Sync: %v", err)
		}
	})

	t.Run("a cancelled job context fails the read as a context error", func(t *testing.T) {
		sys, cancelSys := scopedCtx(t, context.Background())
		defer cancelSys()
		job, cancelJob := scopedCtx(t, sys)
		cancelJob() // the job ends; the system context is still live
		err := newManager(sys).Sync(job)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Sync with a cancelled job context = %v; want context.Canceled", err)
		}
		// The job's Run returns it too, and lease takes it for a shutdown, as the job context ended.
		err = newManager(sys).Job(time.Hour).Run(job, lease.Lease{})
		if !errors.Is(err, context.Canceled) || errors.Is(err, lease.ErrLost) || job.Err() == nil {
			t.Fatalf("Job.Run with a cancelled job context = %v (ctx.Err %v); want context.Canceled", err, job.Err())
		}
	})

	t.Run("an expired job context fails the read as a deadline error", func(t *testing.T) {
		sys, cancelSys := scopedCtx(t, context.Background())
		defer cancelSys()
		job, cancelJob := context.WithDeadline(sys, time.Now().Add(-time.Second))
		defer cancelJob()
		if err := newManager(sys).Sync(job); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Sync with an expired job context = %v; want context.DeadlineExceeded", err)
		}
	})

	t.Run("a cancelled system context does not fail a live job", func(t *testing.T) {
		sys, cancelSys := scopedCtx(t, context.Background())
		cancelSys() // the system context ends first
		job, cancelJob := scopedCtx(t, context.Background())
		defer cancelJob()
		if err := newManager(sys).Sync(job); err != nil {
			t.Fatalf("Sync with a live job context and a cancelled system context: %v", err)
		}
	})

	t.Run("a context without a scope is refused, not read as the system", func(t *testing.T) {
		sys, cancelSys := scopedCtx(t, context.Background())
		defer cancelSys()
		if err := newManager(sys).Sync(context.Background()); err == nil {
			t.Fatal("Sync under a context without a scope succeeded")
		}
	})
}

// TestRenewAsync_ReadsUnderTheSystemContext: the context of RenewAsync is a request's, scoped to
// one org and ended with the request, and it only carries the renewal; the reads that check the
// hostname stay under the system context.
func TestRenewAsync_ReadsUnderTheSystemContext(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys, cancelSys := scopedCtx(t, context.Background())
	defer cancelSys()
	req, cancelReq := scopedCtx(t, context.Background())
	cancelReq()
	m := acme.NewManager(acme.ManagerOptions{DB: db, Sys: sys, Sealer: sealer(t)})
	if started, err := m.RenewAsync(req, "org_x", "a.example.com"); started || !errors.Is(err, acme.ErrNotWanted) {
		t.Fatalf("RenewAsync of an unwanted name = %v, %v; want false, ErrNotWanted", started, err)
	}
	cancelSys()
	if _, err := m.RenewAsync(context.Background(), "org_x", "a.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RenewAsync with a cancelled system context = %v; want context.Canceled", err)
	}
}
