// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// eventually waits for cond, which reads the checks' results.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// answersFast fails when Check takes longer than the target of docs/10 ("Health").
func answersFast(t *testing.T, r *ReadyChecks) error {
	t.Helper()
	start := time.Now()
	err := r.Check(context.Background())
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("Check took %v, want under 50 ms", d)
	}
	return err
}

// TestReadyChecks_slowCheckDoesNotDelay: a check that blocks (a database that does not answer)
// never holds up the answer, which comes from the last result.
func TestReadyChecks_slowCheckDoesNotDelay(t *testing.T) {
	r := NewReadyChecks()
	release := make(chan struct{})
	var mu sync.Mutex
	runs := 0
	r.Add("controller", func(context.Context) error {
		mu.Lock()
		runs++
		n := runs
		mu.Unlock()
		if n > 1 {
			<-release
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(release)
	if err := answersFast(t, r); err == nil || !strings.Contains(err.Error(), "not checked yet") {
		t.Errorf("before Run: %v, want not checked yet", err)
	}
	r.Run(ctx)
	eventually(t, "the first result", func() bool { return r.Check(ctx) == nil })
	r.Poke() // the second run blocks
	eventually(t, "the second run", func() bool { mu.Lock(); defer mu.Unlock(); return runs == 2 })
	for range 20 {
		if err := answersFast(t, r); err != nil {
			t.Fatalf("while a run is blocked: %v, want the last result (ready)", err)
		}
	}
}

// TestReadyChecks_timeout: a check that outlasts its timeout is reported as too slow, not waited for.
func TestReadyChecks_timeout(t *testing.T) {
	r := NewReadyChecks()
	r.timeout = 20 * time.Millisecond
	r.Add("gateway", func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Run(ctx)
	eventually(t, "the timeout reason", func() bool {
		err := r.Check(ctx)
		return err != nil && strings.Contains(err.Error(), "gateway: the check takes longer than")
	})
}

// TestReadyChecks_stale: a check that has not completed for longer than the limit is not ready,
// with that reason, whatever its last result was; a fresh result makes it ready again.
func TestReadyChecks_stale(t *testing.T) {
	r := NewReadyChecks()
	now := time.Now()
	r.now = func() time.Time { return now }
	r.Add("controller", func(context.Context) error { return nil })
	e := r.entries[0]
	e.done = now.Add(-readyStale + time.Second) // ready, and fresh
	if err := r.Check(context.Background()); err != nil {
		t.Fatalf("fresh result: %v", err)
	}
	e.done = now.Add(-readyStale - time.Second)
	err := r.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "controller: no result for") {
		t.Fatalf("stale result: %v, want the staleness reason", err)
	}
	e.err, e.done = errors.New("database: down"), now.Add(-readyStale-time.Second)
	if err := r.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "database: down") {
		t.Errorf("stale and failing: %v, want the last reason kept", err)
	}
	e.err, e.done = nil, now
	if err := r.Check(context.Background()); err != nil {
		t.Errorf("fresh again: %v", err)
	}
}

// TestReadyChecks_composition: an all-in-one's roles are checked apart; every role that is not
// ready is named, and a role that blocks does not hold up the others' results.
func TestReadyChecks_composition(t *testing.T) {
	r := NewReadyChecks()
	r.timeout = time.Hour
	block := make(chan struct{})
	defer close(block)
	r.Add("controller", func(context.Context) error { return nil })
	r.Add("gateway", func(context.Context) error { return errors.New("no control session") })
	r.Add("connector", func(context.Context) error { <-block; return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Run(ctx)
	// Each role runs in its own goroutine: wait for the controller's result too, not only the
	// gateway's. A ready role that is wrongly listed never satisfies this and fails the test.
	eventually(t, "the gateway's reason and the controller's result", func() bool {
		err := r.Check(ctx)
		return err != nil && strings.Contains(err.Error(), "gateway: no control session") &&
			!strings.Contains(err.Error(), "controller:")
	})
	err := answersFast(t, r)
	if err == nil || strings.Contains(err.Error(), "controller:") {
		t.Errorf("composition: %v, want the gateway and the connector listed, not the ready controller", err)
	}
	if !strings.Contains(err.Error(), "connector: not checked yet") {
		t.Errorf("composition: %v, want the connector's missing result named", err)
	}
	if NewReadyChecks().Check(ctx) != nil {
		t.Error("no checks must be ready")
	}
}

// TestReadyChecks_late: a check added after Run is run too.
func TestReadyChecks_late(t *testing.T) {
	r := NewReadyChecks()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Run(ctx)
	r.Add("connector", func(context.Context) error { return errors.New("no snapshot applied") })
	eventually(t, "the late check's reason", func() bool {
		err := r.Check(ctx)
		return err != nil && strings.Contains(err.Error(), "connector: no snapshot applied")
	})
}
