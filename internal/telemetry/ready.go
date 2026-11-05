// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// The readiness cache (docs/03-connections.md, "Timeouts, keepalive and backoff"; docs/10-operations.md,
// "Health"). The values live in 03.
const (
	readyEvery = time.Second // how often each check is run in the background
	readyStale = 10 * time.Second
)

// ReadyChecks runs readiness checks in the background, each in its own loop, and answers from the
// last result at once: /readyz never waits for a database, a lock or a slow check. A check that has
// not completed within the check timeout for longer than the staleness limit counts as not ready.
type ReadyChecks struct {
	now     func() time.Time
	timeout time.Duration // of one run of a check

	mu      sync.Mutex
	entries []*readyEntry
	started bool
	ctx     context.Context
}

type readyEntry struct {
	name  string
	check func(context.Context) error
	poke  chan struct{}

	mu   sync.Mutex
	err  error     // the last result
	done time.Time // when a run last completed in time; zero before the first
}

// NewReadyChecks returns an empty set; Run starts it.
func NewReadyChecks() *ReadyChecks { return &ReadyChecks{now: time.Now, timeout: readyTimeout} }

// Add registers a check under name (a role; may be empty). A check added after Run starts at once.
func (r *ReadyChecks) Add(name string, check func(context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := &readyEntry{name: name, check: check, poke: make(chan struct{}, 1)}
	r.entries = append(r.entries, e)
	if r.started {
		go e.loop(r.ctx, r)
	}
}

// Run starts the background loops and returns at once; they end with ctx.
func (r *ReadyChecks) Run(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.started, r.ctx = true, ctx
	for _, e := range r.entries {
		go e.loop(ctx, r)
	}
}

// Poke makes every check run again now, as after a change of state, instead of at the next tick.
func (r *ReadyChecks) Poke() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		select {
		case e.poke <- struct{}{}:
		default:
		}
	}
}

func (e *readyEntry) loop(ctx context.Context, r *ReadyChecks) {
	t := time.NewTicker(readyEvery)
	defer t.Stop()
	for {
		e.run(ctx, r)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.poke:
		}
	}
}

func (e *readyEntry) run(ctx context.Context, r *ReadyChecks) {
	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	err := e.check(cctx)
	e.mu.Lock()
	defer e.mu.Unlock()
	if cctx.Err() != nil && ctx.Err() == nil {
		// Too slow: the old result stands until it is stale, and the reason is that it is slow.
		e.err = fmt.Errorf("the check takes longer than %v", r.timeout)
		return
	}
	e.err, e.done = err, r.now()
}

// Check returns why the role is not ready, or nil, from the last results; it takes no check's lock
// for longer than reading a field, so it answers in microseconds whatever the checks do.
func (r *ReadyChecks) Check(context.Context) error {
	r.mu.Lock()
	entries := append([]*readyEntry(nil), r.entries...)
	r.mu.Unlock()
	var errs []error
	for _, e := range entries {
		e.mu.Lock()
		err, done := e.err, e.done
		e.mu.Unlock()
		switch {
		case done.IsZero() && err == nil:
			err = errors.New("not checked yet")
		case !done.IsZero() && r.now().Sub(done) > readyStale:
			stuck := fmt.Errorf("no result for %v: the check is stuck or too slow", r.now().Sub(done).Round(time.Second))
			err = errors.Join(stuck, err) // the last reason, if it was one, stays
		}
		if err != nil && e.name != "" {
			err = fmt.Errorf("%s: %w", e.name, err)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
