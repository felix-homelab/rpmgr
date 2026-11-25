// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// waitIdle waits until no login or renewal runs. One that a request starts is running when the
// request returns, so this is a deterministic end of it.
func waitIdle(t *testing.T, c *Client) {
	t.Helper()
	for range 400 {
		c.mu.Lock()
		idle := c.flight == nil
		c.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a login or renewal is still running")
}

// failRenew makes the fake answer renew-self with a status while the flag is set.
func failRenew(f *fakeTransit, status int) *atomic.Bool {
	var on atomic.Bool
	on.Store(true)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/auth/token/renew-self" && on.Load() {
			f.fail(w, status, "unavailable")
			return true
		}
		return false
	}
	return &on
}

// A failed renewal of a token file that has not changed is tried again every 30 s, not at every
// request.
func TestFailedRenewalIsNotRepeatedAtEveryRequest(t *testing.T) {
	f := newFakeTransit(t)
	f.lease = 100
	c, _, clk := testClient(t, f, nil)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	const renew = "POST /v1/auth/token/renew-self"
	first := f.count(renew)
	failRenew(f, http.StatusInternalServerError)
	burst := func() {
		for range 6 {
			if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
				t.Fatal(err)
			}
		}
		waitIdle(t, c)
	}
	clk.advance(51 * time.Second) // half the lease
	burst()
	attempt := f.count(renew) - first // one request and its three retries
	if attempt != 1+maxRetries {
		t.Fatalf("%d renew-self requests for the first failed renewal, want %d", attempt, 1+maxRetries)
	}
	burst()
	if n := f.count(renew) - first; n != attempt {
		t.Errorf("%d renew-self requests after 12 more calls, want no new attempt (%d)", n, attempt)
	}
	clk.advance(31 * time.Second)
	burst()
	if n := f.count(renew) - first; n != 2*attempt {
		t.Errorf("%d renew-self requests 31 s later, want one more attempt (%d)", n, 2*attempt)
	}
}

// A probe that fails because Transit cannot be asked does not turn renewal off for good.
func TestProbeErrorKeepsRenewal(t *testing.T) {
	f := newFakeTransit(t)
	f.lease = 100
	c, _, clk := testClient(t, f, nil)
	on := failRenew(f, http.StatusServiceUnavailable)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	const renew = "POST /v1/auth/token/renew-self"
	failed := f.count(renew)
	if failed != 1+maxRetries {
		t.Fatalf("%d probe requests, want %d", failed, 1+maxRetries)
	}
	on.Store(false)
	clk.advance(31 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, c)
	if n := f.count(renew); n != failed+1 {
		t.Fatalf("%d renew-self requests 31 s after a failed probe, want %d", n, failed+1)
	}
	// It is renewable now, at half the lease.
	clk.advance(49 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, c)
	if n := f.count(renew); n != failed+1 {
		t.Errorf("renewed before half the lease: %d", n)
	}
	clk.advance(2 * time.Second)
	if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, c)
	if n := f.count(renew); n != failed+2 {
		t.Errorf("%d renew-self requests at half the lease, want %d", n, failed+2)
	}
}

// An answer that says the token cannot be renewed does turn renewal off.
func TestProbeRefusedMeansNotRenewable(t *testing.T) {
	f := newFakeTransit(t)
	c, _, clk := testClient(t, f, nil)
	failRenew(f, http.StatusBadRequest)
	for range 3 {
		clk.advance(10 * time.Hour)
		if _, err := c.Wrap(ctxA, dk, aadA); err != nil {
			t.Fatal(err)
		}
		waitIdle(t, c)
	}
	if n := f.count("POST /v1/auth/token/renew-self"); n != 1 {
		t.Errorf("%d renew-self requests for a token that cannot be renewed, want the probe only", n)
	}
}
