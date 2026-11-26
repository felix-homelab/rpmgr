// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/kms"
	"github.com/felix-homelab/rpmgr/internal/kms/kmstest"
)

func kmsHealthFor(t *testing.T, srv *kmstest.Server) (*kmsHealth, *kms.Client) {
	t.Helper()
	h := newKMSHealth()
	c, err := kms.New(kms.Config{Address: srv.URL, Key: kmstest.Key, CAFile: srv.CAFile(),
		TokenFile: srv.WriteCredential("token", kmstest.Token), Observe: h.observe})
	if err != nil {
		t.Fatal(err)
	}
	h.probe = func(ctx context.Context) error { _, err := c.Check(ctx); return err }
	return h, c
}

// TestKMSHealth_KeyThatFailsItsCheckIsNotReady: after an outage, Transit comes back with a key that
// is not derived, of another type, or gone; the check that /readyz makes fails, so the controller
// stays not ready and rpmgr_kms_up stays 0, until the key is right again.
func TestKMSHealth_KeyThatFailsItsCheckIsNotReady(t *testing.T) {
	ctx := context.Background()
	srv := kmstest.New(t)
	h, c := kmsHealthFor(t, srv)
	clock := time.Unix(1_800_000_000, 0)
	h.now = func() time.Time { return clock }
	next := func() { clock = clock.Add(2 * probeEvery) }

	srv.FailWith(503, false)
	_, _ = c.Check(ctx)
	if err := h.Ready(ctx); err == nil {
		t.Fatal("ready while Transit is down")
	}
	for name, set := range map[string]func(){
		"not derived":  func() { srv.SetKey("aes256-gcm96", false) },
		"another type": func() { srv.SetKey("chacha20-poly1305", true) },
	} {
		srv.FailWith(0, false)
		set()
		next()
		if err := h.Ready(ctx); err == nil || h.up.Load() {
			t.Errorf("%s: ready although the key fails its check (%v)", name, err)
		}
	}
	srv.SetKey("aes256-gcm96", true)
	next()
	if err := h.Ready(ctx); err != nil || !h.up.Load() {
		t.Errorf("not ready with a good key again: %v", err)
	}
	// Up, then the key fails its check in a request of the controller's own.
	srv.SetKey("aes256-gcm96", false)
	if _, err := c.Check(ctx); err == nil {
		t.Fatal("a check of a key that is not derived succeeded")
	}
	if h.up.Load() {
		t.Error("rpmgr_kms_up stays 1 after a failed check")
	}
}

// TestKMSHealth_ProbesAreShared: while Transit is down, concurrent readiness checks and checks
// within a second share one read of the key.
func TestKMSHealth_ProbesAreShared(t *testing.T) {
	h := newKMSHealth()
	clock := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	h.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	var probes atomic.Int32
	h.probe = func(context.Context) error {
		probes.Add(1)
		time.Sleep(20 * time.Millisecond)
		return context.DeadlineExceeded
	}
	h.observe("check", "unavailable")
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.Ready(context.Background()); err == nil {
				t.Error("ready")
			}
		}()
	}
	wg.Wait()
	if n := probes.Load(); n != 1 {
		t.Errorf("%d probes for 20 concurrent checks, want 1", n)
	}
	mu.Lock()
	clock = clock.Add(probeEvery)
	mu.Unlock()
	_ = h.Ready(context.Background())
	if n := probes.Load(); n != 2 {
		t.Errorf("%d probes after a second, want 2", n)
	}
}
