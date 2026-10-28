// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// TestNext (#649): retries come 10 s after the first attempt, doubling to at most 1 h, and none is
// scheduled past 24 h after the event.
func TestNext(t *testing.T) {
	at := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	for n, want := range map[int]time.Duration{1: 10 * time.Second, 2: 20 * time.Second, 3: 40 * time.Second, 9: 2560 * time.Second,
		10: time.Hour, 11: time.Hour, 1000: time.Hour} {
		next, ok := webhook.Next(n, at, at)
		if !ok || next.Sub(at) != want {
			t.Errorf("after attempt %d: %s %v, want %s", n, next.Sub(at), ok, want)
		}
	}
	if next, ok := webhook.Next(10, at.Add(23*time.Hour), at); !ok || !next.Equal(at.Add(webhook.GiveUp)) {
		t.Errorf("a retry exactly at the give-up time: %v %v", next, ok)
	}
	if _, ok := webhook.Next(10, at.Add(23*time.Hour+time.Second), at); ok {
		t.Error("a retry past the give-up time was scheduled")
	}
}
