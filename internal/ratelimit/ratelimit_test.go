// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ratelimit"
)

func TestBurstAndRefill(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	l := ratelimit.New(6*time.Second, 10, func() time.Time { return now })
	for i := 0; i < 10; i++ {
		if !l.Allow("198.51.100.1") {
			t.Fatalf("event %d of the burst refused", i+1)
		}
	}
	if l.Allow("198.51.100.1") {
		t.Fatal("the 11th event within a minute was allowed")
	}
	if !l.Allow("198.51.100.2") {
		t.Fatal("another key shares the bucket")
	}
	now = now.Add(5999 * time.Millisecond)
	if l.Allow("198.51.100.1") {
		t.Fatal("refilled before one interval")
	}
	now = now.Add(time.Millisecond)
	if !l.Allow("198.51.100.1") || l.Allow("198.51.100.1") {
		t.Fatal("one interval refills exactly one event")
	}
	now = now.Add(time.Hour)
	for i := 0; i < 10; i++ {
		if !l.Allow("198.51.100.1") {
			t.Fatalf("after an hour, event %d refused: the bucket refills to the burst only", i+1)
		}
	}
	if l.Allow("198.51.100.1") {
		t.Fatal("the bucket held more than the burst")
	}
}

// TestManyKeys: a flood of distinct keys keeps the limiter bounded and fast, never resets a key
// that is limited, and new keys get in again once old buckets are full.
func TestManyKeys(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	l := ratelimit.New(time.Minute, 1, func() time.Time { return now })
	if !l.Allow("victim") || l.Allow("victim") {
		t.Fatal("burst of one")
	}
	start := time.Now()
	for i := 0; i < 250_000; i++ {
		l.Allow(fmt.Sprint("k", i))
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("250 000 keys took %v: the limiter scans too often", d)
	}
	if n := ratelimit.Keys(l); n > 100_000 {
		t.Fatalf("%d keys kept", n)
	}
	if l.Allow("victim") {
		t.Error("the flood reset a limited key")
	}
	if l.Allow("newcomer") {
		t.Error("a new key got in while every bucket was in use")
	}
	now = now.Add(time.Minute)
	if !l.Allow("newcomer") {
		t.Error("a new key is refused after the old buckets refilled")
	}
}

// TestOnRefuse: a Limiter and a Backoff report each refusal, and nothing else.
func TestOnRefuse(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	refused := 0
	l := ratelimit.New(time.Minute, 2, clock)
	l.OnRefuse = func() { refused++ }
	for range 3 {
		l.Allow("a")
	}
	if refused != 1 {
		t.Fatalf("the limiter reported %d refusals, want 1", refused)
	}
	refused = 0
	b := ratelimit.NewBackoff(1, time.Second, time.Minute, clock)
	b.OnRefuse = func() { refused++ }
	b.Wait("a")
	b.Fail("a")
	b.Fail("a")
	if b.Wait("a") == 0 || refused != 1 {
		t.Fatalf("the backoff reported %d refusals, want 1", refused)
	}
}
