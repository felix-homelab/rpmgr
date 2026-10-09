// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ratelimit"
)

// TestBackoff: four failures cost nothing; after the fifth each attempt waits 1 s, doubling up to
// 60 s; a success forgets the key; other keys are unaffected.
func TestBackoff(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	b := ratelimit.NewBackoff(5, time.Second, time.Minute, func() time.Time { return now })
	for i := 1; i <= 4; i++ {
		b.Fail("ada")
		if w := b.Wait("ada"); w != 0 {
			t.Fatalf("after %d failures: %v", i, w)
		}
	}
	for i, want := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		b.Fail("ada")
		if w := b.Wait("ada"); w != want*time.Second {
			t.Fatalf("after %d failures: %v, want %v", 5+i, w, want*time.Second)
		}
		if b.Wait("bob") != 0 {
			t.Fatal("another key waits")
		}
		now = now.Add(want*time.Second - time.Millisecond)
		if b.Wait("ada") != time.Millisecond {
			t.Fatal("the wait ended early")
		}
		now = now.Add(time.Millisecond)
		if b.Wait("ada") != 0 {
			t.Fatal("the wait did not end")
		}
	}
	b.Succeed("ada")
	b.Fail("ada")
	if b.Wait("ada") != 0 {
		t.Fatal("a success did not reset the key")
	}
}
