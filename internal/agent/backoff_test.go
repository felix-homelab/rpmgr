// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
)

// TestBackoff: every delay is within [0, min(cap, base·2^n)], a Goodbye's retry_after is a floor,
// and a healthy connection starts the sequence over.
func TestBackoff(t *testing.T) {
	b := agent.ControlBackoff()
	var maxSeen time.Duration
	for n := 0; n < 200; n++ {
		ceiling := min(b.Cap, b.Base<<min(n, 30))
		d := b.Next(0)
		if d < 0 || d > ceiling {
			t.Fatalf("attempt %d: %v outside [0, %v]", n, d, ceiling)
		}
		maxSeen = max(maxSeen, d)
	}
	if maxSeen < b.Cap/2 {
		t.Errorf("200 attempts never came near the cap: %v", maxSeen)
	}
	if d := b.Next(7 * time.Second); d < 7*time.Second {
		t.Errorf("retry_after 7 s gave %v", d)
	}
	b.Healthy(59 * time.Second)
	if d := b.Next(0); d > b.Cap {
		t.Fatal("over the cap")
	}
	b.Healthy(time.Minute)
	for i := 0; i < 50; i++ {
		if d := b.Next(0); d > b.Base {
			t.Fatalf("after a healthy minute the first delay was %v, want at most %v", d, b.Base)
		}
		b.Healthy(time.Minute)
	}
}
