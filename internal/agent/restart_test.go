// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
)

// TestRestartDelay: the wait before the redial after Goodbye{restart} is a jitter within [0, 1 s],
// not a backoff: it does not grow with the number of restarts.
func TestRestartDelay(t *testing.T) {
	for _, tc := range []struct {
		frac float64
		want time.Duration
	}{{0, 0}, {0.5, 500 * time.Millisecond}, {0.999999, 999999 * time.Microsecond}} {
		if got := agent.RestartDelay(func() float64 { return tc.frac }); got != tc.want {
			t.Errorf("fraction %v: %v, want %v", tc.frac, got, tc.want)
		}
	}
	for range 1000 {
		if d := agent.RestartDelay(agent.RandomFraction); d < 0 || d > time.Second {
			t.Fatalf("delay %v outside [0, 1 s]", d)
		}
	}
}
