// SPDX-License-Identifier: Apache-2.0

package routes

import "testing"

// TestAddWeight: an entry's weight sums its targets' weights, below 1 counted as 1, and stops at the
// bound the gateway accepts, so that many heavy targets never make it refuse the snapshot.
func TestAddWeight(t *testing.T) {
	for _, tc := range []struct {
		sum    uint32
		weight int
		want   uint32
	}{
		{0, 0, 1}, {0, -5, 1}, {1, 1000, 1001}, {maxRankWeight - 1, 1000, maxRankWeight}, {maxRankWeight, 1, maxRankWeight},
		{0, 2 * maxRankWeight, maxRankWeight},
	} {
		if got := addWeight(tc.sum, tc.weight); got != tc.want {
			t.Errorf("addWeight(%d, %d) = %d, want %d", tc.sum, tc.weight, got, tc.want)
		}
	}
	var sum uint32
	for range 1001 {
		sum = addWeight(sum, 1000)
	}
	if sum != maxRankWeight {
		t.Fatalf("1001 targets of weight 1000: %d, want %d", sum, maxRankWeight)
	}
}
