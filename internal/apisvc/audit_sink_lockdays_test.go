// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"math"
	"testing"
)

// TestLockDays: a retention outside the int32 range shows as zero instead of wrapping.
func TestLockDays(t *testing.T) {
	for in, want := range map[int]int32{0: 0, 365: 365, 3650: 3650, -1: 0, math.MaxInt32: math.MaxInt32} {
		if got := lockDays(in); got != want {
			t.Errorf("lockDays(%d) = %d, want %d", in, got, want)
		}
	}
	if big := int64(math.MaxInt32) + 1; int64(int(big)) == big {
		if got := lockDays(int(big)); got != 0 {
			t.Errorf("lockDays(MaxInt32+1) = %d, want 0", got)
		}
	}
}

// TestCount32: a count outside the int32 range is held at its edge instead of wrapping.
func TestCount32(t *testing.T) {
	for in, want := range map[int]int32{0: 0, 7: 7, -1: 0, math.MaxInt32: math.MaxInt32} {
		if got := count32(in); got != want {
			t.Errorf("count32(%d) = %d, want %d", in, got, want)
		}
	}
	if big := int64(math.MaxInt32) + 1; int64(int(big)) == big {
		if got := count32(int(big)); got != math.MaxInt32 {
			t.Errorf("count32(MaxInt32+1) = %d, want MaxInt32", got)
		}
	}
}
