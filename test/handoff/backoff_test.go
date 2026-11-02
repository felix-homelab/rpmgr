// SPDX-License-Identifier: Apache-2.0

//go:build handoff

package handoff

import "testing"

func TestDelaysGrew(t *testing.T) {
	for name, c := range map[string]struct {
		at   []int64
		grew bool
	}{
		// The attempts of the nightly run 41163969176: two connectors, merged, the last two
		// attempts 393 ms apart although each connector waits 14 s between its own.
		"merged attempts of two connectors": {at: []int64{33196, 33677, 34071, 35157, 37412, 38819, 48319, 55495, 69753, 70146}, grew: true},
		"one connector, doubling":           {at: []int64{0, 1000, 3000, 7000, 15000, 30000}, grew: true},
		"a loop without delay":              {at: []int64{0, 100, 200, 300, 400, 500}},
		"constant delay":                    {at: []int64{0, 1000, 2000, 3000, 4000}},
		"shrinking delay":                   {at: []int64{0, 9000, 14000, 15000, 15100, 15200}},
		"three attempts":                    {at: []int64{0, 500, 3000}, grew: true},
	} {
		t.Run(name, func(t *testing.T) {
			first, last := delaysGrew(c.at)
			if got := last > first; got != c.grew {
				t.Errorf("first %d, last %d: grew %v, want %v", first, last, got, c.grew)
			}
		})
	}
}
