// SPDX-License-Identifier: Apache-2.0

// Command chaosseed finds a seed of test/e2e TestChaos whose first eight events hold the most
// controller SIGKILLs, by replaying the order in which cells_chaos_test.go draws from its PCG.
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	best, bestN := uint64(0), 0
	for seed := uint64(1); seed < 20000; seed++ {
		r := rand.New(rand.NewPCG(seed, seed))
		kills := 0
		var seq []string
		for i := 0; i < 8; i++ {
			switch r.IntN(5) {
			case 0:
				if r.IntN(2) == 0 {
					kills++
					seq = append(seq, "ctl-KILL")
				} else {
					seq = append(seq, "ctl-TERM")
				}
			case 1:
				r.IntN(5)
				r.IntN(10)
				seq = append(seq, "clock")
			case 2:
				r.IntN(5)
				seq = append(seq, "latency")
			case 3:
				r.IntN(4)
				seq = append(seq, "loss")
			case 4:
				r.IntN(4)
				seq = append(seq, "kill")
			}
			r.IntN(10)
		}
		if kills > bestN {
			best, bestN = seed, kills
			fmt.Println(seed, kills, seq)
		}
	}
	_ = best
}
