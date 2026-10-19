// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"time"
)

// runQ5: a replica killed with SIGKILL under load. Its agents move to the other replicas with
// rpmgr's reconnect backoff and the admission limit (50 new sessions/s per replica, 03); the
// configuration keeps reaching every agent. Data connections never pass through a controller;
// the end-to-end cells of the product show that with real processes (README).
func runQ5(args []string) error {
	fs := flag.NewFlagSet("q5", flag.ExitOnError)
	agents := fs.Int("agents", 1000, "agents")
	_ = fs.Parse(args)
	ctx := context.Background()
	r, err := newReport("q5")
	if err != nil {
		return err
	}
	defer r.close()
	f, err := startFleet(ctx, 3, *agents, []string{"-poll", "1s", "-resync=true", "-admission", "50"}, false)
	if err != nil {
		return err
	}
	defer f.close()
	r.printf("Q5: 3 replicas (admission 50/s, revision check 1 s), %d agents spread over them, revisions at 10/s", *agents)
	done := make(chan struct{})
	var revErr error
	go func() {
		defer close(done)
		_, revErr = f.revisions(ctx, 400, 10) // 40 s
	}()
	time.Sleep(10 * time.Second)
	victims := map[string]bool{}
	for _, a := range f.agents {
		if _, _, node, _, _ := a.snapshot(); node == "r1" {
			victims[a.id] = true
		}
	}
	killed := time.Now()
	f.procs[0].kill()
	r.printf("killed r1 with SIGKILL; it held %d agents", len(victims))
	err = f.waitConnected(60 * time.Second)
	all := time.Since(killed)
	r.printf("every agent has a session again after %s (err %v)", all.Round(time.Millisecond), err)
	<-done
	if revErr != nil {
		return revErr
	}
	time.Sleep(2 * time.Second)
	var fo []float64
	others := 0
	for _, a := range f.agents {
		a.mu.Lock()
		for _, d := range a.failovers {
			if victims[a.id] {
				fo = append(fo, float64(d.Milliseconds()))
			} else {
				others++
			}
		}
		a.mu.Unlock()
	}
	r.printf("failover of r1's agents, from losing the session to the next Welcome: %s", dist(fo))
	f.procs = f.procs[1:] // r1 is gone
	f.printStatus(r)
	bR, bA, err := f.converged(ctx)
	if err != nil {
		return err
	}
	pass := r.verdict(err == nil && len(fo) == len(victims), "all %d agents of r1 failed over (%d failovers)", len(victims), len(fo))
	maxFo := 0.0
	for _, x := range fo {
		maxFo = max(maxFo, x)
	}
	pass = r.verdict(maxFo <= 30000, "slowest failover %.0f ms within the control reconnect backoff cap of 30 s", maxFo) && pass
	pass = r.verdict(others == 0, "agents of the other replicas kept their sessions: %d reconnects", others) && pass
	pass = r.verdict(bR == 0 && bA == 0, "every agent holds the newest revision afterwards: %d behind", bR+bA) && pass
	r.printf("Q5 overall: %v", map[bool]string{true: "PASS", false: "FAIL"}[pass])
	return nil
}
