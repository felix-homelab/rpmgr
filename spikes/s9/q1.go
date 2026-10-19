// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// fleet is a set of replicas and agents for one run.
type fleet struct {
	procs  []*proc
	agents []*agent
	stop   chan struct{}
	col    *collector
	pool   *pgxpool.Pool
}

func startFleet(ctx context.Context, n, agents int, replicaArgs []string, onlyHome bool) (*fleet, error) {
	pool, err := setupDB(ctx, agents)
	if err != nil {
		return nil, err
	}
	f := &fleet{stop: make(chan struct{}), col: newCollector(), pool: pool}
	for i := range n {
		p, err := startReplica(fmt.Sprintf("r%d", i+1), logDir(), replicaArgs...)
		if err != nil {
			f.close()
			return nil, err
		}
		f.procs = append(f.procs, p)
	}
	for i := range agents {
		var eps []string
		for j := range n {
			eps = append(eps, f.procs[(i+j)%n].addr)
			if onlyHome {
				break
			}
		}
		a := &agent{id: agentID(i), endpoints: eps, col: f.col}
		f.agents = append(f.agents, a)
		go a.run(f.stop)
	}
	return f, f.waitConnected(60 * time.Second)
}

func (f *fleet) waitConnected(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		n := 0
		for _, a := range f.agents {
			if _, _, _, _, c := a.snapshot(); c {
				n++
			}
		}
		if n == len(f.agents) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("not every agent connected within %s", limit)
}

func (f *fleet) close() {
	close(f.stop)
	for _, p := range f.procs {
		p.kill()
	}
	f.pool.Close()
}

// converged reports the agents that do not hold the newest revision and their own newest
// snapshot from the database.
func (f *fleet) converged(ctx context.Context) (behindRev, behindAgent int, err error) {
	var seq int64
	if err := f.pool.QueryRow(ctx, `SELECT seq FROM config WHERE id = 1`).Scan(&seq); err != nil {
		return 0, 0, err
	}
	want := map[string]int64{}
	rows, err := f.pool.Query(ctx, `SELECT agent_id, seq FROM agent_rev`)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var a string
		var s int64
		if err := rows.Scan(&a, &s); err != nil {
			return 0, 0, err
		}
		want[a] = s
	}
	for _, a := range f.agents {
		s, as, _, _, _ := a.snapshot()
		if s != seq {
			behindRev++
		}
		if as != want[a.id] {
			behindAgent++
		}
	}
	return behindRev, behindAgent, nil
}

func (f *fleet) terminateListener(ctx context.Context, node string) (int, error) {
	var n int
	err := f.pool.QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
		WHERE application_name = $1`, "s9-listen-"+node).Scan(&n)
	return n, err
}

// revisions commits n revisions at rate per second and records their commit times.
func (f *fleet) revisions(ctx context.Context, n int, rate float64) ([]int64, error) {
	tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
	defer tick.Stop()
	var seqs []int64
	for range n {
		<-tick.C
		seq, _, err := pushRevision(ctx, f.pool)
		if err != nil {
			return seqs, err
		}
		tc := time.Now()
		f.col.mu.Lock()
		f.col.commits[seq] = tc
		f.col.mu.Unlock()
		seqs = append(seqs, seq)
	}
	return seqs, nil
}

// targeted commits n targeted pushes to random agents at rate per second over workers.
func (f *fleet) targeted(ctx context.Context, n int, rate float64, workers int, pick func() string) error {
	jobs := make(chan string)
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Go(func() {
			for a := range jobs {
				if _, err := pushAgentTx(ctx, f.pool, a); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
	for range n {
		<-tick.C
		jobs <- pick()
	}
	tick.Stop()
	close(jobs)
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

func (f *fleet) randomAgent() string { return f.agents[rand.IntN(len(f.agents))].id } //nolint:gosec // test load

func (f *fleet) missing(seqs []int64) int {
	f.col.mu.Lock()
	defer f.col.mu.Unlock()
	miss := 0
	for _, a := range f.agents {
		for _, s := range seqs {
			if !f.col.got[a.id][s] {
				miss++
			}
		}
	}
	return miss
}

func (f *fleet) printStatus(r *report) {
	for _, p := range f.procs {
		st, err := p.status()
		if err != nil {
			r.printf("  %s: status: %v", p.node, err)
			continue
		}
		r.printf("  %s: sessions=%d last_seq=%d notifications=%d listener_drops=%d resyncs=%d resync_pushes=%d poll_pushes=%d superseded=%d superseded_local=%d overloaded=%d dropped_signals=%d",
			st.Node, len(st.Sessions), st.LastSeq, st.Notifications, st.ListenerDrops, st.Resyncs, st.ResyncPushes,
			st.PollPushes, st.Superseded, st.SuperLocal, st.Overloaded, st.Dropped)
	}
}

// runQ1: push fan-out with LISTEN/NOTIFY. Mode "main" measures latency (broadcast, targeted,
// burst) and the drop of a LISTEN connection with the full resync and without the revision check;
// "noresync" is the negative control (neither resync nor revision check); "poll" has only the
// revision check.
func runQ1(args []string) error {
	fs := flag.NewFlagSet("q1", flag.ExitOnError)
	mode := fs.String("mode", "main", "main | noresync | poll")
	agents := fs.Int("agents", 1000, "agents")
	_ = fs.Parse(args)
	ctx := context.Background()
	r, err := newReport("q1-" + *mode)
	if err != nil {
		return err
	}
	defer r.close()
	replicaArgs := map[string][]string{
		"main":     {"-poll", "0", "-resync=true"},
		"noresync": {"-poll", "0", "-resync=false"},
		"poll":     {"-poll", "1s", "-resync=false"},
	}[*mode]
	if replicaArgs == nil {
		return fmt.Errorf("unknown mode %q", *mode)
	}
	r.printf("Q1 mode=%s: 3 replicas (%v), %d agents", *mode, replicaArgs, *agents)
	start := time.Now()
	f, err := startFleet(ctx, 3, *agents, replicaArgs, true)
	if err != nil {
		return err
	}
	defer f.close()
	r.printf("all %d agents connected in %s", *agents, time.Since(start).Round(time.Millisecond))
	pass := true
	if *mode == "main" {
		// A: broadcast revisions.
		f.col.reset()
		seqs, err := f.revisions(ctx, 300, 20)
		if err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		f.col.mu.Lock()
		lat, after := f.col.revLat, f.col.afterC
		f.col.mu.Unlock()
		miss := f.missing(seqs)
		r.printf("A broadcast: 300 revisions at 20/s to %d agents: latency from before COMMIT %s", *agents, dist(lat))
		r.printf("A broadcast: latency from COMMIT's return %s", dist(after))
		pass = r.verdict(p99(lat) <= 1000, "A p99 %.2f ms <= 1000 ms", p99(lat)) && pass
		pass = r.verdict(miss == 0, "A deliveries missing: %d of %d", miss, len(seqs)*(*agents)) && pass
		// B: targeted pushes, each its own transaction.
		f.col.reset()
		t := time.Now()
		if err := f.targeted(ctx, 5000, 1000, 8, f.randomAgent); err != nil {
			return err
		}
		el := time.Since(t)
		time.Sleep(2 * time.Second)
		f.col.mu.Lock()
		lat = f.col.aLat
		f.col.mu.Unlock()
		r.printf("B targeted: 5000 pushes to random agents, 8 writers, %.0f/s achieved: latency %s", 5000/el.Seconds(), dist(lat))
		pass = r.verdict(p99(lat) <= 1000 && len(lat) == 5000, "B p99 %.2f ms <= 1000 ms, %d of 5000 delivered", p99(lat), len(lat)) && pass
		// C: one transaction that changes every agent's snapshot.
		f.col.reset()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			return err
		}
		for _, a := range f.agents {
			if _, err := pushAgent(ctx, tx, a.id); err != nil {
				return err
			}
		}
		beforeCommit := time.Now()
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		f.col.mu.Lock()
		lat = nil
		for _, t := range f.col.aRecv {
			lat = append(lat, float64(t.Sub(beforeCommit).Microseconds())/1000)
		}
		f.col.mu.Unlock()
		r.printf("C burst: one transaction with %d targeted signals: latency from COMMIT %s", *agents, dist(lat))
		pass = r.verdict(p99(lat) <= 1000 && len(lat) == *agents, "C p99 %.2f ms <= 1000 ms, %d of %d delivered", p99(lat), len(lat), *agents) && pass
		bR, bA, err := f.converged(ctx)
		if err != nil {
			return err
		}
		pass = r.verdict(bR == 0 && bA == 0, "A–C converged: %d agents behind on the revision, %d on their own snapshot", bR, bA) && pass
	}
	// D: the LISTEN connections of r2 and r3 are terminated while revisions and targeted pushes
	// flow.
	f.col.reset()
	var wg sync.WaitGroup
	var seqs []int64
	var revErr, tErr error
	wg.Go(func() { seqs, revErr = f.revisions(ctx, 200, 20) })
	wg.Go(func() { tErr = f.targeted(ctx, 2000, 200, 4, f.randomAgent) })
	time.Sleep(3 * time.Second)
	n, err := f.terminateListener(ctx, "r2")
	r.printf("D: terminated r2's LISTEN connection (%d backend, err %v)", n, err)
	time.Sleep(3 * time.Second)
	n, err = f.terminateListener(ctx, "r3")
	r.printf("D: terminated r3's LISTEN connection (%d backend, err %v)", n, err)
	wg.Wait()
	if revErr != nil || tErr != nil {
		return fmt.Errorf("load: %v %v", revErr, tErr)
	}
	r.printf("D: committed %d revisions and 2000 targeted pushes", len(seqs))
	miss := f.missing(seqs)
	r.printf("D: revision NOTIFYs that never reached an agent (lost while a LISTEN connection was down): %d", miss)
	var bR, bA int
	settle := time.Now()
	for {
		bR, bA, err = f.converged(ctx)
		if err != nil {
			return err
		}
		if (bR == 0 && bA == 0) || time.Since(settle) > 5*time.Second {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.printf("D: after the load, %d agents behind on the revision, %d behind on their own snapshot (waited %s)", bR, bA, time.Since(settle).Round(time.Millisecond))
	f.printStatus(r)
	switch *mode {
	case "noresync":
		r.verdict(bA > 0, "negative control: without resync and revision check, targeted signals are lost (%d agents behind) — expected", bA)
	default:
		pass = r.verdict(bR == 0 && bA == 0, "D no push lost when the LISTEN connection drops") && pass
	}
	r.printf("Q1 mode=%s overall: %v", *mode, map[bool]string{true: "PASS", false: "FAIL"}[pass])
	return nil
}
