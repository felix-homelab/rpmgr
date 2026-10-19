// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// stormAgent opens and drops control sessions by hand, for Q2.
type stormAgent struct {
	id string

	mu       sync.Mutex
	open     map[*stormSession]bool
	welcomes []welcomeAt
	goodbyes []welcomeAt // superseded sessions: their epoch and when the Goodbye arrived
	failed   int
}

type welcomeAt struct {
	epoch int64
	node  string
	at    time.Time
}

type stormSession struct {
	c       net.Conn
	epoch   int64
	node    string
	welcome chan struct{}
	ended   chan struct{}
}

func (a *stormAgent) dial(ep string) *stormSession {
	c, err := net.DialTimeout("tcp", ep, 5*time.Second)
	if err != nil {
		a.mu.Lock()
		a.failed++
		a.mu.Unlock()
		return nil
	}
	s := &stormSession{c: c, welcome: make(chan struct{}), ended: make(chan struct{})}
	w := newWire(c)
	if err := w.send(Msg{T: "hello", Agent: a.id}); err != nil {
		_ = c.Close()
		return nil
	}
	a.mu.Lock()
	a.open[s] = true
	a.mu.Unlock()
	go func() {
		defer close(s.ended)
		defer func() {
			a.mu.Lock()
			delete(a.open, s)
			a.mu.Unlock()
			_ = c.Close()
		}()
		welcomed := false
		for {
			m, err := w.recv()
			if err != nil {
				if !welcomed {
					close(s.welcome)
				}
				return
			}
			now := time.Now()
			switch m.T {
			case "welcome":
				s.epoch, s.node = m.Epoch, m.Node
				a.mu.Lock()
				a.welcomes = append(a.welcomes, welcomeAt{m.Epoch, m.Node, now})
				a.mu.Unlock()
				welcomed = true
				close(s.welcome)
			case "goodbye":
				if !welcomed {
					close(s.welcome)
				}
				if m.Reason == "superseded" && welcomed {
					a.mu.Lock()
					a.goodbyes = append(a.goodbyes, welcomeAt{s.epoch, s.node, now})
					a.mu.Unlock()
				}
				return
			}
		}
	}()
	return s
}

// runQ2: the session registry under supersede and reconnect storms.
func runQ2(args []string) error {
	fs := flag.NewFlagSet("q2", flag.ExitOnError)
	agents := fs.Int("agents", 1000, "agents")
	rounds := fs.Int("rounds", 10, "storm rounds per agent")
	poll := fs.String("poll", "0", "revision check interval of the replicas (0: NOTIFY only)")
	_ = fs.Parse(args)
	ctx := context.Background()
	r, err := newReport("q2-poll" + *poll)
	if err != nil {
		return err
	}
	defer r.close()
	pool, err := setupDB(ctx, *agents)
	if err != nil {
		return err
	}
	defer pool.Close()
	var procs []*proc
	for i := range 3 {
		p, err := startReplica(fmt.Sprintf("r%d", i+1), logDir(), "-poll", *poll, "-resync=true")
		if err != nil {
			return err
		}
		defer p.kill()
		procs = append(procs, p)
	}
	r.printf("Q2: 3 replicas (poll %s), %d agents, %d storm rounds each, all agents at once", *poll, *agents, *rounds)
	as := make([]*stormAgent, *agents)
	var wg sync.WaitGroup
	actions := map[string]int{}
	var amu sync.Mutex
	start := time.Now()
	for i := range as {
		a := &stormAgent{id: agentID(i), open: map[*stormSession]bool{}}
		as[i] = a
		wg.Go(func() {
			rnd := rand.New(rand.NewPCG(uint64(i), 9)) //nolint:gosec // reproducible load
			ep := func() string { return procs[rnd.IntN(len(procs))].addr }
			var last *stormSession
			for range *rounds {
				var act string
				switch x := rnd.IntN(100); {
				case x < 40:
					act = "new session elsewhere, old one kept open"
					last = a.dial(ep())
				case x < 60:
					act = "reconnect: old one closed first"
					if last != nil {
						_ = last.c.Close()
						<-last.ended
					}
					last = a.dial(ep())
				case x < 80:
					act = "two sessions at once"
					s1, s2 := make(chan *stormSession), make(chan *stormSession)
					go func() { s1 <- a.dial(ep()) }()
					go func() { s2 <- a.dial(ep()) }()
					x1, x2 := <-s1, <-s2
					last = x2
					if x1 != nil && x2 != nil {
						<-x1.welcome
						<-x2.welcome
						if x1.epoch > x2.epoch {
							last = x1
						}
					}
				default:
					act = "new session on a replica chosen again"
					last = a.dial(ep())
				}
				amu.Lock()
				actions[act]++
				amu.Unlock()
				if last != nil {
					<-last.welcome
				}
				time.Sleep(time.Duration(rnd.IntN(50)) * time.Millisecond)
			}
		})
	}
	wg.Wait()
	r.printf("storm done in %s: %v", time.Since(start).Round(time.Millisecond), actions)
	// Settle, then compare the agents' open sessions, the replicas' sessions and the registry.
	time.Sleep(2 * time.Second)
	dbEpoch, dbNode := map[string]int64{}, map[string]string{}
	rows, err := pool.Query(ctx, `SELECT agent_id, session_epoch, node FROM agent_sessions`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var a, n string
		var e int64
		if err := rows.Scan(&a, &e, &n); err != nil {
			return err
		}
		dbEpoch[a], dbNode[a] = e, n
	}
	held := map[string][]string{} // agent → nodes whose replica holds a session
	heldEpoch := map[string]int64{}
	for _, p := range procs {
		st, err := p.status()
		if err != nil {
			return err
		}
		for a, e := range st.Sessions {
			held[a] = append(held[a], st.Node)
			heldEpoch[a] = e
		}
		r.printf("  %s: sessions=%d superseded(by other replica)=%d superseded(local)=%d resyncs=%d", st.Node, len(st.Sessions), st.Superseded, st.SuperLocal, st.Resyncs)
	}
	notOne, mismatch, clientOpen, stale, failed := 0, 0, 0, 0, 0
	var supLat []float64
	for _, a := range as {
		if len(held[a.id]) != 1 {
			notOne++
			r.printf("  agent %s held by %v", a.id, held[a.id])
			continue
		}
		if heldEpoch[a.id] != dbEpoch[a.id] || held[a.id][0] != dbNode[a.id] {
			mismatch++
		}
		a.mu.Lock()
		if len(a.open) != 1 {
			clientOpen++
		}
		failed += a.failed
		// Each superseded session needs a newer registration; the latency runs from the first
		// newer session's Welcome (negative: the Goodbye overtook the Welcome on another
		// connection).
		for _, g := range a.goodbyes {
			var first time.Time
			for _, w := range a.welcomes {
				if w.epoch > g.epoch && (first.IsZero() || w.at.Before(first)) {
					first = w.at
				}
			}
			switch {
			case !first.IsZero():
				supLat = append(supLat, float64(g.at.Sub(first).Microseconds())/1000)
			case g.epoch >= dbEpoch[a.id]:
				stale++
			}
		}
		a.mu.Unlock()
	}
	r.printf("superseded sessions ended, time from the newer session's Welcome to the older one's Goodbye: %s", dist(supLat))
	pass := r.verdict(notOne == 0, "exactly one session per agent across the replicas: %d agents with another count", notOne)
	pass = r.verdict(mismatch == 0, "the held session is the registry's (epoch and node): %d mismatches", mismatch) && pass
	pass = r.verdict(clientOpen == 0, "each agent has exactly one open connection left: %d agents differ", clientOpen) && pass
	pass = r.verdict(stale == 0, "no session was superseded without a newer one: %d", stale) && pass
	r.printf("dial failures: %d", failed)
	r.printf("Q2 overall: %v", map[bool]string{true: "PASS", false: "FAIL"}[pass])
	return nil
}
