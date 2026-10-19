// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// replica is one controller replica: it holds agents' control sessions, registers them in the
// session registry, LISTENs for signals, and serves probes, forwarding them over
// controller-to-controller mutual TLS to the replica that holds the agent's session.
type replica struct {
	node      string
	pool      *pgxpool.Pool
	poll      time.Duration // the revision check; 0 disables it
	resync    bool          // full resync after the LISTEN connection was re-established
	admission *bucket       // new sessions per second; nil is unlimited

	mu         sync.Mutex
	sessions   map[string]*session
	superseded map[string]int64 // the highest epoch other replicas announced, per agent
	agentSeq   map[string]int64 // the highest agent_rev signalled, per agent
	lastSeq    int64            // the highest configuration revision known

	c2c       *http.Client // nil without -internal
	c2cDomain string

	probeID atomic.Int64
	stats   replicaStats
}

type replicaStats struct {
	Notifications  atomic.Int64
	ListenerDrops  atomic.Int64
	Resyncs        atomic.Int64
	ResyncPushes   atomic.Int64 // sessions a resync or poll brought up to date
	Superseded     atomic.Int64 // sessions ended because another replica took the agent
	SupersedeLocal atomic.Int64
	Overloaded     atomic.Int64
	Dropped        atomic.Int64 // targeted signals for an agent without a session here
	PollPushes     atomic.Int64
}

type session struct {
	agent  string
	epoch  int64
	w      *wire
	out    chan Msg
	done   chan struct{}
	once   sync.Once
	sent   int64 // configuration revision last sent
	asent  int64 // agent_rev last sent
	mu     sync.Mutex
	probes map[int64]chan Msg
}

func (s *session) end(reason string) {
	s.once.Do(func() {
		if reason != "" {
			_ = s.w.send(Msg{T: "goodbye", Reason: reason})
		}
		close(s.done)
		_ = s.w.c.Close()
	})
}

// push queues m unless the session is gone; a session that cannot keep up is ended.
func (s *session) push(m Msg) {
	select {
	case s.out <- m:
	case <-s.done:
	default:
		s.end("slow")
	}
}

func runReplica(args []string) error {
	fs := flag.NewFlagSet("replica", flag.ExitOnError)
	node := fs.String("node", "", "node ID")
	listen := fs.String("listen", "127.0.0.1:0", "agent listener")
	admin := fs.String("admin", "127.0.0.1:0", "admin listener (stats, probes)")
	internal := fs.String("internal", "", "controller-to-controller mutual-TLS listener; empty disables")
	certs := fs.String("certs", "", "directory with ca.pem and <node>.pem/<node>-key.pem")
	poll := fs.Duration("poll", time.Second, "revision check interval; 0 disables")
	resync := fs.Bool("resync", true, "full resync after the LISTEN connection is re-established")
	admission := fs.Int("admission", 0, "new control sessions per second; 0 is unlimited")
	_ = fs.Parse(args)
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn())
	if err != nil {
		return err
	}
	cfg.MaxConns = 16
	cfg.ConnConfig.RuntimeParams["application_name"] = "s9-" + *node
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	r := &replica{node: *node, pool: pool, poll: *poll, resync: *resync, sessions: map[string]*session{},
		superseded: map[string]int64{}, agentSeq: map[string]int64{}}
	if *admission > 0 {
		r.admission = newBucket(*admission)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	aln, err := net.Listen("tcp", *admin)
	if err != nil {
		return err
	}
	if *internal != "" {
		iln, err := r.startC2C(ctx, *internal, *certs)
		if err != nil {
			return err
		}
		defer func() { _ = iln.Close() }()
	}
	listening := make(chan struct{})
	go r.listen(ctx, listening)
	<-listening
	if r.poll > 0 {
		go r.pollLoop(ctx)
	}
	go r.serveAdmin(aln)
	// The parent reads this line to learn the addresses.
	fmt.Printf("READY %s %s\n", ln.Addr(), aln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.serve(ctx, c)
	}
}

// listen keeps a dedicated connection LISTENing on the broadcast channel and the replica's own
// channel. When it drops, it reconnects, LISTENs again and then, if enabled, resyncs: signals
// committed while it was gone are never delivered to it.
func (r *replica) listen(ctx context.Context, first chan struct{}) {
	backoff := 100 * time.Millisecond
	for {
		cfg, err := pgx.ParseConfig(dsn())
		if err != nil {
			log.Fatal(err)
		}
		cfg.RuntimeParams["application_name"] = "s9-listen-" + r.node
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err == nil {
			_, err = conn.Exec(ctx, "LISTEN "+revChannel+"; LISTEN "+nodeChannel(r.node))
		}
		if err != nil {
			log.Printf("listen: %v", err)
			time.Sleep(backoff)
			continue
		}
		if first != nil {
			close(first)
			first = nil
		}
		if r.resync {
			r.resyncAll(ctx, "listen")
		}
		for {
			n, err := conn.WaitForNotification(ctx)
			if err != nil {
				r.stats.ListenerDrops.Add(1)
				log.Printf("listen connection lost: %v", err)
				_ = conn.Close(context.Background())
				break
			}
			r.stats.Notifications.Add(1)
			r.handle(n.Channel, n.Payload)
		}
		time.Sleep(backoff)
	}
}

func (r *replica) handle(channel, payload string) {
	f := strings.Fields(payload)
	if channel == revChannel && len(f) == 2 {
		seq, t0 := atoi(f[0]), atoi(f[1])
		r.mu.Lock()
		if seq > r.lastSeq {
			r.lastSeq = seq
		}
		targets := make([]*session, 0, len(r.sessions))
		for _, s := range r.sessions {
			targets = append(targets, s)
		}
		r.mu.Unlock()
		for _, s := range targets {
			s.mu.Lock()
			if seq > s.sent {
				s.sent = seq
				s.mu.Unlock()
				s.push(Msg{T: "rev", Seq: seq, T0: t0})
				continue
			}
			s.mu.Unlock()
		}
		return
	}
	switch {
	case len(f) == 4 && f[0] == "push":
		agent, seq, t0 := f[1], atoi(f[2]), atoi(f[3])
		r.mu.Lock()
		if seq > r.agentSeq[agent] {
			r.agentSeq[agent] = seq
		}
		s := r.sessions[agent]
		r.mu.Unlock()
		if s == nil {
			r.stats.Dropped.Add(1)
			return
		}
		s.mu.Lock()
		if seq > s.asent {
			s.asent = seq
			s.mu.Unlock()
			s.push(Msg{T: "agent", AgentSeq: seq, T0: t0})
			return
		}
		s.mu.Unlock()
	case len(f) == 3 && f[0] == "supersede":
		agent, epoch := f[1], atoi(f[2])
		r.mu.Lock()
		if epoch > r.superseded[agent] {
			r.superseded[agent] = epoch
		}
		s := r.sessions[agent]
		if s != nil && s.epoch < epoch {
			delete(r.sessions, agent)
		} else {
			s = nil
		}
		r.mu.Unlock()
		if s != nil {
			r.stats.Superseded.Add(1)
			s.end("superseded")
		}
	}
}

// resyncAll brings every session up to date from the database: the revision, each agent's
// snapshot, and the registry, ending sessions another replica has taken over. It is the full
// resync after a lost LISTEN connection (R4) and, with why == "poll", the revision check.
func (r *replica) resyncAll(ctx context.Context, why string) {
	var seq int64
	if err := r.pool.QueryRow(ctx, `SELECT seq FROM config WHERE id = 1`).Scan(&seq); err != nil {
		log.Printf("resync: %v", err)
		return
	}
	r.mu.Lock()
	if seq > r.lastSeq {
		r.lastSeq = seq
	}
	agents := make([]string, 0, len(r.sessions))
	for a := range r.sessions {
		agents = append(agents, a)
	}
	r.mu.Unlock()
	rows, err := r.pool.Query(ctx, `SELECT s.agent_id, s.session_epoch, coalesce(v.seq, 0)
		FROM agent_sessions s LEFT JOIN agent_rev v ON v.agent_id = s.agent_id WHERE s.agent_id = ANY($1)`, agents)
	if err != nil {
		log.Printf("resync: %v", err)
		return
	}
	type row struct {
		epoch, aseq int64
	}
	db := map[string]row{}
	for rows.Next() {
		var a string
		var x row
		if err := rows.Scan(&a, &x.epoch, &x.aseq); err != nil {
			log.Printf("resync: %v", err)
			return
		}
		db[a] = x
	}
	if rows.Err() != nil {
		return
	}
	if why == "listen" {
		r.stats.Resyncs.Add(1)
	}
	r.mu.Lock()
	var stale, current []*session
	for a, s := range r.sessions {
		if x, ok := db[a]; ok && x.epoch > s.epoch {
			delete(r.sessions, a)
			stale = append(stale, s)
			continue
		}
		current = append(current, s)
	}
	r.mu.Unlock()
	for _, s := range stale {
		r.stats.Superseded.Add(1)
		s.end("superseded")
	}
	for _, s := range current {
		x := db[s.agent]
		s.mu.Lock()
		var msgs []Msg
		if seq > s.sent {
			s.sent = seq
			msgs = append(msgs, Msg{T: "rev", Seq: seq})
		}
		if x.aseq > s.asent {
			s.asent = x.aseq
			msgs = append(msgs, Msg{T: "agent", AgentSeq: x.aseq})
		}
		s.mu.Unlock()
		for _, m := range msgs {
			if why == "poll" {
				r.stats.PollPushes.Add(1)
			} else {
				r.stats.ResyncPushes.Add(1)
			}
			s.push(m)
		}
	}
}

func (r *replica) pollLoop(ctx context.Context) {
	t := time.NewTicker(r.poll)
	for range t.C {
		r.resyncAll(ctx, "poll")
	}
}

// serve runs one control session.
func (r *replica) serve(ctx context.Context, c net.Conn) {
	w := newWire(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, err := w.recv()
	_ = c.SetReadDeadline(time.Time{})
	if err != nil || hello.T != "hello" || hello.Agent == "" {
		_ = c.Close()
		return
	}
	if r.admission != nil && !r.admission.take() {
		r.stats.Overloaded.Add(1)
		_ = w.send(Msg{T: "goodbye", Reason: "overloaded", RetryAfter: int64(1000 + rand.IntN(9000))}) //nolint:gosec // jitter
		_ = c.Close()
		return
	}
	epoch, seq, aseq, err := r.register(ctx, hello.Agent)
	if err != nil {
		log.Printf("register %s: %v", hello.Agent, err)
		_ = w.send(Msg{T: "goodbye", Reason: "unavailable", RetryAfter: 1000})
		_ = c.Close()
		return
	}
	s := &session{agent: hello.Agent, epoch: epoch, w: w, out: make(chan Msg, 4096), done: make(chan struct{}),
		probes: map[int64]chan Msg{}}
	r.mu.Lock()
	if r.superseded[hello.Agent] >= epoch { // another replica took the agent before we got here
		r.mu.Unlock()
		r.stats.Superseded.Add(1)
		s.end("superseded")
		return
	}
	old := r.sessions[hello.Agent]
	r.sessions[hello.Agent] = s
	seq = max(seq, r.lastSeq)
	aseq = max(aseq, r.agentSeq[hello.Agent])
	s.sent, s.asent = seq, aseq
	r.mu.Unlock()
	if old != nil {
		r.stats.SupersedeLocal.Add(1)
		old.end("superseded")
	}
	go func() {
		for {
			select {
			case m := <-s.out:
				if err := w.send(m); err != nil {
					s.end("")
					return
				}
			case <-s.done:
				return
			}
		}
	}()
	if err := w.send(Msg{T: "welcome", Node: r.node, Epoch: epoch, Seq: seq, AgentSeq: aseq}); err != nil {
		s.end("")
	}
	for {
		m, err := w.recv()
		if err != nil {
			break
		}
		if m.T == "probe_result" {
			s.mu.Lock()
			ch := s.probes[m.ID]
			delete(s.probes, m.ID)
			s.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}
	s.end("")
	r.mu.Lock()
	if r.sessions[hello.Agent] == s {
		delete(r.sessions, hello.Agent)
	}
	r.mu.Unlock()
}

// register gives the session the agent's next epoch and tells the replica that held the agent
// before, in the same transaction, so that it ends its session. It returns the revision and the
// agent's snapshot as of after the registry row was locked.
func (r *replica) register(ctx context.Context, agent string) (epoch, seq, aseq int64, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The row exists before it is locked, so that two first registrations of an agent are
	// ordered by the lock too.
	if _, err := tx.Exec(ctx, `INSERT INTO agent_sessions (agent_id, node, session_epoch) VALUES ($1, '', 0)
		ON CONFLICT (agent_id) DO NOTHING`, agent); err != nil {
		return 0, 0, 0, err
	}
	var old string
	if err := tx.QueryRow(ctx, `SELECT node FROM agent_sessions WHERE agent_id = $1 FOR UPDATE`, agent).Scan(&old); err != nil {
		return 0, 0, 0, err
	}
	if err := tx.QueryRow(ctx, `UPDATE agent_sessions SET session_epoch = session_epoch + 1, node = $2,
		connected_at = now() WHERE agent_id = $1 RETURNING session_epoch`, agent, r.node).Scan(&epoch); err != nil {
		return 0, 0, 0, err
	}
	if old != "" && old != r.node {
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, nodeChannel(old), fmt.Sprintf("supersede %s %d", agent, epoch)); err != nil {
			return 0, 0, 0, err
		}
	}
	if err := tx.QueryRow(ctx, `SELECT c.seq, coalesce((SELECT seq FROM agent_rev WHERE agent_id = $1), 0)
		FROM config c WHERE c.id = 1`, agent).Scan(&seq, &aseq); err != nil {
		return 0, 0, 0, err
	}
	return epoch, seq, aseq, tx.Commit(ctx)
}

// probe asks the agent's connector to probe a target: directly when this replica holds the
// session, else over controller-to-controller mutual TLS to the replica that does.
func (r *replica) probe(ctx context.Context, agent string, delay time.Duration, forward bool) (string, error) {
	r.mu.Lock()
	s := r.sessions[agent]
	r.mu.Unlock()
	if s != nil {
		return r.node, r.probeLocal(ctx, s, delay)
	}
	if !forward || r.c2c == nil {
		return "", errNotHere
	}
	var node, addr string
	err := r.pool.QueryRow(ctx, `SELECT s.node, n.internal_address FROM agent_sessions s
		JOIN controller_nodes n ON n.node_id = s.node WHERE s.agent_id = $1`, agent).Scan(&node, &addr)
	if err != nil {
		return "", fmt.Errorf("registry: %w", err)
	}
	return node, r.forward(ctx, node, addr, agent, delay)
}

var errNotHere = errors.New("the agent has no session here")

func (r *replica) probeLocal(ctx context.Context, s *session, delay time.Duration) error {
	id := r.probeID.Add(1)
	ch := make(chan Msg, 1)
	s.mu.Lock()
	s.probes[id] = ch
	s.mu.Unlock()
	s.push(Msg{T: "probe", ID: id, DelayMs: delay.Milliseconds()})
	// ProbeTargetCertificate waits at most 15 s for the connector's answer (03, timeouts).
	t := time.NewTimer(15 * time.Second)
	defer t.Stop()
	select {
	case <-ch:
		return nil
	case <-s.done:
		return errors.New("session ended")
	case <-t.C:
		return errors.New("probe timed out")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *replica) serveAdmin(ln net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		sessions := make(map[string]int64, len(r.sessions))
		for a, s := range r.sessions {
			sessions[a] = s.epoch
		}
		last := r.lastSeq
		r.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"node": r.node, "sessions": sessions, "last_seq": last,
			"notifications": r.stats.Notifications.Load(), "listener_drops": r.stats.ListenerDrops.Load(),
			"resyncs": r.stats.Resyncs.Load(), "resync_pushes": r.stats.ResyncPushes.Load(),
			"poll_pushes": r.stats.PollPushes.Load(), "superseded": r.stats.Superseded.Load(),
			"superseded_local": r.stats.SupersedeLocal.Load(), "overloaded": r.stats.Overloaded.Load(),
			"dropped_signals": r.stats.Dropped.Load()})
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, req *http.Request) {
		delay, _ := time.ParseDuration(req.URL.Query().Get("delay"))
		start := time.Now()
		node, err := r.probe(req.Context(), req.URL.Query().Get("agent"), delay, true)
		res := map[string]any{"via": node, "ms": float64(time.Since(start).Microseconds()) / 1000}
		if err != nil {
			res["error"] = err.Error()
		}
		_ = json.NewEncoder(w).Encode(res)
	})
	_ = http.Serve(ln, mux) //nolint:gosec // loopback admin listener of a spike
}

// bucket is a token bucket for the admission limit (03: 50 new control sessions/s per replica).
type bucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

func newBucket(perSecond int) *bucket {
	return &bucket{rate: float64(perSecond), tokens: float64(perSecond), last: time.Now()}
}

func (b *bucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens = min(b.rate, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
