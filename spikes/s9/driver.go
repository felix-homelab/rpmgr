// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// proc is a replica process the driver started.
type proc struct {
	node  string
	cmd   *exec.Cmd
	addr  string // agent listener
	admin string
}

// startReplica starts "s9 replica" as a separate process and waits for its READY line.
func startReplica(node, logDir string, extra ...string) (*proc, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := append([]string{"replica", "-node", node}, extra...)
	cmd := exec.Command(self, args...) //nolint:gosec // the spike's own binary
	logf, err := os.Create(filepath.Join(logDir, "replica-"+node+".log"))
	if err != nil {
		return nil, err
	}
	cmd.Stderr = logf
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(out)
	ready := make(chan []string, 1)
	go func() {
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) == 3 && f[0] == "READY" {
				ready <- f
			}
		}
	}()
	select {
	case f := <-ready:
		return &proc{node: node, cmd: cmd, addr: f[1], admin: f[2]}, nil
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("replica %s did not start", node)
	}
}

func (p *proc) kill() { _ = p.cmd.Process.Kill(); _, _ = p.cmd.Process.Wait() }

type replicaStatus struct {
	Node          string           `json:"node"`
	Sessions      map[string]int64 `json:"sessions"`
	LastSeq       int64            `json:"last_seq"`
	Notifications int64            `json:"notifications"`
	ListenerDrops int64            `json:"listener_drops"`
	Resyncs       int64            `json:"resyncs"`
	ResyncPushes  int64            `json:"resync_pushes"`
	PollPushes    int64            `json:"poll_pushes"`
	Superseded    int64            `json:"superseded"`
	SuperLocal    int64            `json:"superseded_local"`
	Overloaded    int64            `json:"overloaded"`
	Dropped       int64            `json:"dropped_signals"`
}

func (p *proc) status() (replicaStatus, error) {
	var st replicaStatus
	resp, err := http.Get("http://" + p.admin + "/stats") //nolint:noctx // spike
	if err != nil {
		return st, err
	}
	defer func() { _ = resp.Body.Close() }()
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

// agent is a simulated agent with rpmgr's reconnect behaviour: endpoints in order, full-jitter
// backoff (base 0.5 s, factor 2, cap 30 s, reset after 60 s healthy), Goodbye.retry_after honoured
// (03, timeouts).
type agent struct {
	id        string
	endpoints []string
	col       *collector

	mu        sync.Mutex
	seq       int64 // configuration revision received
	aseq      int64 // own snapshot received
	node      string
	epoch     int64
	connected bool
	welcomes  int
	lostAt    time.Time
	failovers []time.Duration // time from losing a session to the next welcome
}

func (a *agent) run(stop <-chan struct{}) {
	attempt := 0
	i := 0
	for {
		select {
		case <-stop:
			return
		default:
		}
		ep := a.endpoints[i%len(a.endpoints)]
		healthy, retryAfter := a.session(ep, stop)
		select {
		case <-stop:
			return
		default:
		}
		if healthy >= 60*time.Second {
			attempt = 0
		}
		wait := time.Duration(rand.Int64N(int64(min(30*time.Second, time.Duration(float64(500*time.Millisecond)*math.Pow(2, float64(attempt))))))) //nolint:gosec // jitter
		attempt++
		if retryAfter > wait {
			wait = retryAfter
		}
		if healthy == 0 { // this endpoint did not give a session: try the next one
			i++
		}
		select {
		case <-stop:
			return
		case <-time.After(wait):
		}
	}
}

// session runs one control session; it returns how long it was healthy and a retry_after.
func (a *agent) session(ep string, stop <-chan struct{}) (time.Duration, time.Duration) {
	c, err := net.DialTimeout("tcp", ep, 5*time.Second)
	if err != nil {
		return 0, 0
	}
	go func() { <-stop; _ = c.Close() }()
	w := newWire(c)
	defer func() { _ = c.Close() }()
	if err := w.send(Msg{T: "hello", Agent: a.id}); err != nil {
		return 0, 0
	}
	start := time.Time{}
	for {
		m, err := w.recv()
		if err != nil {
			break
		}
		now := time.Now()
		switch m.T {
		case "welcome":
			start = now
			a.mu.Lock()
			if !a.lostAt.IsZero() {
				a.failovers = append(a.failovers, now.Sub(a.lostAt))
				a.lostAt = time.Time{}
			}
			a.node, a.epoch, a.connected = m.Node, m.Epoch, true
			a.welcomes++
			a.seq = max(a.seq, m.Seq)
			a.aseq = max(a.aseq, m.AgentSeq)
			a.mu.Unlock()
		case "rev":
			a.mu.Lock()
			a.seq = max(a.seq, m.Seq)
			a.mu.Unlock()
			if a.col != nil {
				a.col.rev(a.id, m.Seq, m.T0, now)
			}
		case "agent":
			a.mu.Lock()
			a.aseq = max(a.aseq, m.AgentSeq)
			a.mu.Unlock()
			if a.col != nil {
				a.col.agent(a.id, m.AgentSeq, m.T0, now)
			}
		case "probe":
			go func(m Msg) {
				time.Sleep(time.Duration(m.DelayMs) * time.Millisecond)
				_ = w.send(Msg{T: "probe_result", ID: m.ID})
			}(m)
		case "goodbye":
			a.lost(now)
			if m.RetryAfter > 0 {
				return healthyFor(start, now), time.Duration(m.RetryAfter) * time.Millisecond
			}
			return healthyFor(start, now), 0
		}
	}
	now := time.Now()
	a.lost(now)
	return healthyFor(start, now), 0
}

func healthyFor(start, now time.Time) time.Duration {
	if start.IsZero() {
		return 0
	}
	return max(now.Sub(start), time.Nanosecond)
}

func (a *agent) lost(now time.Time) {
	a.mu.Lock()
	if a.connected {
		a.connected = false
		a.lostAt = now
	}
	a.mu.Unlock()
}

func (a *agent) snapshot() (seq, aseq int64, node string, epoch int64, connected bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seq, a.aseq, a.node, a.epoch, a.connected
}

// collector records latencies of pushes received by agents, in milliseconds from t0.
type collector struct {
	mu      sync.Mutex
	revLat  []float64
	aLat    []float64
	aRecv   []time.Time               // when each targeted push arrived
	got     map[string]map[int64]bool // agent → revisions received by a push carrying t0
	commits map[int64]time.Time       // revision → when its commit returned
	afterC  []float64                 // latency from the commit's return, ms (negative: before)
	enabled atomic.Bool
}

func newCollector() *collector {
	c := &collector{got: map[string]map[int64]bool{}, commits: map[int64]time.Time{}}
	c.enabled.Store(true)
	return c
}

func (c *collector) rev(agent string, seq, t0 int64, now time.Time) {
	if t0 == 0 || !c.enabled.Load() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revLat = append(c.revLat, float64(now.UnixNano()-t0)/1e6)
	if c.got[agent] == nil {
		c.got[agent] = map[int64]bool{}
	}
	c.got[agent][seq] = true
	if tc, ok := c.commits[seq]; ok {
		c.afterC = append(c.afterC, float64(now.Sub(tc).Microseconds())/1000)
	}
}

func (c *collector) agent(_ string, _ int64, t0 int64, now time.Time) {
	if t0 == 0 || !c.enabled.Load() {
		return
	}
	c.mu.Lock()
	c.aLat = append(c.aLat, float64(now.UnixNano()-t0)/1e6)
	c.aRecv = append(c.aRecv, now)
	c.mu.Unlock()
}

func (c *collector) reset() {
	c.mu.Lock()
	c.revLat, c.aLat, c.afterC, c.aRecv = nil, nil, nil, nil
	c.got = map[string]map[int64]bool{}
	c.commits = map[int64]time.Time{}
	c.mu.Unlock()
}

// dist summarises samples in milliseconds.
func dist(xs []float64) string {
	if len(xs) == 0 {
		return "n=0"
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	q := func(p float64) float64 { return s[min(len(s)-1, int(math.Ceil(p*float64(len(s))))-1)] }
	return fmt.Sprintf("n=%d min=%.2f p50=%.2f p90=%.2f p99=%.2f p99.9=%.2f max=%.2f ms", len(s), s[0], q(0.5), q(0.9), q(0.99), q(0.999), s[len(s)-1])
}

func p99(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[min(len(s)-1, int(math.Ceil(0.99*float64(len(s))))-1)]
}

// report writes to stdout and to results/<name>.txt.
type report struct {
	w io.Writer
	f *os.File
}

func newReport(name string) (*report, error) {
	if err := os.MkdirAll(resultsDir(), 0o750); err != nil {
		return nil, err
	}
	f, err := os.Create(filepath.Join(resultsDir(), name+".txt"))
	if err != nil {
		return nil, err
	}
	return &report{w: io.MultiWriter(os.Stdout, f), f: f}, nil
}

func (r *report) printf(format string, a ...any) {
	_, _ = fmt.Fprintf(r.w, "%s "+format+"\n", append([]any{time.Now().UTC().Format("15:04:05.000")}, a...)...)
}

func (r *report) close() { _ = r.f.Close() }

// verdict prints PASS or FAIL for a criterion and records failures.
func (r *report) verdict(ok bool, format string, a ...any) bool {
	v := "PASS"
	if !ok {
		v = "FAIL"
	}
	r.printf("%s "+format, append([]any{v}, a...)...)
	return ok
}

func logDir() string {
	d := filepath.Join(resultsDir(), "logs")
	_ = os.MkdirAll(d, 0o750)
	return d
}

// resultsDir is where raw results go: $S9_RESULTS, else results/ under the working directory.
func resultsDir() string {
	if d := os.Getenv("S9_RESULTS"); d != "" {
		return d
	}
	return "results"
}
