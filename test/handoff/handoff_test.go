// SPDX-License-Identifier: Apache-2.0

//go:build handoff

// Package handoff upgrades a lone gateway and an all-in-one under load, from the previous build
// to this tree's, with the socket hand-off (docs/03-connections.md, "Restarts with socket
// hand-off"; docs/12-testing-and-quality.md; slices 17.4 and 17.8). Run with check-handoff.sh;
// needs Docker. HANDOFF_FROM names the previous build as a git revision, default HEAD~1; the
// processes are started by the test and signalled with SIGUSR2, as `rpmgr handoff` does under
// systemd (D155): the unit paths are covered by the install script and updater tests.
package handoff

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestHandoff starts the topology on the previous build and hands the gateway, the all-in-one and
// last the gateway's absence over, under load. The subtests share the lab and run in order.
func TestHandoff(t *testing.T) {
	l := newLab(t)
	l.up()
	for _, c := range []struct {
		name string
		f    func(*testing.T)
	}{{"lone gateway", l.gatewayUpgrade}, {"lone gateway, a connector pinned to QUIC", l.gatewayPinned}, {"all-in-one", l.allInOneUpgrade}, {"connector retries with backoff", l.backoff}} {
		t.Run(c.name, func(t *testing.T) {
			l.t = t // the helpers report to the running subtest
			c.f(t)
		})
	}
}

// probeOut is `e2eclient probe`'s line.
type probeOut struct {
	TCPOK, TCPFail, HTTPOK, HTTPFail, UDPOK int
	UDPGaps                                 []struct {
		AtMS  int64 `json:"at_ms"`
		GapMS int64 `json:"gap_ms"`
	}
	Errors   []string
	FailAtMS []int64
}

// scenario is one role under hand-off: the routes the load uses and where to reach them.
type scenario struct {
	role, bin      string
	admin          int
	tcp, udp       string   // the routes' addresses in the lab
	httpAddr, host string   // the address that serves the HTTP route, and its host name
	held           []string // TCP routes with a connection held open across the hand-off
}

const (
	probeFor = 30 * time.Second
	heldFor  = 14 * time.Second
)

func (l *lab) pid(role string) int {
	l.t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(l.exec("lab", "cat", "/run/rpmgr/"+role+"/handoff.pid")))
	if err != nil {
		l.t.Fatalf("pid of %s: %v", role, err)
	}
	return n
}

func (l *lab) alive(pid int) bool {
	_, err := l.try("lab", "kill", "-0", strconv.Itoa(pid))
	return err == nil
}

func (l *lab) eventually(d time.Duration, what string, f func() error) {
	l.t.Helper()
	var err error
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		if err = f(); err == nil {
			return
		}
	}
	logs, _ := l.try("lab", "sh", "-c", "ps -eo pid,ppid,args | grep '[r]pmgr'; tail -n 25 /var/lib/gw/gateway.yaml.log /var/lib/aio/all-in-one.yaml.log | cut -c1-280")
	l.t.Fatalf("%s: %v\n%s", what, err, logs)
}

func (l *lab) client(node string, args ...string) error {
	_, err := l.try(node, append([]string{"e2eclient"}, args...)...)
	return err
}

// answers waits until the routes of s answer on every protocol.
func (l *lab) answers(s scenario) {
	l.t.Helper()
	l.eventually(60*time.Second, "tcp route "+s.tcp, func() error { return l.client("lab", "check", "-addr", s.tcp) })
	l.eventually(60*time.Second, "udp route "+s.udp, func() error { return l.client("lab", "udp", "-addr", s.udp) })
	l.eventually(60*time.Second, "http route "+s.host, func() error {
		return l.client("lab", "http", "-addr", s.httpAddr, "-url", "https://"+s.host+"/")
	})
}

func (l *lab) metrics(node string, port int) string {
	l.t.Helper()
	return l.exec(node, "e2eclient", "scrape", "-url", fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
}

// handoff replaces the role's binary by this tree's build, as the updater does, signals the
// process and waits for the outcome; it returns the old and the new process.
func (l *lab) handoff(s scenario) (oldPID, newPID int) {
	l.t.Helper()
	oldPID = l.pid(s.role)
	l.sh("lab", fmt.Sprintf("cp /opt/ctl/rpmgr %[1]s.new && mv %[1]s.new %[1]s", s.bin))
	l.exec("lab", "kill", "-USR2", strconv.Itoa(oldPID))
	var out string
	l.eventually(100*time.Second, "the outcome of the hand-off", func() error {
		out = l.exec("lab", "cat", "/run/rpmgr/"+s.role+"/handoff.json")
		if strings.Contains(out, `"running"`) {
			return fmt.Errorf("still running: %s", out)
		}
		return nil
	})
	if !strings.Contains(out, `"ok"`) {
		l.t.Fatalf("the hand-off failed: %s\n%s", out, l.sh("lab", "tail -n 20 "+s.cfg()+".log"))
	}
	newPID = l.pid(s.role)
	if newPID == oldPID {
		l.t.Fatalf("the process is still %d after the hand-off", oldPID)
	}
	return oldPID, newPID
}

func (s scenario) cfg() string {
	if s.role == "gateway" {
		return "/var/lib/gw/gateway.yaml"
	}
	return "/var/lib/aio/all-in-one.yaml"
}

// load runs the traffic of the scenario while hand runs, and returns its results. The held
// connections must live through the hand-off.
func (l *lab) load(s scenario, hand func(start time.Time)) (probeOut, map[string]probeOut) {
	t := l.t
	start := time.Now()
	var wg sync.WaitGroup
	held := make([]error, len(s.held))
	for i, a := range s.held {
		wg.Go(func() {
			_, held[i] = l.try("lab", "e2eclient", "hold", "-addr", a, "-duration", heldFor.String())
		})
	}
	var main probeOut
	var perr error
	extra := map[string]probeOut{}
	var mu sync.Mutex
	probe := func(args ...string) (probeOut, error) {
		out, err := l.try("lab", append([]string{"e2eclient", "probe", "-duration", probeFor.String()}, args...)...)
		var p probeOut
		if err != nil {
			return p, err
		}
		return p, json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &p)
	}
	wg.Go(func() {
		main, perr = probe("-tcp", s.tcp, "-udpaddr", s.udp, "-httpaddr", s.httpAddr, "-url", "https://"+s.host+"/")
	})
	for _, a := range s.held[min(1, len(s.held)):] { // the routes pinned to a transport: probed, not judged
		wg.Go(func() {
			p, err := probe("-tcp", a)
			if err != nil {
				t.Errorf("probe of %s: %v", a, err)
			}
			mu.Lock()
			extra[a] = p
			mu.Unlock()
		})
	}
	time.Sleep(4 * time.Second)
	done := make(chan struct{})
	go func() { // a failed check ends this goroutine, not the wait for the load below
		defer close(done)
		hand(start)
	}()
	<-done
	wg.Wait()
	if perr != nil {
		t.Fatalf("the probe: %v", perr)
	}
	for i, err := range held {
		if err != nil {
			t.Errorf("the connection held through %s across the hand-off: %v", s.held[i], err)
		}
	}
	return main, extra
}

// judge checks a probe's result; without strict it only reports it.
func (l *lab) judge(s scenario, p probeOut, exitAt time.Duration, strict bool) {
	t := l.t
	t.Logf("failures started at %v ms", p.FailAtMS)
	t.Logf("%s: tcp %d ok %d failed, http %d ok %d failed, udp %d answers, silences %+v, first errors %v",
		s.role, p.TCPOK, p.TCPFail, p.HTTPOK, p.HTTPFail, p.UDPOK, p.UDPGaps, p.Errors)
	l.refused(s, p)
	if !strict {
		return
	}
	if p.TCPOK < 200 || p.HTTPOK < 200 {
		t.Errorf("too little load went through: tcp %d, http %d", p.TCPOK, p.HTTPOK)
	}
	// UDP answers while the old process lives; an open flow may start again once it exits.
	for _, g := range p.UDPGaps {
		if time.Duration(g.AtMS)*time.Millisecond < exitAt-2*time.Second {
			t.Errorf("udp: %d ms without an answer at %d ms, before the old process exited at %v", g.GapMS, g.AtMS, exitAt)
		}
		if g.GapMS > 15000 {
			t.Errorf("udp: %d ms without an answer at %d ms, the flow did not start again", g.GapMS, g.AtMS)
		}
	}
	if p.UDPOK < 100 {
		t.Errorf("udp: %d answers", p.UDPOK)
	}
}

// refused judges the connections that failed: D127's exit check is none, so any refused or reset
// connection fails the test.
func (l *lab) refused(s scenario, p probeOut) {
	if p.TCPFail != 0 || p.HTTPFail != 0 {
		l.t.Errorf("a refused or reset connection of %s under load: tcp %d, http %d: %v", s.role, p.TCPFail, p.HTTPFail, p.Errors)
	}
}

// awaitExit waits until the old process has exited and returns when, since start (the load's).
func (l *lab) awaitExit(old int, start time.Time) time.Duration {
	l.t.Helper()
	l.eventually(80*time.Second, "the old process to exit", func() error {
		if l.alive(old) {
			return fmt.Errorf("process %d serves on", old)
		}
		return nil
	})
	return time.Since(start)
}

var (
	sessionRE = regexp.MustCompile(`(?m)^rpmgr_gateway_sessions\{([^}]*)\} (\d+)`)
	labelRE   = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// sessions returns the data sessions of generation gen per transport.
func sessions(metrics string, gen int) map[string]int {
	out := map[string]int{}
	for _, m := range sessionRE.FindAllStringSubmatch(metrics, -1) {
		labels := map[string]string{}
		for _, kv := range labelRE.FindAllStringSubmatch(m[1], -1) {
			labels[kv[1]] = kv[2]
		}
		if labels["generation"] == strconv.Itoa(gen) {
			out[labels["transport"]], _ = strconv.Atoi(m[2])
		}
	}
	return out
}

func (l *lab) gatewayScenario(pinned bool) scenario {
	s := scenario{role: "gateway", bin: "/opt/gw/rpmgr", admin: 7382, tcp: "127.0.0.1:20001", udp: "127.0.0.1:20002",
		httpAddr: fmt.Sprintf("127.0.0.1:%d", gwPort), host: "app.e2e.test", held: []string{"127.0.0.1:20001"}}
	if pinned {
		s.held = append(s.held, "127.0.0.1:20003")
	}
	return s
}

// gatewayUpgrade hands the lone gateway over from the previous build to this one, with connectors
// on auto only: no refused or reset connection, UDP answering, and the connectors on TCP at
// first and back on QUIC at their re-probe.
func (l *lab) gatewayUpgrade(t *testing.T) {
	l.gateway(t, l.gatewayScenario(false), 2)
}

// gatewayPinned hands the gateway over again with a connector pinned to QUIC, which cannot join
// the new process while the old one holds the UDP port: it reconnects once the old one exits.
func (l *lab) gatewayPinned(t *testing.T) {
	target := fmt.Sprintf("%s:%d", l.ip, 7007)
	l.seed("/var/lib/ctl/controller.yaml", nil, "route", "--name", "tcp-quic", "--group", "solo", "--port", "20003", "--target", target,
		"--transport", "quic", "--connector", "c2")
	s := l.gatewayScenario(true)
	l.eventually(60*time.Second, "the pinned route", func() error { return l.client("lab", "check", "-addr", s.held[1]) })
	l.gateway(t, s, 3)
}

// gateway runs one hand-off of the gateway under load; gen is the generation of the new process.
func (l *lab) gateway(t *testing.T, s scenario, gen int) {
	pinned := len(s.held) > 1
	l.answers(s)
	var oldPID int
	var exitAt time.Duration
	var early map[string]int
	p, extra := l.load(s, func(start time.Time) {
		var newPID int
		oldPID, newPID = l.handoff(s)
		t.Logf("hand-off from %d to %d, outcome ok %v after the start of the load", oldPID, newPID, time.Since(start))
		if !l.alive(oldPID) {
			t.Errorf("the old process %d ended with the hand-off: it must drain", oldPID)
		}
		// Connectors on auto reach the new process over TCP while the old one holds the UDP port;
		// the one pinned to QUIC has no session with it yet.
		l.eventually(40*time.Second, "the auto connector's TCP session with the new process", func() error {
			m := l.metrics("lab", s.admin)
			early = sessions(m, gen)
			if early["h2"] < 1 || !strings.Contains(l.metrics("c1", 7383), `transport="h2"`) {
				return fmt.Errorf("sessions of generation %d: %v\n%s", gen, early, grep(m, "rpmgr_gateway_sessions"))
			}
			return nil
		})
		exitAt = l.awaitExit(oldPID, start)
		t.Logf("the old process exited %v after the start of the load", exitAt)
	})
	t.Logf("sessions of generation %d just after the hand-off: %v", gen, early)
	if early["quic"] != 0 {
		t.Errorf("the new process has %d QUIC sessions while the old one holds the UDP port", early["quic"])
	}
	l.judge(s, p, exitAt, !pinned)
	for a, e := range extra {
		t.Logf("route %s, pinned to QUIC, probed: %d ok, %d failed, first errors %v", a, e.TCPOK, e.TCPFail, e.Errors)
	}
	// Once the old process has exited the new one binds UDP: the connector pinned to QUIC
	// reconnects, and the one on auto returns to QUIC at its re-probe (shortened to 15 s).
	l.eventually(90*time.Second, "QUIC sessions of both connectors with the new process", func() error {
		got := sessions(l.metrics("lab", s.admin), gen)
		if got["quic"] < 2 {
			return fmt.Errorf("sessions of generation %d: %v", gen, got)
		}
		return nil
	})
	l.eventually(60*time.Second, "the auto connector off TCP", func() error {
		if m := l.metrics("c1", 7383); strings.Contains(m, `transport="h2"`) {
			return fmt.Errorf("still on h2")
		}
		return nil
	})
	if pinned {
		l.eventually(60*time.Second, "the pinned route", func() error { return l.client("lab", "check", "-addr", s.held[1]) })
	}
	l.answers(s)
}

func (l *lab) allInOneUpgrade(t *testing.T) {
	s := scenario{role: "all-in-one", bin: "/opt/aio/rpmgr", admin: 7392, tcp: "127.0.0.1:21001", udp: "127.0.0.1:21002",
		httpAddr: fmt.Sprintf("127.0.0.1:%d", aioPort), host: "app2.e2e.test", held: []string{"127.0.0.1:21001"}}
	l.answers(s)
	var oldPID int
	p, _ := l.load(s, func(start time.Time) {
		var newPID int
		oldPID, newPID = l.handoff(s)
		t.Logf("hand-off from %d to %d, outcome ok %v after the start of the load", oldPID, newPID, time.Since(start))
		l.ready("lab", s.admin)
	})
	// The old all-in-one has no hand-off drain of its own to set (its default is 10 min) and serves
	// its flows until then, so the load sees no silence at all. Ending it moves the UDP flows.
	l.judge(s, p, probeFor, true)
	l.exec("lab", "kill", "-KILL", strconv.Itoa(oldPID))
	if m := l.metrics("lab", s.admin); !strings.Contains(m, `generation="2"`) {
		t.Errorf("the admin listener does not report generation 2")
	}
	l.answers(s)
}

func (l *lab) backoff(t *testing.T) {
	pid := l.pid("gateway")
	l.exec("lab", "kill", "-KILL", strconv.Itoa(pid))
	l.eventually(10*time.Second, "the gateway to end", func() error {
		if l.alive(pid) {
			return fmt.Errorf("alive")
		}
		return nil
	})
	out, err := l.try("lab", "e2eclient", "accepts", "-addr", fmt.Sprintf(":%d", gwPort), "-duration", "80s")
	if err != nil {
		t.Fatal(err)
	}
	var at []int64
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &at); err != nil {
		t.Fatalf("%v: %q", err, out)
	}
	t.Logf("TCP attempts of the connectors on the dead gateway, in ms: %v", at)
	// The auto connector redials: more than once, with a delay that grows (up to 15 s), not in a loop.
	if len(at) < 3 || len(at) > 25 {
		t.Fatalf("%d attempts in 80 s, want between 3 and 25", len(at))
	}
	if first, last := at[1]-at[0], at[len(at)-1]-at[len(at)-2]; last <= first {
		t.Errorf("the delay between attempts did not grow: %d ms first, %d ms last", first, last)
	}
}

func grep(text, what string) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, what) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
