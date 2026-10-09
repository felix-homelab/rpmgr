// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// chaosEvent is one disturbance of the chaos test. A soft one must not reset a connection through
// the other parts of the topology; a hard one may reset connections through the process it hits.
type chaosEvent struct {
	name string
	soft bool
	run  func(t *testing.T, r *rand.Rand)
}

// netem shapes node's traffic on all its links for d, then clears it.
func netem(t *testing.T, node string, d time.Duration, args ...string) {
	t.Helper()
	links := []string{"eth0", "eth1"}
	for _, l := range links {
		_, _ = asRoot(node, append([]string{"tc", "qdisc", "add", "dev", l, "root", "netem"}, args...)...)
	}
	time.Sleep(d)
	for _, l := range links {
		_, _ = asRoot(node, "tc", "qdisc", "del", "dev", l, "root")
	}
}

var roles = map[string]struct {
	role string
	port int
}{"ctl": {"controller", 7381}, "gw1": {"gateway", 7382}, "gw2": {"gateway", 7382}, "con1": {"connector", 7383},
	"con2": {"connector", 7383}}

func pick(r *rand.Rand, nodes ...string) string { return nodes[r.IntN(len(nodes))] }

var chaosEvents = []chaosEvent{
	{"controller database restart", true, func(t *testing.T, r *rand.Rand) {
		restart(t, "ctl", "controller", 7381, pick(r, "KILL", "TERM"))
	}},
	{"clock jump", true, func(t *testing.T, r *rand.Rand) {
		node := pick(r, "ctl", "gw1", "gw2", "con1", "con2")
		jump := time.Duration(r.IntN(10)-5) * time.Minute
		t.Logf("clock of %s %+v", node, jump)
		if err := writeFile(node, "clock-offset", jump.String()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Second)
		if err := writeFile(node, "clock-offset", "0s"); err != nil {
			t.Fatal(err)
		}
	}},
	{"latency spike", true, func(t *testing.T, r *rand.Rand) {
		netem(t, pick(r, "ctl", "gw1", "gw2", "con1", "con2"), 5*time.Second, "delay", "300ms", "100ms")
	}},
	{"packet loss and reordering", false, func(t *testing.T, r *rand.Rand) {
		netem(t, pick(r, "gw1", "gw2", "con1", "con2"), 5*time.Second, "loss", "20%", "delay", "20ms", "reorder", "25%", "50%")
	}},
	{"process killed", false, func(t *testing.T, r *rand.Rand) {
		node := pick(r, "gw1", "gw2", "con1", "con2")
		restart(t, node, roles[node].role, roles[node].port, "KILL")
	}},
}

// TestChaos runs for E2E_CHAOS_DURATION (default 6 min), nightly: a load generator keeps
// connections busy through routes on each transport and both gateways, checking every byte, while
// a seeded random sequence of chaos events (E2E_CHAOS_SEED repeats one) restarts the controller,
// kills gateways and connectors, jumps clocks through the rpmgrtest clock hook, and adds latency,
// loss and reordering. No byte may come back changed; a connection held through the other gateway
// and connector survives every soft event; afterwards every route answers again.
func TestChaos(t *testing.T) {
	fullMatrix(t)
	duration := 6 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("E2E_CHAOS_DURATION")); err == nil {
		duration = d
	}
	seed := uint64(time.Now().UnixNano())
	if s, err := strconv.ParseUint(os.Getenv("E2E_CHAOS_SEED"), 10, 64); err == nil {
		seed = s
	}
	t.Logf("chaos seed %d (E2E_CHAOS_SEED repeats it), %s", seed, duration)
	r := rand.New(rand.NewPCG(seed, seed)) //nolint:gosec // G404: a seeded, repeatable chaos schedule, not a secret

	ports := map[string]int{"auto": 22001, "quic": 22002, "h2": 22003}
	var addrs []string
	for _, tr := range transports {
		addRoute(t, "chaos-"+tr, ports[tr], tr, "con1", "con2")
		for _, gw := range []string{"gw1", "gw2"} {
			eventually(t, 60*time.Second, "chaos-"+tr+" through "+gw, func() error { return client("check", "-addr", addr(gw, ports[tr])) })
			addrs = append(addrs, addr(gw, ports[tr]))
		}
	}
	// A connection held through gw2 and con2 must survive every soft event, also one on its path.
	addRoute(t, "chaos-held", 22004, "auto", "con2")
	eventually(t, 60*time.Second, "chaos-held", func() error { return client("check", "-addr", addr("gw2", 22004)) })

	var loadOut string
	load := background(func() error {
		var err error
		loadOut, err = in("client", "e2eclient", "load", "-addrs", strings.Join(addrs, ","), "-conns", "2", "-bytes", "32768",
			"-duration", (duration + 30*time.Second).String())
		return err
	})
	for end := time.Now().Add(duration); time.Now().Before(end); {
		ev := chaosEvents[r.IntN(len(chaosEvents))]
		t.Logf("%s: %s", time.Now().Format(time.TimeOnly), ev.name)
		var held <-chan error
		if ev.soft {
			held = background(func() error {
				return client("hold", "-addr", addr("gw2", 22004), "-duration", "25s", "-every", "500ms")
			})
			time.Sleep(time.Second)
		}
		ev.run(t, r)
		if held != nil {
			if err := <-held; err != nil {
				t.Errorf("a connection across the %s: %v", ev.name, err)
			}
		}
		for node, rl := range roles {
			if err := ready(node, rl.port); err != nil {
				t.Fatalf("after the %s: %s: %v", ev.name, node, err)
			}
		}
		time.Sleep(time.Duration(5+r.IntN(10)) * time.Second)
	}
	if err := <-load; err != nil {
		t.Errorf("the load generator: %v", err)
	}
	t.Logf("load: %s", strings.TrimSpace(loadOut))
	for _, a := range append(addrs, addr("gw2", 22004)) {
		eventually(t, 90*time.Second, a+" after the chaos", func() error { return client("check", "-addr", a) })
	}
}
