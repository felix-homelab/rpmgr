// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
)

// ctlTarget is a target serving HTTP, whose answers the test controls: 503 while down is set, no
// answer at all while hang is set. It counts the connections it takes, checks and streams alike.
type ctlTarget struct {
	connector.Target
	down, hang atomic.Bool
	conns      atomic.Int64
}

func newCtlTarget(t *testing.T, id string) *ctlTarget {
	t.Helper()
	c := &ctlTarget{}
	stop := make(chan struct{})
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for c.hang.Load() {
			select {
			case <-stop:
				return
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
		if c.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}), ConnState: func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			c.conns.Add(1)
		}
	}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { close(stop); _ = srv.Close() })
	c.Target = connector.Target{ID: id, Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)} //nolint:gosec // G115: a port
	return c
}

// keepCheck is an http check that treats one result as decisive and runs again only after an hour,
// so that a test sees the first round alone.
func keepCheck(path string) *connector.HealthCheck {
	return &connector.HealthCheck{HTTP: true, Path: path, StatusMin: 200, StatusMax: 399, Interval: time.Hour, Timeout: 3 * time.Second,
		Unhealthy: 1, Healthy: 1}
}

// unknown is whether Status lists the target as not decided yet.
func (e *targetsEnv) unknown(id string) bool {
	return e.statusOf(id).GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_TARGET_UNKNOWN
}

func (e *targetsEnv) unhealthy(id string) bool {
	return e.statusOf(id).GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_TARGETS_UNHEALTHY
}

// healthy waits until the target's checks passed: not listed in Status, and its change, ready,
// reported.
func (e *targetsEnv) healthy(t *testing.T, id string) {
	t.Helper()
	eventually(t, id+" never became healthy", func() bool {
		last := e.lastTarget(id)
		return e.statusOf(id) == nil && last != nil && last.GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_UNSPECIFIED
	})
}

// streams opens n streams to the route, each of which must succeed.
func (e *targetsEnv) streams(t *testing.T, route string, n int) {
	t.Helper()
	for range n {
		code, gw := e.handle(t, tcpOpen(route))
		if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("a stream to %s: %s", route, code)
		}
		_ = gw.Close()
	}
}

// settle gives a check that was wrongly started time to dial.
func settle() { time.Sleep(150 * time.Millisecond) }

// TestHealthKeep_UnrelatedChangeKeepsStates (D156, rule 1): a route change that leaves a target's
// address and the check as they were keeps the target's state: an unhealthy target stays unhealthy
// and out of selection, and no new check runs.
func TestHealthKeep_UnrelatedChangeKeepsStates(t *testing.T) {
	bad, good := newCtlTarget(t, "tg_bad"), newCtlTarget(t, "tg_good")
	bad.down.Store(true)
	e := newTargets(allowLoopback(t, bad.Port, good.Port))
	t.Cleanup(e.Close)
	check := keepCheck("/")
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{bad.Target, good.Target}, Check: check}})
	eventually(t, "the target never became unhealthy", func() bool { return e.unhealthy(bad.ID) })
	e.healthy(t, good.ID)
	checks := bad.conns.Load()

	// The weight and priority of the other target, and a copy of the check, are not what is checked.
	heavier := good.Target
	heavier.Weight = 5
	same := *check
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{bad.Target, heavier}, Check: &same}})
	if !e.unhealthy(bad.ID) {
		t.Fatalf("an unrelated change reset the unhealthy target: %v", e.statusOf(bad.ID))
	}
	e.readyPriorities(t, "rt_a", 0)
	e.streams(t, "rt_a", 20)
	settle()
	if n := bad.conns.Load(); n != checks {
		t.Fatalf("the unhealthy target took %d connections after the change, want none", n-checks)
	}
	if !e.unhealthy(bad.ID) || e.statusOf(good.ID) != nil {
		t.Fatalf("states after the change: bad %v, good %v", e.statusOf(bad.ID), e.statusOf(good.ID))
	}
}

// TestHealthKeep_NewTargetStartsUnknown (D156, rule 3): a target added to a route is unknown, which
// Status reports, and gets no traffic while another target of its priority passed its check; it is
// healthy after its first pass, and then takes traffic.
func TestHealthKeep_NewTargetStartsUnknown(t *testing.T) {
	old, fresh := newCtlTarget(t, "tg_old"), newCtlTarget(t, "tg_new")
	fresh.hang.Store(true)
	e := newTargets(allowLoopback(t, old.Port, fresh.Port))
	t.Cleanup(e.Close)
	check := keepCheck("/")
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{old.Target}, Check: check}})
	e.healthy(t, old.ID)

	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{old.Target, fresh.Target}, Check: check}})
	if !e.unknown(fresh.ID) {
		t.Fatalf("a new target's status: %v, want unknown", e.statusOf(fresh.ID))
	}
	eventually(t, "the new target was never checked", func() bool { return fresh.conns.Load() == 1 })
	e.healthy(t, old.ID)
	e.streams(t, "rt_a", 20)
	if n := fresh.conns.Load(); n != 1 {
		t.Fatalf("the unknown target took %d connections besides its check while another was healthy", n-1)
	}
	if !e.lastOf("rt_a").GetReady() {
		t.Fatalf("a route with an unknown target: %v", e.lastOf("rt_a"))
	}

	fresh.hang.Store(false) // its check passes
	e.healthy(t, fresh.ID)
	before := fresh.conns.Load()
	e.streams(t, "rt_a", 60)
	if fresh.conns.Load() == before {
		t.Fatal("a healthy target never took traffic")
	}
}

// TestHealthKeep_ReAddedTargetStartsUnknown (D156): a target that was healthy, removed and added
// again is unknown, not healthy.
func TestHealthKeep_ReAddedTargetStartsUnknown(t *testing.T) {
	a, b := newCtlTarget(t, "tg_a"), newCtlTarget(t, "tg_b")
	e := newTargets(allowLoopback(t, a.Port, b.Port))
	t.Cleanup(e.Close)
	check := keepCheck("/")
	both := []connector.Target{a.Target, b.Target}
	e.Set([]connector.Route{{ID: "rt_a", Targets: both, Check: check}})
	e.healthy(t, a.ID)
	e.healthy(t, b.ID)

	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{a.Target}, Check: check}})
	if e.statusOf(b.ID) != nil {
		t.Fatalf("a removed target in Status: %v", e.statusOf(b.ID))
	}
	b.hang.Store(true)
	checks := b.conns.Load()
	e.Set([]connector.Route{{ID: "rt_a", Targets: both, Check: check}})
	if !e.unknown(b.ID) {
		t.Fatalf("a re-added target: %v, want unknown", e.statusOf(b.ID))
	}
	eventually(t, "the re-added target was never checked", func() bool { return b.conns.Load() == checks+1 })
	e.healthy(t, a.ID)
	before := b.conns.Load()
	e.streams(t, "rt_a", 20)
	if n := b.conns.Load(); n != before {
		t.Fatalf("a re-added target took %d connections while unknown and another was healthy", n-before)
	}
}

// TestHealthKeep_ChangedAddressStartsUnknown: a target whose address changed is another target.
func TestHealthKeep_ChangedAddressStartsUnknown(t *testing.T) {
	a, moved := newCtlTarget(t, "tg_a"), newCtlTarget(t, "tg_a")
	moved.hang.Store(true)
	e := newTargets(allowLoopback(t, a.Port, moved.Port))
	t.Cleanup(e.Close)
	check := keepCheck("/")
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{a.Target}, Check: check}})
	e.healthy(t, a.ID)
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{moved.Target}, Check: check}})
	if !e.unknown(a.ID) {
		t.Fatalf("a target at a new address: %v, want unknown", e.statusOf(a.ID))
	}
}

// TestHealthKeep_AllUnknownStillServes (D156, rule 3): while no target of the route has passed a
// check, the route is ready and its streams reach its targets.
func TestHealthKeep_AllUnknownStillServes(t *testing.T) {
	a, b := newCtlTarget(t, "tg_a"), newCtlTarget(t, "tg_b")
	a.hang.Store(true)
	b.hang.Store(true)
	e := newTargets(allowLoopback(t, a.Port, b.Port))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{a.Target, b.Target}, Check: keepCheck("/")}})
	if !e.unknown(a.ID) || !e.unknown(b.ID) {
		t.Fatalf("targets before a check: %v, %v", e.statusOf(a.ID), e.statusOf(b.ID))
	}
	e.readyPriorities(t, "rt_a", 0)
	eventually(t, "the checks never dialled", func() bool { return a.conns.Load() == 1 && b.conns.Load() == 1 })
	e.streams(t, "rt_a", 40)
	if a.conns.Load() == 1 || b.conns.Load() == 1 {
		t.Fatalf("streams reached a %d, b %d connections, want both used while all are unknown", a.conns.Load(), b.conns.Load())
	}
}

// TestHealthKeep_UnknownAmongUnhealthy: an unknown target is used while the others of its priority
// are unhealthy, and not a priority later than a healthy one is passed over for it.
func TestHealthKeep_UnknownAmongUnhealthy(t *testing.T) {
	bad, fresh := newCtlTarget(t, "tg_bad"), newCtlTarget(t, "tg_new")
	bad.down.Store(true)
	fresh.hang.Store(true)
	e := newTargets(allowLoopback(t, bad.Port, fresh.Port))
	t.Cleanup(e.Close)
	check := keepCheck("/")
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{bad.Target}, Check: check}})
	eventually(t, "never unhealthy", func() bool { return e.unhealthy(bad.ID) })
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{bad.Target, fresh.Target}, Check: check}})
	eventually(t, "the new target was never checked", func() bool { return fresh.conns.Load() == 1 })
	before := bad.conns.Load()
	e.streams(t, "rt_a", 20)
	if bad.conns.Load() != before || fresh.conns.Load() == 1 {
		t.Fatalf("streams: unhealthy took %d, unknown %d connections more; want only the unknown one", bad.conns.Load()-before, fresh.conns.Load()-1)
	}
}

// TestHealthKeep_ChangedCheckKeepsStateAndRunsAtOnce (D156, rule 2): a changed check keeps a
// target's state until its first result, which comes at once, not after one interval.
func TestHealthKeep_ChangedCheckKeepsStateAndRunsAtOnce(t *testing.T) {
	bad, good := newCtlTarget(t, "tg_bad"), newCtlTarget(t, "tg_good")
	bad.down.Store(true)
	e := newTargets(allowLoopback(t, bad.Port, good.Port))
	t.Cleanup(e.Close)
	targets := []connector.Target{bad.Target, good.Target}
	e.Set([]connector.Route{{ID: "rt_a", Targets: targets, Check: keepCheck("/")}})
	eventually(t, "never unhealthy", func() bool { return e.unhealthy(bad.ID) })
	e.healthy(t, good.ID)

	// The new check's first result is not in yet: the target stays unhealthy, not healthy as before.
	bad.hang.Store(true)
	checks := bad.conns.Load()
	e.Set([]connector.Route{{ID: "rt_a", Targets: targets, Check: keepCheck("/v2")}})
	eventually(t, "the changed check did not run at once", func() bool { return bad.conns.Load() == checks+1 })
	if !e.unhealthy(bad.ID) || e.statusOf(good.ID) != nil {
		t.Fatalf("a changed check changed states: bad %v, good %v", e.statusOf(bad.ID), e.statusOf(good.ID))
	}
	e.readyPriorities(t, "rt_a", 0)
	e.streams(t, "rt_a", 20)

	// Its first result decides, an hour before the second round.
	bad.down.Store(false)
	bad.hang.Store(false)
	e.healthy(t, bad.ID)
}

// TestHealthKeep_ChangedCheckOfPassingTarget: a changed check does not make a failing target look
// healthy, and its first failure makes it unhealthy at once where the threshold is one.
func TestHealthKeep_ChangedCheckFirstFailure(t *testing.T) {
	a := newCtlTarget(t, "tg_a")
	e := newTargets(allowLoopback(t, a.Port))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{a.Target}, Check: keepCheck("/")}})
	e.healthy(t, a.ID)
	a.down.Store(true)
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{a.Target}, Check: keepCheck("/v2")}})
	eventually(t, "the changed check's failure was not found at once", func() bool { return e.unhealthy(a.ID) })
}

// TestHealthKeep_RemovedRouteForgets: a route that is removed and added again starts its targets
// unknown, and a route that loses its check keeps nothing.
func TestHealthKeep_RemovedRouteForgets(t *testing.T) {
	a := newCtlTarget(t, "tg_a")
	e := newTargets(allowLoopback(t, a.Port))
	t.Cleanup(e.Close)
	route := connector.Route{ID: "rt_a", Targets: []connector.Target{a.Target}, Check: keepCheck("/")}
	e.Set([]connector.Route{route})
	e.healthy(t, a.ID)
	route.Check = nil
	e.Set([]connector.Route{route})
	if st := e.statusOf(a.ID); st != nil {
		t.Fatalf("a route without a check lists a target: %v", st)
	}
	a.hang.Store(true)
	route.Check = keepCheck("/")
	e.Set([]connector.Route{route})
	if !e.unknown(a.ID) {
		t.Fatalf("a check added to a route: %v, want unknown", e.statusOf(a.ID))
	}
}
