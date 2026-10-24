// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
)

// fastCheck is a tcp health check every 20 ms, unhealthy after 3 failures, healthy after 2 passes.
func fastCheck() *connector.HealthCheck {
	return &connector.HealthCheck{Interval: 20 * time.Millisecond, Timeout: time.Second, Unhealthy: 3, Healthy: 2}
}

// readyPriorities waits until the route's last report is ready at exactly want.
func (e *targetsEnv) readyPriorities(t *testing.T, route string, want ...uint32) {
	t.Helper()
	defer func() {
		if t.Failed() {
			e.mu.Lock()
			t.Logf("reports: %v", e.health)
			e.mu.Unlock()
		}
	}()
	eventually(t, "the route's ready priorities never became "+strconv.Quote(slicesString(want)), func() bool {
		h := e.lastOf(route)
		return h.GetReady() && slices.Equal(h.GetReadyPriorities(), want)
	})
}

// lastOf is the route's last health report.
func (e *targetsEnv) lastOf(route string) *tunnelv1.RouteHealth {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.health) - 1; i >= 0; i-- {
		if e.health[i].GetRouteId() == route {
			return e.health[i]
		}
	}
	return nil
}

func slicesString(v []uint32) string {
	s := ""
	for _, x := range v {
		s += strconv.Itoa(int(x)) + " "
	}
	return s
}

// TestHealthCheck_ObeysLocalPolicy (docs/12, security regression tests): a health check dials as
// traffic does: a target the connector-local policy blocks, by its address, by the name it
// resolves to, or by the port the check names, and a target that deny_targets refuses, by address
// or by a name resolving into it on an allowed port, fail without being dialled, so a check never
// reaches what traffic may not; such a target counts as blocked by the policy, with the policy's
// detail, not as unhealthy. The targets the policy allows are checked and stay ready.
func TestHealthCheck_ObeysLocalPolicy(t *testing.T) {
	allowed := startService(t, echoService)
	blocked := startService(t, echoService)
	denied := startService(t, echoService)
	// 127.0.0.0/8 is allowed on the allowed and the denied service's ports, but deny_targets
	// refuses 127.0.0.1 and ::1 on the denied one, which wins (D84).
	dp := strconv.Itoa(int(denied.port()))
	e := newTargets(policyOf(t, "allow_targets:\n  - cidr: 127.0.0.0/8\n    ports: ["+strconv.Itoa(int(allowed.port()))+", "+dp+"]\n"+
		"deny_targets: [\"127.0.0.1/32:"+dp+"\", \"[::1]:"+dp+"\"]\n"))
	t.Cleanup(e.Close)
	byAddress, byName, ok := target("127.0.0.1", blocked.port()), target("localhost", blocked.port()), target("127.0.0.1", allowed.port())
	deniedAddr, deniedName := target("127.0.0.1", denied.port()), target("localhost", denied.port())
	byAddress.Priority, byName.Priority, deniedAddr.Priority, deniedName.Priority, ok.Priority = 0, 1, 3, 4, 2
	e.Set([]connector.Route{
		{ID: "rt_1", Targets: []connector.Target{byAddress, byName, deniedAddr, deniedName, ok}, Check: fastCheck()},
		{ID: "rt_port", Targets: []connector.Target{ok}, Check: &connector.HealthCheck{Port: blocked.port(), Interval: 20 * time.Millisecond,
			Timeout: time.Second, Unhealthy: 3, Healthy: 2}},
		{ID: "rt_denied", Targets: []connector.Target{deniedName}, Check: fastCheck()},
	})
	// The names pass the policy until they resolve; their checks fail without a connection.
	e.readyPriorities(t, "rt_1", 2)
	blockedBy := func(route string) func() bool {
		return func() bool {
			h := e.lastOf(route)
			return !h.GetReady() && h.GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY && h.GetDetail() != ""
		}
	}
	eventually(t, "a check of a port the policy blocks did not count as blocked", blockedBy("rt_port"))
	eventually(t, "a name resolving into deny_targets did not count as blocked", blockedBy("rt_denied"))
	if d := e.lastOf("rt_port").GetDetail(); !strings.Contains(d, strconv.Itoa(int(blocked.port()))) {
		t.Errorf("the blocked check port's detail %q", d)
	}
	time.Sleep(100 * time.Millisecond) // more rounds
	if n := blocked.conns.Load() + denied.conns.Load(); n != 0 {
		t.Fatalf("checks dialled blocked targets %d times", n)
	}
	if allowed.conns.Load() == 0 {
		t.Fatal("the allowed target was never checked")
	}
}

// webTarget is a target serving HTTP that answers 503 while down is set and counts its
// connections.
func webTarget(t *testing.T, id string, down *atomic.Bool) (connector.Target, *atomic.Int64) {
	t.Helper()
	var conns atomic.Int64
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down != nil && down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}), ConnState: func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return connector.Target{ID: id, Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}, &conns //nolint:gosec // G115: a port
}

// TestHealthCheck_PrioritiesAndStreams: a target that fails its checks leaves its priority's
// readiness once the unhealthy threshold is reached, and comes back after the healthy threshold;
// a stream meanwhile goes to the healthy priority; when every target fails, the route is not ready
// with the reason targets_unhealthy; a route without a check names no priorities.
func TestHealthCheck_PrioritiesAndStreams(t *testing.T) {
	var down atomic.Bool
	flaky, _ := webTarget(t, "tg_flaky", &down)
	steady, steadyConns := webTarget(t, "tg_steady", nil)
	steady.Priority = 1
	only, _ := webTarget(t, "tg_only", &down)
	e := newTargets(allowLoopback(t, flaky.Port, steady.Port, only.Port))
	t.Cleanup(e.Close)
	check := fastCheck()
	check.HTTP, check.Path, check.StatusMin, check.StatusMax = true, "/", 200, 399
	e.Set([]connector.Route{
		{ID: "rt_web", Targets: []connector.Target{flaky, steady}, Check: check},
		{ID: "rt_only", Targets: []connector.Target{only}, Check: check},
		{ID: "rt_plain", Targets: []connector.Target{flaky}},
	})
	e.readyPriorities(t, "rt_web", 0, 1)

	down.Store(true)
	e.readyPriorities(t, "rt_web", 1)
	before := steadyConns.Load()
	code, gw := e.handle(t, tcpOpen("rt_web"))
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("a stream while priority 0 is unhealthy: %s", code)
	}
	_ = gw.Close()
	eventually(t, "the stream did not go to the healthy priority", func() bool { return steadyConns.Load() > before })
	eventually(t, "a route whose only target answers 503 stayed ready", func() bool {
		h := e.lastOf("rt_only")
		return !h.GetReady() && h.GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_TARGETS_UNHEALTHY
	})

	down.Store(false)
	e.readyPriorities(t, "rt_web", 0, 1)
	e.readyPriorities(t, "rt_only", 0)
	if h := e.lastOf("rt_plain"); !h.GetReady() || len(h.GetReadyPriorities()) != 0 {
		t.Errorf("a route without a check: %v", h)
	}
}

// TestHealthCheck_UDPFlows: a udp route's flows pass over a target its tcp check finds unhealthy,
// as streams do, and use it again only as the last chance once every target is unhealthy.
func TestHealthCheck_UDPFlows(t *testing.T) {
	svc := startUDPService(t)
	check, err := net.Listen("tcp", "127.0.0.1:0") // the check port, on 127.0.0.1 alone
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := check.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	checkPort := uint16(check.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	sick, good := target("127.0.0.2", svc.port()), target("127.0.0.1", svc.port())
	good.Priority = 1
	e := newTargets(allowLoopback(t, svc.port(), checkPort))
	t.Cleanup(e.Close)
	c := fastCheck()
	c.Port = checkPort
	e.Set([]connector.Route{{ID: "rt_udp", UDP: true, Targets: []connector.Target{sick, good}, Check: c}})
	e.readyPriorities(t, "rt_udp", 1)
	for range 5 {
		res, gw := e.handleResult(t, udpOpen("rt_udp"))
		_ = gw.Close()
		if res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR || res.GetTargetId() != good.ID {
			t.Fatalf("a flow while %s is unhealthy: %v", sick.ID, res)
		}
	}
	_ = check.Close()
	eventually(t, "the route stayed ready with every target unhealthy", func() bool { return !e.lastOf("rt_udp").GetReady() })
	res, gw := e.handleResult(t, udpOpen("rt_udp"))
	_ = gw.Close()
	if res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR || res.GetTargetId() != sick.ID {
		t.Fatalf("a flow with every target unhealthy: %v, want the best priority as the last chance", res)
	}
}
