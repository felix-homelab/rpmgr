// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// perSourceTarget is a target that serves at most limit connections at once from its one peer, the
// loopback address, and closes every further one at once, as a service with a per-peer throttle
// does (#1052). A connection that sends "GET" gets an answer, 503 while down is set, and ends; any
// other holds its slot until the peer closes it, as a stalled handshake does.
type perSourceTarget struct {
	*service
	active   atomic.Int64
	refused  atomic.Int64
	down     atomic.Bool
	answered atomic.Int64
}

func startPerSourceTarget(t *testing.T, limit int64) *perSourceTarget {
	t.Helper()
	p := &perSourceTarget{}
	p.service = startService(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		if p.active.Add(1) > limit {
			p.active.Add(-1)
			p.refused.Add(1)
			return
		}
		defer p.active.Add(-1)
		r := bufio.NewReader(c)
		first, err := r.Peek(3)
		if err != nil || string(first) != "GET" {
			_, _ = r.Peek(4) // holds until the peer closes
			return
		}
		_, _ = r.ReadString('\n')
		status := "200 OK"
		if p.down.Load() {
			status = "503 Service Unavailable"
		}
		_, _ = c.Write([]byte("HTTP/1.1 " + status + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		p.answered.Add(1)
	})
	return p
}

func (p *perSourceTarget) target(id string) connector.Target {
	return connector.Target{ID: id, Host: "127.0.0.1", Port: p.port()}
}

func capCheck() *connector.HealthCheck {
	c := fastCheck()
	c.Interval = 150 * time.Millisecond // a check holds a slot only briefly: rarely meets a stream
	c.HTTP, c.Path, c.StatusMin, c.StatusMax, c.Unhealthy, c.Healthy = true, "/", 200, 399, 2, 1
	return c
}

// stall opens n streams to the route, each of which must succeed, and returns them: they send
// nothing, so each holds a connection of the target.
func (e *targetsEnv) stall(t *testing.T, route string, n int) []*net.TCPConn {
	t.Helper()
	var held []*net.TCPConn
	for range n {
		for try := 0; ; try++ {
			code, gw := e.handle(t, tcpOpen(route))
			if code == tunnelv1.ResultCode_RESULT_CODE_OVERLOADED && try < 20 {
				_ = gw.Close() // a check holds the last slot for a moment
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
				t.Fatalf("a stream to %s: %s", route, code)
			}
			held = append(held, gw)
			break
		}
	}
	return held
}

// TestTargetBound_StalledStreamsKeepRouteReady is the scenario of #1052: a target allows 5
// connections per source and 5 streams stall. The bound refuses the next stream with OVERLOADED
// and never lets a check be a sixth connection; the checks the target would have refused are not
// decided, so the route stays ready, and when the streams end the target is used again.
func TestTargetBound_StalledStreamsKeepRouteReady(t *testing.T) {
	const limit = 5
	svc := startPerSourceTarget(t, limit)
	tg := svc.target("tg_grd")
	e := newTargets(allowLoopback(t, tg.Port))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_rdp", Targets: []connector.Target{tg}, Check: capCheck(), MaxTargetConns: limit}})
	e.healthy(t, tg.ID)
	e.readyPriorities(t, "rt_rdp", 0)

	held := e.stall(t, "rt_rdp", limit)
	eventually(t, "the target does not hold the 5 stalled streams", func() bool { return svc.active.Load() == limit })
	refusedBefore := svc.refused.Load()
	for range 3 {
		res, gw := e.handleResult(t, tcpOpen("rt_rdp"))
		_ = gw.Close()
		if res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
			t.Fatalf("a stream over the bound: %s, want OVERLOADED", res.GetCode())
		}
	}
	// Several rounds of checks pass (20 ms apart): none dials, so the target never sees a sixth
	// connection, and none counts as a failure.
	time.Sleep(700 * time.Millisecond)
	if r := svc.refused.Load(); r != refusedBefore {
		t.Errorf("the target refused %d connections after the bound was reached: a check or stream went over it", r-refusedBefore)
	}
	if h := e.lastOf("rt_rdp"); !h.GetReady() {
		t.Errorf("the route is not ready while only its bound is reached: %v", h)
	}
	if st := e.statusOf(tg.ID); st != nil {
		t.Errorf("a target at the bound is listed in Status: %v", st)
	}

	for _, gw := range held {
		_ = gw.Close()
	}
	eventually(t, "the slots were not given back when the streams ended", func() bool {
		code, gw := e.handle(t, tcpOpen("rt_rdp"))
		if gw != nil {
			_ = gw.Close()
		}
		return code == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR
	})
	if h := e.lastOf("rt_rdp"); !h.GetReady() {
		t.Errorf("the route after the streams ended: %v", h)
	}
}

// TestTargetBound_RefusedCheckWhileStreamsHeldIsNotDecided: a bound above what the target allows,
// so that the target refuses the check while streams hold its connections: the check fails with a
// closed connection, which decides nothing; the target stays healthy and its checks go on.
func TestTargetBound_RefusedCheckWhileStreamsHeldIsNotDecided(t *testing.T) {
	const limit = 3
	connector.SetMaxUndecided(t, 1000) // this test is about the undecided results themselves
	svc := startPerSourceTarget(t, limit)
	tg := svc.target("tg_grd")
	e := newTargets(allowLoopback(t, tg.Port))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_rdp", Targets: []connector.Target{tg}, Check: capCheck(), MaxTargetConns: 100}})
	e.healthy(t, tg.ID)

	held := e.stall(t, "rt_rdp", limit)
	eventually(t, "the target does not hold the stalled streams", func() bool { return svc.active.Load() == limit })
	t.Cleanup(func() {
		for _, gw := range held {
			_ = gw.Close()
		}
	})
	eventually(t, "the checks were not refused by the target: active "+strconv.Itoa(int(svc.active.Load()))+" answered "+strconv.Itoa(int(svc.answered.Load())), func() bool { return svc.refused.Load() >= 3 })
	time.Sleep(700 * time.Millisecond) // more than the unhealthy threshold of rounds
	if e.unhealthy(tg.ID) || !e.lastOf("rt_rdp").GetReady() {
		t.Fatalf("refused checks while streams hold the target made it unhealthy: %v, %v", e.statusOf(tg.ID), e.lastOf("rt_rdp"))
	}

	// The same refusals without a stream are a failure: a target that refuses everything is unhealthy.
	for _, gw := range held {
		_ = gw.Close()
	}
	held = nil
	eventually(t, "the streams did not end", func() bool { return svc.active.Load() == 0 })
	svc.down.Store(true)
	eventually(t, "a target answering 503 with no stream held never became unhealthy", func() bool { return e.unhealthy(tg.ID) })
}

// TestTargetBound_TargetRefusingEverythingIsUnhealthy: with no stream held, a target that refuses
// every connection fails its checks as before, whatever the bound.
func TestTargetBound_TargetRefusingEverythingIsUnhealthy(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(closed.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	_ = closed.Close()
	tg := target("127.0.0.1", port)
	e := newTargets(allowLoopback(t, port))
	t.Cleanup(e.Close)
	check := fastCheck()
	check.Unhealthy = 1
	e.Set([]connector.Route{{ID: "rt_down", Targets: []connector.Target{tg}, Check: check, MaxTargetConns: 2}})
	eventually(t, "a target refusing everything never became unhealthy", func() bool { return e.unhealthy(tg.ID) })
	h := e.lastOf("rt_down")
	if h.GetReady() || h.GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_TARGETS_UNHEALTHY || strings.Contains(h.GetDetail(), "holds") {
		t.Errorf("the route of a target refusing everything: %v", h)
	}
}

// TestTargetBound_UnhealthyDetailNamesHeldStreams: a check that fails for a reason that decides,
// here a 503, while streams hold connections to the target: the target and the route are not ready
// and both details name the streams as the likely cause besides the failure.
func TestTargetBound_UnhealthyDetailNamesHeldStreams(t *testing.T) {
	svc := startPerSourceTarget(t, 10)
	tg := svc.target("tg_web")
	e := newTargets(allowLoopback(t, tg.Port))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_web", Targets: []connector.Target{tg}, Check: capCheck()}})
	e.healthy(t, tg.ID)
	held := e.stall(t, "rt_web", 2)
	t.Cleanup(func() {
		for _, gw := range held {
			_ = gw.Close()
		}
	})
	svc.down.Store(true)
	eventually(t, "the route never reported the cause", func() bool {
		h := e.lastOf("rt_web")
		return !h.GetReady() && strings.Contains(h.GetDetail(), "holds 2 connections") && strings.Contains(h.GetDetail(), "the target for streams")
	})
	st := e.statusOf(tg.ID)
	if !strings.Contains(st.GetDetail(), "503") || !strings.Contains(st.GetDetail(), "holds 2 connections") {
		t.Errorf("the target's status %q names no failure and cause", st.GetDetail())
	}
	h := e.lastOf("rt_web")
	if h.GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_TARGETS_UNHEALTHY {
		t.Errorf("the route's reason %s", h.GetReason())
	}
}

// TestTargetBound_PerTargetAndDefault: the bound is per target address, so a second target has its
// own slots and the stream goes to it; a route without a bound takes the default, far above a
// handful of streams; and the bound is shared by the routes that name the same target.
func TestTargetBound_PerTargetAndDefault(t *testing.T) {
	a, b := startService(t, echoService), startService(t, echoService)
	ta, tb := target("127.0.0.1", a.port()), target("127.0.0.1", b.port())
	tb.Priority = 1
	e := newTargets(allowLoopback(t, a.port(), b.port()))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{
		{ID: "rt_two", Targets: []connector.Target{ta, tb}, MaxTargetConns: 1},
		{ID: "rt_one", Targets: []connector.Target{ta}, MaxTargetConns: 1},
		{ID: "rt_default", Targets: []connector.Target{tb}},
	})
	first, second := tcpOpen("rt_two"), tcpOpen("rt_two")
	res1, gw1 := e.handleResult(t, first)
	res2, gw2 := e.handleResult(t, second)
	t.Cleanup(func() { _ = gw1.Close(); _ = gw2.Close() })
	if res1.GetTargetId() != ta.ID || res2.GetTargetId() != tb.ID {
		t.Errorf("targets of two streams under a bound of 1: %q then %q, want the second target taking the second", res1.GetTargetId(), res2.GetTargetId())
	}
	res3, gw3 := e.handleResult(t, tcpOpen("rt_one"))
	_ = gw3.Close()
	if res3.GetCode() != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
		t.Errorf("a stream of another route to a target at its bound: %s, want OVERLOADED", res3.GetCode())
	}
	// A stream refused by the bound holds nothing: the next fits once a slot is free.
	_ = gw1.Close()
	eventually(t, "the bound did not free with the stream", func() bool {
		code, gw := e.handle(t, tcpOpen("rt_one"))
		_ = gw.Close()
		return code == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR
	})
	for range 20 {
		code, gw := e.handle(t, tcpOpen("rt_default"))
		t.Cleanup(func() { _ = gw.Close() })
		if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("a stream of a route without a bound: %s", code)
		}
	}
}

// TestApplier_RouteBoundReachesTargets: a snapshot's max_target_connections is the route's bound:
// the second of two stalled streams to a route of bound 1 is refused with OVERLOADED, and a route
// without one takes both.
func TestApplier_RouteBoundReachesTargets(t *testing.T) {
	w := newWorld(t)
	svc := startService(t, echoService)
	var cur atomic.Pointer[policy.Policy]
	cur.Store(allowLoopback(t, svc.port()))
	var m *connector.Sessions
	targets := connector.NewTargets(connector.TargetsOptions{Policy: cur.Load, OnHealth: func(h *tunnelv1.RouteHealth) { m.SetReady(h) }})
	t.Cleanup(targets.Close)
	m = newConnectorWith(t, w, targets.Handle)
	a := connector.NewApplier(targets, m)
	bounded := routeResource("rt_bounded", agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO, addrTarget("127.0.0.1", uint32(svc.port())))
	bounded.GetConnectorRoute().MaxTargetConnections = 1
	a.Apply(t.Context(), &agentv1.Snapshot{Resources: []*agentv1.Resource{bounded,
		routeResource("rt_free", agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO, addrTarget("127.0.0.1", uint32(svc.port())))}}, agent.Changes{})
	open := func(route string) tunnelv1.ResultCode {
		st, gw := streamPair(t)
		t.Cleanup(func() { _ = gw.Close() })
		go targets.Handle(t.Context(), "gw_test", st, tcpOpen(route))
		res := &tunnelv1.StreamResult{}
		if err := tunnel.ReadMessage(gw, res); err != nil {
			t.Fatal(err)
		}
		return res.GetCode()
	}
	if c1, c2 := open("rt_bounded"), open("rt_bounded"); c1 != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR || c2 != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
		t.Errorf("two streams of a route bounded at 1: %s, %s", c1, c2)
	}
	if c1, c2 := open("rt_free"), open("rt_free"); c1 != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR || c2 != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Errorf("two streams of a route without a bound: %s, %s", c1, c2)
	}
}

// failingStream is a stream whose writes fail, as one whose gateway went away before the answer.
type failingStream struct{ tunnel.Stream }

func (failingStream) Write([]byte) (int, error) { return 0, errors.New("the gateway is gone") }

// TestTargetBound_ReleasePaths: the slot of a stream goes back however the stream ends: when the
// answer cannot be written, when the PROXY header cannot be written, and when the stream ends
// after its route was changed or removed.
func TestTargetBound_ReleasePaths(t *testing.T) {
	svc := startService(t, echoService)
	tg := target("127.0.0.1", svc.port())
	addr := tg.String()
	e := newTargets(allowLoopback(t, svc.port()))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{tg}, MaxTargetConns: 1}})

	st, gw := streamPair(t)
	_ = gw.Close()
	e.Handle(context.Background(), "gw_test", failingStream{st}, tcpOpen("rt_a")) // returns once the stream is done
	if n := e.HeldConns(addr); n != 0 {
		t.Fatalf("held %d after the answer could not be written, want 0", n)
	}

	// A target that resets at once: the PROXY header write, or the relay after it, fails; no slot stays.
	rst := startService(t, func(c net.Conn) {
		_ = c.(*net.TCPConn).SetLinger(0)
		_ = c.Close()
	})
	proxied := target("127.0.0.1", rst.port())
	proxied.ProxyProtocol = "v2"
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{tg}, MaxTargetConns: 1},
		{ID: "rt_p", Targets: []connector.Target{proxied}, MaxTargetConns: 1}})
	e.cur.Store(allowLoopback(t, svc.port(), rst.port()))
	for range 10 {
		_, gw := e.handleResult(t, tcpOpen("rt_p"))
		_ = gw.Close()
	}
	eventually(t, "a slot stayed taken after a target reset", func() bool { return e.HeldConns(proxied.String()) == 0 })

	// Streams that run while the route is changed and then removed keep the count right.
	held := e.stall(t, "rt_a", 1)
	e.Set([]connector.Route{{ID: "rt_a", Targets: []connector.Target{tg}, MaxTargetConns: 2}})
	if n := e.HeldConns(addr); n != 1 {
		t.Fatalf("held %d after a reload with a stream running, want 1", n)
	}
	held = append(held, e.stall(t, "rt_a", 1)...)
	if code, gw := e.handle(t, tcpOpen("rt_a")); code != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
		_ = gw.Close()
		t.Fatalf("a third stream under the new bound of 2: %s", code)
	}
	e.Set(nil) // the route is removed; its streams run on
	if n := e.HeldConns(addr); n != 2 {
		t.Fatalf("held %d after the route was removed with two streams running, want 2", n)
	}
	for _, gw := range held {
		_ = gw.Close()
	}
	eventually(t, "the slots stayed taken after the streams of a removed route ended", func() bool { return e.HeldConns(addr) == 0 })
}

// TestTargetBound_HTTPStreamsCountedNotRefused: an http route's streams are pooled and its limit
// counts requests, so the bound never refuses them, however low the route's value; a tcp route
// with the same value refuses.
func TestTargetBound_HTTPStreamsCountedNotRefused(t *testing.T) {
	svc := startService(t, echoService)
	tg := target("127.0.0.1", svc.port())
	e := newTargets(allowLoopback(t, svc.port()))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_web", HTTP: true, Targets: []connector.Target{tg}, MaxTargetConns: 1},
		{ID: "rt_tcp", Targets: []connector.Target{tg}, MaxTargetConns: 1}})
	held := e.stall(t, "rt_web", 3)
	t.Cleanup(func() {
		for _, gw := range held {
			_ = gw.Close()
		}
	})
	if n := e.HeldConns(tg.String()); n != 3 {
		t.Errorf("the connector counts %d http streams, want 3", n)
	}
	if code, gw := e.handle(t, tcpOpen("rt_tcp")); code != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
		_ = gw.Close()
		t.Errorf("a tcp stream beside the http ones: %s, want OVERLOADED", code)
	}
}

// TestTargetBound_OverlappingChecksOfDeadTargetCount: two routes check one address that does not
// answer, in step; each check's slot is not a stream, so neither makes the other undecided and the
// target becomes unhealthy on both.
func TestTargetBound_OverlappingChecksOfDeadTargetCount(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c) // accepted and never answered: a host that went away
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	a := connector.Target{ID: "tg_a", Host: "127.0.0.1", Port: port}
	b := connector.Target{ID: "tg_b", Host: "127.0.0.1", Port: port}
	check := &connector.HealthCheck{HTTP: true, Path: "/", StatusMin: 200, StatusMax: 399, Interval: 30 * time.Millisecond,
		Timeout: 150 * time.Millisecond, Unhealthy: 2, Healthy: 1}
	e := newTargets(allowLoopback(t, port))
	t.Cleanup(e.Close)
	e.Set([]connector.Route{{ID: "rt_1", Targets: []connector.Target{a}, Check: check}, {ID: "rt_2", Targets: []connector.Target{b}, Check: check}})
	eventually(t, "a dead target checked by two routes never became unhealthy", func() bool { return e.unhealthy(a.ID) && e.unhealthy(b.ID) })
}

// TestTargetBound_OpenStreamDoesNotKeepDeadTargetHealthy: a stream that stays open, as a client
// sending a byte now and then does, makes the checks a target refuses undecided only for so long: the
// maxUndecided-th in a row counts, and the target is unhealthy.
func TestTargetBound_OpenStreamDoesNotKeepDeadTargetHealthy(t *testing.T) {
	connector.SetMaxUndecided(t, 3)
	svc := startPerSourceTarget(t, 1)
	tg := svc.target("tg_one")
	e := newTargets(allowLoopback(t, tg.Port))
	t.Cleanup(e.Close)
	check := capCheck()
	check.Unhealthy = 1 // the check interval stays long, so that a check rarely meets the stream opening
	e.Set([]connector.Route{{ID: "rt_x", Targets: []connector.Target{tg}, Check: check, MaxTargetConns: 100}})
	e.healthy(t, tg.ID)
	held := e.stall(t, "rt_x", 1) // the target now refuses every other connection, its checks'
	t.Cleanup(func() {
		for _, gw := range held {
			_ = gw.Close()
		}
	})
	eventually(t, "refused checks never counted while a stream stayed open", func() bool { return e.unhealthy(tg.ID) })
	if st := e.statusOf(tg.ID); !strings.Contains(st.GetDetail(), "holds 1 connections") {
		t.Errorf("the status %q does not name the open stream", st.GetDetail())
	}
}
