// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestApplier_OnCut: a snapshot that removes a route or changes its access rules reports the route
// for the old process of a hand-off to cut; the first snapshot, an unchanged route and a new one
// report nothing.
func TestApplier_OnCut(t *testing.T) {
	a, _ := gateway.NewApplier()
	var mu sync.Mutex
	var cut []string
	a.OnCut = func(id string) {
		mu.Lock()
		cut = append(cut, id)
		mu.Unlock()
	}
	denyAll := func(r *agentv1.Resource, cidr string) *agentv1.Resource {
		r.GetGatewayTcpRoute().Access = &agentv1.RouteAccess{IpRules: []*agentv1.IPRule{{Allow: false, Cidrs: []string{cidr}}}}
		return r
	}
	take := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := slices.Sorted(slices.Values(cut))
		cut = nil
		return out
	}
	apply := func(seq uint64, rs ...*agentv1.Resource) {
		t.Helper()
		if st := a.Apply(t.Context(), gatewaySnapshot(seq, rs...), agent.Changes{}); len(st) != 0 {
			t.Fatal(st)
		}
	}
	p1, p2, p3 := freePort(t), freePort(t), freePort(t)
	apply(1, tcpResource("rt_1", uint32(p1), cid("con_1")), denyAll(tcpResource("rt_2", uint32(p2), cid("con_1")), "192.0.2.0/24"))
	if got := take(); len(got) != 0 {
		t.Fatalf("the first snapshot cut %v", got)
	}
	apply(2, tcpResource("rt_1", uint32(p1), cid("con_1")), denyAll(tcpResource("rt_2", uint32(p2), cid("con_1")), "192.0.2.0/24"),
		tcpResource("rt_3", uint32(p3), cid("con_1")))
	if got := take(); len(got) != 0 {
		t.Fatalf("an unchanged and a new route cut %v", got)
	}
	apply(3, tcpResource("rt_1", uint32(p1), cid("con_1")), denyAll(tcpResource("rt_2", uint32(p2), cid("con_1")), "198.51.100.0/24"),
		tcpResource("rt_3", uint32(p3), cid("con_1")))
	if got := take(); !slices.Equal(got, []string{"rt_2"}) {
		t.Fatalf("changed access rules cut %v, want rt_2", got)
	}
	apply(4, tcpResource("rt_1", uint32(p1), cid("con_1")))
	if got := take(); !slices.Equal(got, []string{"rt_2", "rt_3"}) {
		t.Fatalf("removed routes cut %v, want rt_2 and rt_3", got)
	}
}

// TestCuts: the routes changed before the pipe to the old process is there wait for it, and a pipe
// that fails loses a cut without stopping the new process.
func TestCuts(t *testing.T) {
	var c gateway.Cuts
	c.Send("rt_1")
	c.Send("rt_2")
	var got []string
	c.Attach(func(typ, reason string) error {
		if typ != gateway.MsgCut {
			t.Errorf("type %q", typ)
		}
		got = append(got, reason)
		return nil
	})
	if !slices.Equal(got, []string{"rt_1", "rt_2"}) {
		t.Fatalf("held cuts sent as %v", got)
	}
	c.Send("rt_3")
	if !slices.Equal(got, []string{"rt_1", "rt_2", "rt_3"}) {
		t.Fatalf("a cut after the pipe: %v", got)
	}
	var d gateway.Cuts
	d.Attach(func(string, string) error { return io.ErrClosedPipe })
	d.Send("rt_9") // the old process is gone: no panic, nothing to do
}

// TestTCPRoutes_CutRoute: the old process of a hand-off resets the open connections of the route
// the new process changed, and only those.
func TestTCPRoutes_CutRoute(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}})
	c := dialPort(t, port)
	if err := ping(c, "before"); err != nil {
		t.Fatal(err)
	}
	p.routes.CutRoute("rt_other")
	p.routes.CutRoute("")
	if err := ping(c, "another route cut"); err != nil {
		t.Fatalf("the connection of an unrelated cut ended: %v", err)
	}
	p.routes.CutRoute("rt_1")
	if err := ping(c, "after the cut"); err == nil {
		t.Fatal("a connection of the cut route went on")
	}
	p.routes.CutRoute("rt_1") // none left: no panic
}

// TestPassthrough_CutRoute: the same for a passthrough route.
func TestPassthrough_CutRoute(t *testing.T) {
	addr, pool := backend(t, "db.example.com")
	p := newPlaneWith(t, addr, "none", "rt_db")
	pass := gateway.NewPassthrough(p.sessions, nil, nil)
	t.Cleanup(pass.Close)
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	front := serve(t, &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: pass, DefaultTLS: def})
	pass.Apply([]gateway.PassthroughRoute{{ID: "rt_db", Hostnames: []string{"db.example.com"}}})
	var c *tls.Conn
	eventually(t, "no passthrough", func() bool {
		var err error
		c, err = tls.Dial("tcp", front, &tls.Config{ServerName: "db.example.com", RootCAs: pool, MinVersion: tls.VersionTLS13})
		return err == nil
	})
	defer func() { _ = c.Close() }()
	pass.CutRoute("rt_other")
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("an unrelated cut ended the connection: %v", err)
	}
	pass.CutRoute("rt_db")
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Write([]byte("x"))
	if err == nil {
		_, err = io.ReadFull(c, make([]byte, 8))
	}
	if err == nil {
		t.Fatal("a connection of the cut route went on")
	}
}

// TestSessions_AwaitSession: in the new process of a hand-off a connection of a route without a
// session waits for one up to the session wait: it succeeds once the connector arrives and gets
// ErrNoSession after the wait; a process that does not await fails at once.
func TestSessions_AwaitSession(t *testing.T) {
	gateway.SetSessionWait(t, 600*time.Millisecond)
	a := &assignment{known: map[string]bool{cid("con_1"): true}, routes: map[string][]string{"r1": {cid("con_1")}}}
	var await bool
	var mu sync.Mutex
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: a, AwaitSession: func() bool {
		mu.Lock()
		defer mu.Unlock()
		return await
	}})
	t.Cleanup(m.Close)
	open := func() (time.Duration, error) {
		start := time.Now()
		st, _, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"})
		if st != nil {
			_ = st.Close()
		}
		return time.Since(start), err
	}
	if d, err := open(); !errors.Is(err, gateway.ErrNoSession) || d > 300*time.Millisecond {
		t.Fatalf("without the wait: %v after %v", err, d)
	}
	mu.Lock()
	await = true
	mu.Unlock()
	if d, err := open(); !errors.Is(err, gateway.ErrNoSession) || d < 500*time.Millisecond {
		t.Fatalf("a wait that ran out: %v after %v", err, d)
	}
	// A cancelled connection stops waiting.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a cancelled wait: %v", err)
	}
	// The connector redials during the wait.
	done := make(chan error, 1)
	go func() { _, err := open(); done <- err }()
	time.Sleep(150 * time.Millisecond)
	c := start(t, m, connectorID("con_1"), hello("r1"))
	_ = c
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a connection that waited for the connector: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting connection did not return")
	}
}

// TestHTTPRoutes_CutRoute: the old process cancels a WebSocket of the route the new process
// changed, and leaves that of another route.
func TestHTTPRoutes_CutRoute(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", WebSocket: true, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	e := newHTTPEnv(t, websocketEcho, route)
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write([]byte("GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	echo := func() error {
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		_, err := io.ReadFull(br, make([]byte, 4))
		return err
	}
	e.routes.CutRoute("rt_other")
	e.routes.CutRoute("rt_missing")
	if err := echo(); err != nil {
		t.Fatalf("an unrelated cut ended the WebSocket: %v", err)
	}
	e.routes.CutRoute("rt_web")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("x"))
	_, err = io.Copy(io.Discard, br)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("a WebSocket of the cut route went on")
	}
}

// TestApplier_OnCutRules: every change of what decides who may use a route is reported, and one
// that decides nothing (a rate limit) is not.
func TestApplier_OnCutRules(t *testing.T) {
	port := freePort(t)
	uport := freeUDPPort(t)
	tcpWith := func(f func(*agentv1.RouteAccess)) *agentv1.Resource {
		r := tcpResource("rt_1", uint32(port), cid("con_1"))
		r.GetGatewayTcpRoute().Access = &agentv1.RouteAccess{}
		f(r.GetGatewayTcpRoute().Access)
		return r
	}
	udpWith := func(cidr string) *agentv1.Resource {
		r := udpResource("rt_1", uint32(uport), cid("con_1"))
		r.GetGatewayUdpRoute().Access = &agentv1.RouteAccess{IpRules: []*agentv1.IPRule{{Allow: true, Cidrs: []string{cidr}}}}
		return r
	}
	basic := func(version string) func(*agentv1.RouteAccess) {
		return func(a *agentv1.RouteAccess) {
			a.BasicAuth = []*agentv1.BasicAuthRule{{PolicyId: "pol_1", CredentialVersion: version}}
		}
	}
	header := func(sum byte) func(*agentv1.RouteAccess) {
		return func(a *agentv1.RouteAccess) {
			a.RequireHeader = []*rpmgrv1.RequireHeaderParams{{Name: "X-Key", ValueSha256: [][]byte{{sum}}}}
		}
	}
	limit := func(n uint32) func(*agentv1.RouteAccess) {
		return func(a *agentv1.RouteAccess) {
			a.RateLimits = []*agentv1.RateLimitRule{{PolicyId: "pol_1", PerSecond: n, Burst: n}}
		}
	}
	none := func(*agentv1.RouteAccess) {}
	for _, tc := range []struct {
		name       string
		a, b       []*agentv1.Resource
		wantCutOne bool
	}{
		{"require_header rotated", []*agentv1.Resource{tcpWith(header(1))}, []*agentv1.Resource{tcpWith(header(2))}, true},
		{"require_header the same", []*agentv1.Resource{tcpWith(header(1))}, []*agentv1.Resource{tcpWith(header(1))}, false},
		{"basic auth version bumped", []*agentv1.Resource{tcpWith(basic("v1"))}, []*agentv1.Resource{tcpWith(basic("v2"))}, true},
		{"basic auth added", []*agentv1.Resource{tcpWith(none)}, []*agentv1.Resource{tcpWith(basic("v1"))}, true},
		{"rate limit only", []*agentv1.Resource{tcpWith(limit(1))}, []*agentv1.Resource{tcpWith(limit(9))}, false},
		{"udp rule tightened", []*agentv1.Resource{udpWith("0.0.0.0/0")}, []*agentv1.Resource{udpWith("10.0.0.0/8")}, true},
		{"udp rule the same", []*agentv1.Resource{udpWith("10.0.0.0/8")}, []*agentv1.Resource{udpWith("10.0.0.0/8")}, false},
		{"udp route removed", []*agentv1.Resource{udpWith("10.0.0.0/8")}, nil, true},
		{"tcp route became udp", []*agentv1.Resource{tcpWith(none)}, []*agentv1.Resource{udpResource("rt_1", uint32(uport), cid("con_1"))}, true},
	} {
		a, _ := gateway.NewApplier()
		var cut []string
		a.OnCut = func(id string) { cut = append(cut, id) }
		a.Apply(t.Context(), gatewaySnapshot(1, tc.a...), agent.Changes{})
		a.Apply(t.Context(), gatewaySnapshot(2, tc.b...), agent.Changes{})
		if got := len(cut) == 1 && cut[0] == "rt_1"; got != tc.wantCutOne || len(cut) > 1 {
			t.Errorf("%s: cut %v, want cut %v", tc.name, cut, tc.wantCutOne)
		}
	}
	// Removed in one snapshot and added again in the next: cut once, at the removal.
	a, _ := gateway.NewApplier()
	var cut []string
	a.OnCut = func(id string) { cut = append(cut, id) }
	r := tcpWith(none)
	a.Apply(t.Context(), gatewaySnapshot(1, r), agent.Changes{})
	a.Apply(t.Context(), gatewaySnapshot(2), agent.Changes{})
	a.Apply(t.Context(), gatewaySnapshot(3, r), agent.Changes{})
	if !slices.Equal(cut, []string{"rt_1"}) {
		t.Fatalf("removed and added again: cut %v", cut)
	}
}

// TestUDPRoutes_CutRoute: the old process ends the flows of the cut route and only those; an
// unknown route ID changes nothing.
func TestUDPRoutes_CutRoute(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-cut"): true}, routes: map[string][]string{route: {cid("udp-cut")}}}, nil)
	t.Cleanup(m.Close)
	start(t, m, connectorID("udp-cut"), hello(route))
	u, addr, _ := udpGateway(t, m, route, time.Minute)
	c := client(t)
	exchange(t, c, addr, []byte("flow"))
	if u.Flows() != 1 {
		t.Fatalf("%d flows", u.Flows())
	}
	u.CutRoute("rt_unknown")
	u.CutRoute("")
	if u.Flows() != 1 {
		t.Fatalf("an unrelated cut left %d flows", u.Flows())
	}
	u.CutRoute(route)
	if u.Flows() != 0 {
		t.Fatalf("%d flows after the cut", u.Flows())
	}
	exchange(t, c, addr, []byte("again")) // the port still serves new flows
}

// TestWithGeneration: a gateway's metrics carry the generation next to an all-in-one's role label.
func TestWithGeneration(t *testing.T) {
	reg := prometheus.NewRegistry()
	withRole := telemetry.WithLabels(reg, prometheus.Labels{"role": "gateway"})
	m, err := gateway.NewMetrics(gateway.WithGeneration(withRole, "3"))
	if err != nil {
		t.Fatalf("both labels on one registry: %v", err)
	}
	m.PageLogDropped()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		for _, mt := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range mt.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if mf.GetName() == "rpmgr_gateway_page_log_lines_dropped_total" && labels["generation"] == "3" && labels["role"] == "gateway" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no gateway series with generation and role")
	}
}
