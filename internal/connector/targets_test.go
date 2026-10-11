// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// tcpStream is a tunnel.Stream over one end of a TCP connection: FIN, reset and half-close as on
// a real transport.
type tcpStream struct{ *net.TCPConn }

func (s tcpStream) SetReliableBoundary() {}
func (s tcpStream) Abort() {
	_ = s.SetLinger(0)
	_ = s.Close()
}

// streamPair returns a stream for Handle and the gateway's end of it.
func streamPair(t *testing.T) (tunnel.Stream, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		got <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-got
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return tcpStream{s.(*net.TCPConn)}, c.(*net.TCPConn)
}

// service is a TCP listener that counts its connections and hands each to serve.
type service struct {
	ln    net.Listener
	conns atomic.Int64
}

func startService(t *testing.T, serve func(net.Conn)) *service {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &service{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go serve(c)
		}
	}()
	return s
}

func (s *service) port() uint16 {
	return uint16(s.ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
}

func echoService(c net.Conn) {
	_, _ = io.Copy(c, c)
	_ = c.Close()
}

// policyOf parses a policy file body after its version line.
func policyOf(t *testing.T, body string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte("version: 1\n" + body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func allowLoopback(t *testing.T, ports ...uint16) *policy.Policy {
	t.Helper()
	list := ""
	for _, p := range ports {
		list += fmt.Sprintf("%d, ", p)
	}
	return policyOf(t, "allow_targets:\n  - cidr: 127.0.0.0/8\n    ports: ["+list+"]\n")
}

// targets returns a Targets with the policy in cur, recording health reports.
type targetsEnv struct {
	*connector.Targets
	cur    atomic.Pointer[policy.Policy]
	mu     sync.Mutex
	health []*tunnelv1.RouteHealth
}

func newTargets(p *policy.Policy) *targetsEnv { return newTargetsWith(p, nil) }

// newTargetsWith is newTargets recording metrics.
func newTargetsWith(p *policy.Policy, metrics *connector.Metrics) *targetsEnv {
	e := &targetsEnv{}
	e.cur.Store(p)
	e.Targets = connector.NewTargets(connector.TargetsOptions{Policy: e.cur.Load, Metrics: metrics, OnHealth: func(h *tunnelv1.RouteHealth) {
		e.mu.Lock()
		e.health = append(e.health, h)
		e.mu.Unlock()
	}})
	return e
}

func (e *targetsEnv) last() *tunnelv1.RouteHealth {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.health) == 0 {
		return nil
	}
	return e.health[len(e.health)-1]
}

// handle runs Handle for open and returns the gateway's end after its StreamResult.
func (e *targetsEnv) handle(t *testing.T, open *tunnelv1.StreamOpen) (tunnelv1.ResultCode, *net.TCPConn) {
	t.Helper()
	res, gw := e.handleResult(t, open)
	return res.GetCode(), gw
}

// handleResult is handle returning the whole StreamResult.
func (e *targetsEnv) handleResult(t *testing.T, open *tunnelv1.StreamOpen) (*tunnelv1.StreamResult, *net.TCPConn) {
	t.Helper()
	st, gw := streamPair(t)
	go e.Handle(context.Background(), "gw_test", st, open)
	_ = gw.SetReadDeadline(time.Now().Add(10 * time.Second))
	res := &tunnelv1.StreamResult{}
	if err := tunnel.ReadMessage(gw, res); err != nil {
		t.Fatalf("no StreamResult: %v", err)
	}
	_ = gw.SetReadDeadline(time.Time{})
	return res, gw
}

func tcpOpen(route string) *tunnelv1.StreamOpen {
	return &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: route}
}

func target(host string, port uint16) connector.Target {
	return connector.Target{ID: "tg_" + host + strconv.Itoa(int(port)), Host: host, Port: port}
}

// TestTargets_Codes: the StreamResult of each failure, and a stream that only a route of the
// snapshot, or one removed less than the drain period ago, opens.
func TestTargets_Codes(t *testing.T) {
	connector.SetRouteDrain(t, 300*time.Millisecond)
	echo := startService(t, echoService)
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := uint16(closed.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	_ = closed.Close()
	e := newTargets(allowLoopback(t, echo.port(), closedPort))
	e.Set([]connector.Route{
		{ID: "rt_echo", Targets: []connector.Target{target("127.0.0.1", echo.port())}},
		{ID: "rt_closed", Targets: []connector.Target{target("127.0.0.1", closedPort)}},
	})
	for _, tc := range []struct {
		name string
		open *tunnelv1.StreamOpen
		want tunnelv1.ResultCode
	}{
		{"unknown route", tcpOpen("rt_nope"), tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN},
		{"refused", tcpOpen("rt_closed"), tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED},
		{"no route", tcpOpen(""), tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{"UDP before its slice", &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW, RouteId: "rt_echo"}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{"DIAG", &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_DIAG, RouteId: "rt_echo"}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{"bad address", &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: "rt_echo", SrcIp: []byte{1, 2, 3}}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{"open", tcpOpen("rt_echo"), tunnelv1.ResultCode_RESULT_CODE_NO_ERROR},
	} {
		if got, _ := e.handle(t, tc.open); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
	eventually(t, "the opened stream did not reach the service", func() bool { return echo.conns.Load() == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := echo.conns.Load(); n != 1 {
		t.Fatalf("the service got %d connections, want only the one that was opened", n)
	}

	// A removed route drains: it still opens, until the drain period ends.
	e.Set(nil)
	if h := e.last(); h.GetReady() {
		t.Fatalf("a removed route is still reported ready: %v", h)
	}
	if got, _ := e.handle(t, tcpOpen("rt_echo")); got != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("a draining route: %s", got)
	}
	time.Sleep(400 * time.Millisecond)
	if got, _ := e.handle(t, tcpOpen("rt_echo")); got != tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN {
		t.Fatalf("after the drain: %s", got)
	}
}

// TestTargets_HalfClose: bytes the service sends after the client's FIN reach the client.
func TestTargets_HalfClose(t *testing.T) {
	svc := startService(t, func(c net.Conn) {
		req, _ := io.ReadAll(c)
		_, _ = c.Write(bytes.ToUpper(req))
		_ = c.Close()
	})
	e := newTargets(allowLoopback(t, svc.port()))
	e.Set([]connector.Route{{ID: "rt_1", Targets: []connector.Target{target("127.0.0.1", svc.port())}}})
	code, gw := e.handle(t, tcpOpen("rt_1"))
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatal(code)
	}
	_, _ = gw.Write([]byte("last words"))
	_ = gw.CloseWrite()
	got, err := io.ReadAll(gw)
	if err != nil || string(got) != "LAST WORDS" {
		t.Fatalf("%q %v", got, err)
	}
}

// TestTargets_BlockedNeverDialled: a target the local policy forbids is never dialled; the route
// is not_ready(blocked_by_local_policy: <ip:port>) until the policy allows it. A name is checked
// on its resolved address when it is dialled.
func TestTargets_BlockedNeverDialled(t *testing.T) {
	svc := startService(t, echoService)
	e := newTargets(policy.Defaults())
	ipTarget := target("127.0.0.1", svc.port())
	e.Set([]connector.Route{{ID: "rt_ip", Targets: []connector.Target{ipTarget}}})
	want := "127.0.0.1:" + strconv.Itoa(int(svc.port()))
	if h := e.last(); h.GetReady() || h.GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY || h.GetDetail() != want {
		t.Fatalf("health %v", h)
	}
	if st := e.Status(); len(st) != 1 || st[0].GetResourceId() != "rt_ip" || st[0].GetDetail() != want {
		t.Fatalf("status %v", st)
	}
	if code, _ := e.handle(t, tcpOpen("rt_ip")); code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("a blocked target: %s", code)
	}

	// A name counts as ready until its dial is refused on the resolved address.
	e.Set([]connector.Route{{ID: "rt_name", Targets: []connector.Target{target("localhost", svc.port())}}})
	if h := e.last(); !h.GetReady() || h.GetRouteId() != "rt_name" {
		t.Fatalf("a name target: %v", h)
	}
	if code, _ := e.handle(t, tcpOpen("rt_name")); code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("a blocked name: %s", code)
	}
	if h := e.last(); h.GetReady() || h.GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY {
		t.Fatalf("after a blocked dial: %v", h)
	}
	if n := svc.conns.Load(); n != 0 {
		t.Fatalf("the service got %d connections from blocked targets", n)
	}

	// The policy changes: the route becomes ready without a new snapshot.
	e.cur.Store(allowLoopback(t, svc.port()))
	e.Recheck()
	if h := e.last(); !h.GetReady() || h.GetRouteId() != "rt_name" {
		t.Fatalf("after allowing: %v", h)
	}
	if code, _ := e.handle(t, tcpOpen("rt_name")); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("an allowed name: %s", code)
	}

	// An invalid policy blocks everything.
	_, err := policy.Parse([]byte("version: 2\n"))
	e.cur.Store(&policy.Policy{Invalid: err})
	e.Recheck()
	if h := e.last(); h.GetReady() || h.GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_POLICY_INVALID {
		t.Fatalf("an invalid policy: %v", h)
	}
}

// TestTargets_Failover: a refused target is passed over for the next priority; a timeout ends the
// attempt.
func TestTargets_Failover(t *testing.T) {
	svc := startService(t, echoService)
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := uint16(closed.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	_ = closed.Close()
	e := newTargets(allowLoopback(t, svc.port(), closedPort))
	primary, backup := target("127.0.0.1", closedPort), target("127.0.0.1", svc.port())
	backup.Priority = 1
	e.Set([]connector.Route{{ID: "rt_1", Targets: []connector.Target{backup, primary}}})
	// The result names the target the stream reached, so a gateway can verify an HTTPS upstream.
	if res, _ := e.handleResult(t, tcpOpen("rt_1")); res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR || res.GetTargetId() != backup.ID {
		t.Fatalf("failover: %v, want NO_ERROR from %s", res, backup.ID)
	}
	e.Set([]connector.Route{{ID: "rt_1", Targets: []connector.Target{primary}}})
	if res, _ := e.handleResult(t, tcpOpen("rt_1")); res.GetCode() == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR || res.GetTargetId() != "" {
		t.Fatalf("a refused stream: %v, want no target", res)
	}
	eventually(t, "the backup was not used", func() bool { return svc.conns.Load() >= 1 })
}

// TestOrder: priorities in order; within one, weights decide how often a target comes first.
func TestOrder(t *testing.T) {
	ts := []connector.Target{{ID: "c", Priority: 2}, {ID: "a", Weight: 3}, {ID: "b", Weight: 1}, {ID: "z", Priority: 1}}
	first := map[string]int{}
	for range 2000 {
		o := connector.Order(ts)
		if o[2].ID != "z" || o[3].ID != "c" {
			t.Fatalf("priority order %v", o)
		}
		first[o[0].ID]++
	}
	if r := float64(first["a"]) / float64(first["b"]); r < 2 || r > 4.5 {
		t.Fatalf("weights 3:1 came first %v", first)
	}
}

// TestTargets_ProxyHeaders: the PROXY header each target asks for, byte for byte.
func TestTargets_ProxyHeaders(t *testing.T) {
	headers := make(chan []byte, 8)
	svc := startService(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		b, _ := io.ReadAll(c)
		headers <- b
		_ = c.Close()
	})
	e := newTargets(allowLoopback(t, svc.port()))
	v4src, v4dst := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("198.51.100.1")
	v6src, v6dst := netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("2001:db8::1")
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	for _, tc := range []struct {
		name     string
		version  string
		src, dst netip.Addr
		want     []byte
	}{
		{"v1 IPv4", "v1", v4src, v4dst, []byte("PROXY TCP4 203.0.113.7 198.51.100.1 51234 5432\r\n")},
		{"v1 IPv6", "v1", v6src, v6dst, []byte("PROXY TCP6 2001:db8::7 2001:db8::1 51234 5432\r\n")},
		{"v1 without addresses", "v1", netip.Addr{}, netip.Addr{}, []byte("PROXY UNKNOWN\r\n")},
		{"v2 IPv4", "v2", v4src, v4dst, append(append([]byte{}, sig...), 0x21, 0x11, 0x00, 0x0c,
			203, 0, 113, 7, 198, 51, 100, 1, 0xc8, 0x22, 0x15, 0x38)},
		{"v2 without addresses", "v2", netip.Addr{}, netip.Addr{}, append(append([]byte{}, sig...), 0x20, 0x00, 0x00, 0x00)},
		{"none", "none", v4src, v4dst, []byte{}},
	} {
		tg := target("127.0.0.1", svc.port())
		tg.ProxyProtocol = tc.version
		e.Set([]connector.Route{{ID: "rt_1", Targets: []connector.Target{tg}}})
		open := tcpOpen("rt_1")
		if tc.src.IsValid() {
			open.SrcIp, open.SrcPort, open.DstIp, open.DstPort = tc.src.AsSlice(), 51234, tc.dst.AsSlice(), 5432
		}
		code, gw := e.handle(t, open)
		if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("%s: %s", tc.name, code)
		}
		_ = gw.CloseWrite()
		if got := <-headers; !bytes.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestTargets_Unix: a unix socket target, only where the policy lists it.
func TestTargets_Unix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var conns atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go echoService(c)
		}
	}()
	e := newTargets(policy.Defaults())
	e.Set([]connector.Route{{ID: "rt_unix", Targets: []connector.Target{{ID: "tg_u", UnixPath: path}}}})
	if h := e.last(); h.GetReady() || h.GetDetail() != path {
		t.Fatalf("an unlisted socket: %v", h)
	}
	if code, _ := e.handle(t, tcpOpen("rt_unix")); code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED || conns.Load() != 0 {
		t.Fatalf("an unlisted socket: %s, %d connections", code, conns.Load())
	}
	e.cur.Store(policyOf(t, "allow_targets:\n  - unix: "+path+"\n"))
	e.Recheck()
	code, gw := e.handle(t, tcpOpen("rt_unix"))
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatal(code)
	}
	_, _ = gw.Write([]byte("over a socket"))
	_ = gw.CloseWrite()
	if got, err := io.ReadAll(gw); err != nil || string(got) != "over a socket" {
		t.Fatalf("%q %v", got, err)
	}
}

// TestTargets_ThroughSessions: end to end, the gateway opens a route's streams only once the
// connector's local policy lets the route be ready.
func TestTargets_ThroughSessions(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	svc := startService(t, echoService)
	var cur atomic.Pointer[policy.Policy]
	cur.Store(policy.Defaults())
	var m *connector.Sessions
	tg := connector.NewTargets(connector.TargetsOptions{Policy: cur.Load, OnHealth: func(h *tunnelv1.RouteHealth) { m.SetReady(h) }})
	m = newConnectorWith(t, w, tg.Handle)
	tg.Set([]connector.Route{{ID: "rt_1", Targets: []connector.Target{target("127.0.0.1", svc.port())}}})
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_1": connector.TransportQUIC}}})
	eventually(t, "no session", func() bool { return g.sessions.Load().Count()["quic"] == 1 })
	if _, _, err := g.sessions.Load().OpenStream(context.Background(), tcpOpen("rt_1")); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a blocked route was opened: %v", err)
	}
	cur.Store(allowLoopback(t, svc.port()))
	tg.Recheck()
	eventually(t, "the allowed route is not open", func() bool {
		st, code, err := g.sessions.Load().OpenStream(context.Background(), tcpOpen("rt_1"))
		if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			return false
		}
		defer func() { _ = st.Close() }()
		_, _ = st.Write([]byte("through"))
		_ = st.CloseWrite()
		got, err := io.ReadAll(st)
		return err == nil && string(got) == "through"
	})
}

// TestCodeOf: dial errors and their result codes.
func TestCodeOf(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want tunnelv1.ResultCode
	}{
		{context.DeadlineExceeded, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT},
		{&net.OpError{Op: "dial", Err: &net.DNSError{IsTimeout: true}}, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNRESET)}, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_RESET},
		{&net.OpError{Op: "dial", Err: &net.DNSError{IsNotFound: true}}, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED},
	} {
		if got := connector.CodeOf(tc.err); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}

// TestTargets_Timeout: a StreamOpen's shorter open timeout bounds the dial.
func TestTargets_Timeout(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: never routed, so a dial waits or fails at once, never connects.
	e := newTargets(policyOf(t, "allow_targets:\n  - cidr: 192.0.2.0/24\n    ports: [9]\n"))
	e.Set([]connector.Route{{ID: "rt_1", Targets: []connector.Target{target("192.0.2.1", 9)}}})
	open := tcpOpen("rt_1")
	open.OpenTimeoutMs = 200
	begin := time.Now()
	code, _ := e.handle(t, open)
	if d := time.Since(begin); d > 3*time.Second {
		t.Fatalf("took %s with a 200 ms open timeout", d)
	}
	if code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT && code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("%s", code)
	}
}

// TestTargets_PolicyReloadResetsBlocked: when a reloaded policy takes a target out, the open
// connections to it are reset, as a pooled upstream connection would otherwise keep it reachable;
// a connection to a target the policy still allows carries on, and a policy that does not load
// resets every connection.
func TestTargets_PolicyReloadResetsBlocked(t *testing.T) {
	kept, removed := startService(t, echoService), startService(t, echoService)
	e := newTargets(allowLoopback(t, kept.port(), removed.port()))
	e.Set([]connector.Route{
		{ID: "rt_kept", Targets: []connector.Target{target("127.0.0.1", kept.port())}},
		{ID: "rt_removed", Targets: []connector.Target{target("127.0.0.1", removed.port())}},
	})
	echoes := func(gw *net.TCPConn) error {
		_ = gw.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := gw.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		_, err := io.ReadFull(gw, buf)
		return err
	}
	open := func(route string) *net.TCPConn {
		code, gw := e.handle(t, tcpOpen(route))
		if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("%s: %v", route, code)
		}
		if err := echoes(gw); err != nil {
			t.Fatalf("%s before the reload: %v", route, err)
		}
		return gw
	}
	a, b := open("rt_kept"), open("rt_removed")

	e.cur.Store(allowLoopback(t, kept.port()))
	e.Recheck()
	if err := echoes(a); err != nil {
		t.Errorf("a target the policy still allows: %v", err)
	}
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(b); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a target the policy took out: %v, want a reset", err)
	}
	if h := e.last(); h.GetRouteId() != "rt_removed" || h.GetReady() {
		t.Errorf("readiness after the reload: %v", h)
	}

	e.cur.Store(&policy.Policy{Invalid: errors.New("the file does not parse")})
	e.Recheck()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(a); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a policy that does not load: %v, want a reset", err)
	}
}
