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
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
)

// TestRouteLimit_Slots (docs/03-connections.md, "Route limits"): a route has at most its limit of
// slots; a slot is released once however often its release runs, also when what holds it panics;
// a changed limit applies to the same state, 0 is no limit, and a route's state stays the same
// across snapshots until it is dropped. A nil state limits nothing.
func TestRouteLimit_Slots(t *testing.T) {
	var ls gateway.Limits
	lim := ls.Set("rt_1", gateway.RouteLimits{MaxConnections: 2})
	if again := ls.Set("rt_1", gateway.RouteLimits{MaxConnections: 2}); again != lim {
		t.Fatal("a second snapshot made a new state")
	}
	r1, ok1 := lim.Acquire()
	r2, ok2 := lim.Acquire()
	if _, ok3 := lim.Acquire(); !ok1 || !ok2 || ok3 || lim.Open() != 2 {
		t.Fatalf("slots %t %t %t, %d open", ok1, ok2, ok3, lim.Open())
	}
	r1()
	r1()
	if lim.Open() != 1 {
		t.Fatalf("released twice: %d open", lim.Open())
	}
	func() {
		defer func() { _ = recover() }()
		release, ok := lim.Acquire()
		if !ok {
			t.Error("a released slot was not free")
		}
		defer release()
		panic("the handler failed")
	}()
	if lim.Open() != 1 {
		t.Fatalf("after a panic: %d open", lim.Open())
	}
	r2()
	ls.Set("rt_1", gateway.RouteLimits{})
	for range 100 {
		if _, ok := lim.Acquire(); !ok {
			t.Fatal("0 limited the connections")
		}
	}
	ls.Retain(map[string]bool{})
	if ls.Set("rt_1", gateway.RouteLimits{}) == lim {
		t.Error("a dropped route kept its state")
	}

	var none *gateway.RouteLimit
	if release, ok := none.Acquire(); !ok {
		t.Error("no state refused a connection")
	} else {
		release()
	}
	c, _ := net.Pipe()
	defer func() { _ = c.Close() }()
	if !none.AllowDatagram(true, 1<<20) || none.Conn(c) != c || none.Open() != 0 {
		t.Error("no state limited something")
	}
}

// TestTCPRoutes_ConnectionLimit: a connection over the route's limit is reset before a stream
// opens, the slot of a closed connection is free again, and a raised limit reaches the open route.
func TestTCPRoutes_ConnectionLimit(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	var ls gateway.Limits
	lim := ls.Set("rt_1", gateway.RouteLimits{MaxConnections: 1})
	port := freePort(t)
	if st := p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, Limit: lim}}); len(st) != 0 {
		t.Fatal(st)
	}
	a := dialPort(t, port)
	if err := ping(a, "first"); err != nil {
		t.Fatal(err)
	}
	b := dialPort(t, port)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := b.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("a connection over the limit: %d bytes, %v", n, err)
	}
	_ = a.Close()
	eventually(t, "the closed connection kept its slot", func() bool { return lim.Open() == 0 })
	c := dialPort(t, port)
	if err := ping(c, "after the first closed"); err != nil {
		t.Fatal(err)
	}
	ls.Set("rt_1", gateway.RouteLimits{MaxConnections: 2})
	if err := ping(dialPort(t, port), "a raised limit"); err != nil {
		t.Fatal(err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// echoRate sends n bytes through the echo route on port and returns the rate the echo came back
// at, in bytes per second, and the longest wait between two reads.
func echoRate(t *testing.T, port uint16, n int) (float64, time.Duration) {
	t.Helper()
	c := dialPort(t, port)
	go func() {
		_, _ = c.Write(make([]byte, n))
		_ = c.CloseWrite()
	}()
	start := time.Now()
	last, gap, got := start, time.Duration(0), 0
	buf := make([]byte, 32<<10)
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		k, err := c.Read(buf)
		got += k
		now := time.Now()
		gap, last = max(gap, now.Sub(last)), now
		if err != nil {
			break
		}
	}
	if got != n {
		t.Fatalf("the echo returned %d bytes of %d", got, n)
	}
	return float64(n) / time.Since(start).Seconds(), gap
}

// TestTCPRoutes_Bandwidth: a route's bandwidth limit holds the rate of each direction within
// ±10 %, and a low limit slows a connection down without stalling it.
func TestTCPRoutes_Bandwidth(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	const limit = 1 << 20
	var ls gateway.Limits
	lim := ls.Set("rt_1", gateway.RouteLimits{BandwidthBytesPerSecond: limit})
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, Limit: lim}})
	if got, _ := echoRate(t, port, 3<<20); got < 0.9*limit || got > 1.1*limit {
		t.Errorf("%.0f bytes per second at a limit of %d", got, limit)
	}

	// 16 KiB/s: the bucket's 64 KiB pass at once, the rest in steps of 1.6 KiB.
	ls.Set("rt_1", gateway.RouteLimits{BandwidthBytesPerSecond: 16 << 10})
	got, gap := echoRate(t, port, 96<<10)
	if got > 48<<10 || gap > time.Second {
		t.Errorf("a low limit: %.0f bytes per second, a stall of %s", got, gap)
	}
}

// TestUDPRoutes_Limits: a flow over the route's connection limit is dropped and counted with the
// reason "limit", and the slot of a flow that ended is free again; datagrams over the bandwidth are
// dropped and counted the same way.
func TestUDPRoutes_Limits(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-lim"): true}, routes: map[string][]string{route: {cid("udp-lim")}}}, nil)
	t.Cleanup(m.Close)
	start(t, m, connectorID("udp-lim"), hello(route))
	u, addr, reg := udpGateway(t, m, route, time.Minute)
	var ls gateway.Limits
	lim := ls.Set(route, gateway.RouteLimits{MaxConnections: 1})
	port := uint16(addr.Port) //nolint:gosec // G115: a port
	u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: time.Minute, Limit: lim}})
	dropped := func() float64 {
		return counter(t, reg, "rpmgr_udp_datagrams_dropped_total", map[string]string{"route": route, "reason": "limit"})
	}
	a, b := client(t), client(t)
	exchange(t, a, addr, []byte("a"))
	if _, err := b.WriteToUDP([]byte("b"), addr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a second flow was not dropped", func() bool { return dropped() == 1 })
	if u.Flows() != 1 || lim.Open() != 1 {
		t.Fatalf("%d flows, %d slots", u.Flows(), lim.Open())
	}

	// 1000 bytes per second: the bucket's 64 KiB pass, the rest of 120 KB is dropped.
	ls.Set(route, gateway.RouteLimits{MaxConnections: 1, BandwidthBytesPerSecond: 1000})
	for range 100 {
		if _, err := a.WriteToUDP(make([]byte, 1200), addr); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "datagrams over the bandwidth were not dropped", func() bool { return dropped() > 30 })

	ls.Set(route, gateway.RouteLimits{MaxConnections: 1})
	u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: time.Second, Limit: lim}})
	eventually(t, "an ended flow kept its slot", func() bool { return u.Flows() == 0 && lim.Open() == 0 })
	exchange(t, b, addr, []byte("b again"))
}

// TestHTTPRoutes_ConnectionLimit: a request over the route's limit of requests in flight is 503
// with Retry-After; a cancelled request and an upgraded connection that ends free their slots.
func TestHTTPRoutes_ConnectionLimit(t *testing.T) {
	entered := make(chan struct{}, 4)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/slow":
			entered <- struct{}{}
			<-r.Context().Done()
		case r.Header.Get("Upgrade") != "":
			websocketEcho(w, r)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	})
	var ls gateway.Limits
	lim := ls.Set("rt_lim", gateway.RouteLimits{MaxConnections: 1})
	route := gateway.HTTPRoute{ID: "rt_lim", Upstream: "http", WebSocket: true, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}, Limit: lim}
	e := newHTTPEnv(t, upstream, route)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.com/slow", nil)
		if resp, err := e.client(false).Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered
	r := get(t, e.client(false), "https://app.example.com/", nil)
	if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") != "1" {
		t.Fatalf("over the limit: %d, Retry-After %q", r.status, r.header.Get("Retry-After"))
	}
	cancel()
	<-done
	eventually(t, "a cancelled request kept its slot", func() bool { return lim.Open() == 0 })
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusOK || r.body != "ok" {
		t.Fatalf("after the cancel: %d %q", r.status, r.body)
	}

	// An upgraded connection holds its slot until it ends.
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write([]byte("GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusServiceUnavailable {
		t.Fatalf("during an upgrade: %d", r.status)
	}
	_ = c.Close()
	eventually(t, "an ended upgrade kept its slot", func() bool { return lim.Open() == 0 })
}

// TestHTTPRoutes_Bandwidth: a response comes at the route's bandwidth limit, within ±10 %.
func TestHTTPRoutes_Bandwidth(t *testing.T) {
	const limit, size = 512 << 10, 3 << 19
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(zeros{}, size))
	})
	var ls gateway.Limits
	route := gateway.HTTPRoute{ID: "rt_bw", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		Limit: ls.Set("rt_bw", gateway.RouteLimits{BandwidthBytesPerSecond: limit})}
	e := newHTTPEnv(t, upstream, route)
	start := time.Now()
	r := get(t, e.client(true), "https://app.example.com/big", nil)
	got := float64(len(r.body)) / time.Since(start).Seconds()
	if r.status != http.StatusOK || len(r.body) != size || got < 0.9*limit || got > 1.1*limit {
		t.Fatalf("%d, %d bytes at %.0f bytes per second, limit %d", r.status, len(r.body), got, limit)
	}
	if strings.Count(r.body, "\x00") != size {
		t.Fatal("the body changed on the way")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }
