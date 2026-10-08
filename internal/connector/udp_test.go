// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// udpService echoes datagrams and records the addresses they came from.
type udpService struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	sources map[string]bool
}

func startUDPService(t *testing.T) *udpService {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s := &udpService{conn: c, sources: map[string]bool{}}
	go func() {
		buf := make([]byte, 70000)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.sources[from.String()] = true
			s.mu.Unlock()
			_, _ = c.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return s
}

func (s *udpService) port() uint16 { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort().Port() }

func (s *udpService) seen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sources)
}

func udpOpen(route string) *tunnelv1.StreamOpen {
	return &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW, RouteId: route}
}

func randomPayload(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// exchangeUDP sends payload to addr until its echo comes back, so a datagram lost on the way does
// not fail the test.
func exchangeUDP(t *testing.T, c *net.UDPConn, addr *net.UDPAddr, payload []byte) {
	t.Helper()
	buf := make([]byte, 70000)
	for range 40 {
		if _, err := c.WriteToUDP(payload, addr); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if n, err := c.Read(buf); err == nil && bytes.Equal(buf[:n], payload) {
			return
		}
	}
	t.Fatalf("no echo of %d bytes", len(payload))
}

func udpClient(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func oversize(t *testing.T, reg *prometheus.Registry) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	sum := 0.0
	for _, mf := range mfs {
		if mf.GetName() == "rpmgr_udp_oversize_total" {
			for _, m := range mf.GetMetric() {
				sum += m.GetCounter().GetValue()
			}
		}
	}
	return sum
}

// TestUDPFlows_EndToEnd: a udp route's flows travel from a gateway port through the connector to
// the target and back, on both transports: on QUIC a payload that fits goes as a datagram and a
// larger one as a frame, counted as oversize; on h2 everything goes as frames. Each client is a
// flow with a socket of its own at the connector.
func TestUDPFlows_EndToEnd(t *testing.T) {
	for _, transport := range []string{connector.TransportQUIC, connector.TransportH2} {
		t.Run(transport, func(t *testing.T) {
			w := newWorld(t)
			id := w.gatewayID()
			g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
			svc := startUDPService(t)
			reg := prometheus.NewRegistry()
			metrics, err := tunnel.NewUDPMetrics(reg)
			if err != nil {
				t.Fatal(err)
			}
			var m *connector.Sessions
			tg := connector.NewTargets(connector.TargetsOptions{Policy: constant(allowLoopback(t, svc.port())), UDPMetrics: metrics,
				OnHealth: func(h *tunnelv1.RouteHealth) { m.SetReady(h) }})
			m = newConnectorWith(t, w, tg.Handle)
			tg.Set([]connector.Route{{ID: "rt_udp", UDP: true, Targets: []connector.Target{target("127.0.0.1", svc.port())}}})
			m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_udp": transport}}})

			u := gateway.NewUDPRoutes(gateway.UDPOptions{Host: "127.0.0.1", Sessions: g.sessions.Load()})
			t.Cleanup(u.Close)
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			public := pc.LocalAddr().(*net.UDPAddr)
			_ = pc.Close()
			if st := u.Apply([]gateway.UDPRoute{{ID: "rt_udp", Port: public.AddrPort().Port(), FlowIdle: time.Minute}}); len(st) != 0 {
				t.Fatal(st)
			}
			a, b := udpClient(t), udpClient(t)
			for _, n := range []int{1, 100, 3000, 60000} {
				exchangeUDP(t, a, public, randomPayload(n))
			}
			exchangeUDP(t, b, public, randomPayload(10))
			if svc.seen() != 2 {
				t.Fatalf("the target saw %d source addresses, want one per flow", svc.seen())
			}
			got := oversize(t, reg)
			if transport == connector.TransportQUIC && got < 2 || transport == connector.TransportH2 && got != 0 {
				t.Fatalf("oversize replies counted: %v", got)
			}
		})
	}
}

// constant returns a policy source that always returns p.
func constant[T any](p T) func() T { return func() T { return p } }

// TestUDPFlows_Refusals: a flow needs a udp route of the snapshot and an address target the local
// policy allows; a tcp stream never opens a udp route.
func TestUDPFlows_Refusals(t *testing.T) {
	svc := startUDPService(t)
	e := newTargets(allowLoopback(t, svc.port()))
	e.Set([]connector.Route{
		{ID: "rt_udp", UDP: true, Targets: []connector.Target{target("127.0.0.1", svc.port())}},
		{ID: "rt_tcp", Targets: []connector.Target{target("127.0.0.1", svc.port())}},
		{ID: "rt_blocked", UDP: true, Targets: []connector.Target{target("127.0.0.1", svc.port()+1)}},
		{ID: "rt_unix", UDP: true, Targets: []connector.Target{{ID: "tg_unix", UnixPath: "/run/x.sock"}}},
	})
	for _, tc := range []struct {
		open *tunnelv1.StreamOpen
		want tunnelv1.ResultCode
	}{
		{udpOpen("rt_tcp"), tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{tcpOpen("rt_udp"), tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{udpOpen("rt_gone"), tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN},
		{udpOpen("rt_blocked"), tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED},
		{udpOpen("rt_unix"), tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED},
	} {
		if code, _ := e.handle(t, tc.open); code != tc.want {
			t.Errorf("%v on %s: %v, want %v", tc.open.GetKind(), tc.open.GetRouteId(), code, tc.want)
		}
	}
	if svc.seen() != 0 {
		t.Fatalf("a refused flow reached the target")
	}
}

// TestUDPFlows_Frames: on a stream without datagrams every payload is a frame, from an empty one
// to the largest UDP payload; a frame above it ends the flow, and so does the end of the stream.
func TestUDPFlows_Frames(t *testing.T) {
	svc := startUDPService(t)
	e := newTargets(allowLoopback(t, svc.port()))
	e.Set([]connector.Route{{ID: "rt_udp", UDP: true, Targets: []connector.Target{target("127.0.0.1", svc.port())}}})
	code, gw := e.handle(t, udpOpen("rt_udp"))
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatal(code)
	}
	_ = gw.SetDeadline(time.Now().Add(10 * time.Second))
	for _, n := range []int{0, 1, 1500, 65507} { // 65507: the largest UDP payload over IPv4
		p := randomPayload(n)
		if err := tunnel.WriteFrame(gw, p); err != nil {
			t.Fatal(err)
		}
		got, err := tunnel.ReadFrame(gw)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("%d bytes: %d back, %v", n, len(got), err)
		}
	}
	if _, err := gw.Write(binary.AppendUvarint(nil, tunnel.MaxUDPPayload+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.ReadFrame(gw); err == nil {
		t.Fatal("the flow went on after an oversized frame")
	}

	code, gw = e.handle(t, udpOpen("rt_udp"))
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatal(code)
	}
	_ = gw.CloseWrite()
	_ = gw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tunnel.ReadFrame(gw); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the flow outlived its stream: %v", err)
	}
}

// TestUDPFlows_TargetUnreachable: a target port that answers with ICMP port unreachable does not
// end the flow; the target may come back.
func TestUDPFlows_TargetUnreachable(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	_ = c.Close()
	e := newTargets(allowLoopback(t, port))
	e.Set([]connector.Route{{ID: "rt_udp", UDP: true, Targets: []connector.Target{target("127.0.0.1", port)}}})
	code, gw := e.handle(t, udpOpen("rt_udp"))
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatal(code)
	}
	for range 3 {
		if err := tunnel.WriteFrame(gw, []byte("anyone?")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = gw.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := tunnel.ReadFrame(gw); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the flow ended: %v", err)
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Skipf("the port was taken meanwhile: %v", err)
	}
	defer func() { _ = back.Close() }()
	go func() {
		buf := make([]byte, 100)
		n, from, err := back.ReadFromUDPAddrPort(buf)
		if err == nil {
			_, _ = back.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	_ = gw.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tunnel.WriteFrame(gw, []byte("back")); err != nil {
		t.Fatal(err)
	}
	if got, err := tunnel.ReadFrame(gw); err != nil || string(got) != "back" {
		t.Fatalf("%q %v", got, err)
	}
}

// TestUDPFlows_Cancelled: a flow ends when the connector stops.
func TestUDPFlows_Cancelled(t *testing.T) {
	svc := startUDPService(t)
	e := newTargets(allowLoopback(t, svc.port()))
	e.Set([]connector.Route{{ID: "rt_udp", UDP: true, Targets: []connector.Target{target("127.0.0.1", svc.port())}}})
	st, gw := streamPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Handle(ctx, "gw_test", st, udpOpen("rt_udp")); close(done) }()
	if err := tunnel.ReadMessage(gw, &tunnelv1.StreamResult{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the flow outlived the connector")
	}
}
