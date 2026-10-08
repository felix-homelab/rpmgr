// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// udpEcho is a connector over QUIC that answers every UDP_FLOW stream and echoes its payloads the
// way they came: datagrams as datagrams, frames as frames.
type udpEcho struct {
	opens             chan *tunnelv1.StreamOpen
	datagrams, frames atomic.Int64
}

// newUDPEcho starts a gateway data-session listener for m and a connector session to it that
// reports route ready.
func newUDPEcho(t *testing.T, m *gateway.Sessions, w *world, route string) *udpEcho {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	ln, err := tunnel.ListenQUIC(tr, gateway.QUICTLS(td, w.gw.ID, w.tunnelTLS), tunnel.NewBudget(tunnel.DefaultWindowBudget))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close(); _ = tr.Close(); _ = pc.Close() })
	go func() {
		s, err := ln.Accept(ctx)
		if err == nil {
			_ = m.Serve(ctx, s, s.PeerCertificate())
		}
	}()
	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close(); _ = cpc.Close() })
	s, err := tunnel.DialQUIC(ctx, ctr, pc.LocalAddr(), w.conTLS(w.gw.DNSName()), tunnel.NewBudget(tunnel.DefaultWindowBudget))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	control, err := s.Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.WriteMessage(control, hello(route)); err != nil {
		t.Fatal(err)
	}
	if msg := (&tunnelv1.SessionMessage{}); tunnel.ReadMessage(control, msg) != nil || msg.GetWelcome() == nil {
		t.Fatalf("no SessionWelcome: %v", msg)
	}
	go func() { // the gateway's pings and the like
		for tunnel.ReadMessage(control, &tunnelv1.SessionMessage{}) == nil {
		}
	}()
	e := &udpEcho{opens: make(chan *tunnelv1.StreamOpen, 16)}
	dg := s.Datagrams()
	go func() {
		for {
			st, err := s.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = st.Close() }()
				open := &tunnelv1.StreamOpen{}
				if tunnel.ReadMessage(st, open) != nil {
					return
				}
				e.opens <- open
				if tunnel.WriteMessage(st, &tunnelv1.StreamResult{}) != nil {
					return
				}
				id, _ := tunnel.StreamID(st)
				defer dg.Register(id, func(b []byte) { e.datagrams.Add(1); dg.Send(id, b) })()
				for {
					b, err := tunnel.ReadFrame(st)
					if err != nil || tunnel.WriteFrame(st, b) != nil {
						return
					}
					e.frames.Add(1)
				}
			}()
		}
	}()
	eventually(t, "no data session", func() bool { return m.Count()["quic"] == 1 })
	return e
}

// udpGateway serves route on a free port with metrics in reg.
func udpGateway(t *testing.T, m *gateway.Sessions, route string, idle time.Duration) (*gateway.UDPRoutes, *net.UDPAddr, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	metrics, err := tunnel.NewUDPMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	u := gateway.NewUDPRoutes(gateway.UDPOptions{Host: "127.0.0.1", Sessions: m, Metrics: metrics,
		Revision: func() *agentv1.Revision { return &agentv1.Revision{Seq: 9} }})
	t.Cleanup(u.Close)
	port := freeUDPPort(t)
	if st := u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: idle}}); len(st) != 0 {
		t.Fatalf("apply: %v", st)
	}
	return u, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}, reg
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

// client is a UDP client socket.
func client(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// exchange sends payload to addr until the echo comes back, so a datagram lost on the way does not
// fail the test.
func exchange(t *testing.T, c *net.UDPConn, addr *net.UDPAddr, payload []byte) {
	t.Helper()
	buf := make([]byte, 70000)
	for range 20 {
		if _, err := c.WriteToUDP(payload, addr); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := c.Read(buf)
		if err == nil && bytes.Equal(buf[:n], payload) {
			return
		}
	}
	t.Fatalf("no echo of %d bytes", len(payload))
}

func payload(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// counter is the value of a counter of reg with the given labels.
func counter(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	metric:
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if labels[l.GetName()] != l.GetValue() {
					continue metric
				}
			}
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

// TestUDPRoutes_Datagrams: over QUIC a payload that fits travels as a datagram and one that does
// not as a frame on the flow's stream, counted as oversize; the flow's StreamOpen names the
// client and the route.
func TestUDPRoutes_Datagrams(t *testing.T) {
	w := newWorld(t)
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: w.gw.ID, Assignment: routeAssignment{w.con.ID}})
	t.Cleanup(m.Close)
	route := ids.New("rt")
	echo := newUDPEcho(t, m, w, route)
	u, addr, reg := udpGateway(t, m, route, time.Minute)
	c := client(t)

	exchange(t, c, addr, payload(100))
	open := <-echo.opens
	src := c.LocalAddr().(*net.UDPAddr).AddrPort()
	if open.GetKind() != tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW || open.GetRouteId() != route ||
		!bytes.Equal(open.GetSrcIp(), src.Addr().AsSlice()) || open.GetSrcPort() != uint32(src.Port()) ||
		open.GetDstPort() != uint32(addr.Port) || open.GetSnapshotRev().GetSeq() != 9 { //nolint:gosec // G115: a port
		t.Fatalf("StreamOpen %v, client %v", open, src)
	}
	if echo.datagrams.Load() == 0 || echo.frames.Load() != 0 {
		t.Fatalf("a small payload: %d datagrams, %d frames", echo.datagrams.Load(), echo.frames.Load())
	}
	for _, n := range []int{3000, 60000} {
		exchange(t, c, addr, payload(n))
	}
	if echo.frames.Load() < 2 {
		t.Fatalf("large payloads: %d frames", echo.frames.Load())
	}
	if got := counter(t, reg, "rpmgr_udp_oversize_total", map[string]string{"route": route}); got < 2 {
		t.Fatalf("oversize counter %v", got)
	}
	exchange(t, c, addr, payload(1))
	if u.Flows() != 1 || len(echo.opens) != 0 {
		t.Fatalf("%d flows, %d more streams: one client is one flow", u.Flows(), len(echo.opens))
	}

	// A second client is a second flow.
	exchange(t, client(t), addr, payload(10))
	if u.Flows() != 2 {
		t.Fatalf("%d flows, want 2", u.Flows())
	}
}

// TestUDPRoutes_Frames: over the TCP transport every payload, small or large, is a frame on the
// flow's stream, and nothing counts as oversize.
func TestUDPRoutes_Frames(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-h2"): true}, routes: map[string][]string{route: {cid("udp-h2")}}}, nil)
	t.Cleanup(m.Close)
	con := start(t, m, connectorID("udp-h2"), hello(route))
	_, addr, reg := udpGateway(t, m, route, time.Minute)
	c := client(t)
	for _, n := range []int{0, 1, 1200, 3000, 60000} {
		exchange(t, c, addr, payload(n))
	}
	if open := <-con.opens; open.GetKind() != tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW {
		t.Fatalf("StreamOpen %v", open)
	}
	if got := counter(t, reg, "rpmgr_udp_oversize_total", map[string]string{"route": route}); got != 0 {
		t.Fatalf("oversize counter %v over h2", got)
	}
}

// TestUDPRoutes_Refused: a flow the connector refuses ends, and the client's next datagram opens a
// new one; without a data session a flow ends at once.
func TestUDPRoutes_Refused(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-no"): true}, routes: map[string][]string{route: {cid("udp-no")}}}, nil)
	t.Cleanup(m.Close)
	u, addr, _ := udpGateway(t, m, route, time.Minute)
	c := client(t)
	if _, err := c.WriteToUDP([]byte("x"), addr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a flow without a session stays", func() bool { return u.Flows() == 0 })

	con := start(t, m, connectorID("udp-no"), hello(route))
	con.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED))
	if _, err := c.WriteToUDP([]byte("x"), addr); err != nil {
		t.Fatal(err)
	}
	<-con.opens
	eventually(t, "a refused flow stays", func() bool { return u.Flows() == 0 })
	con.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_NO_ERROR))
	exchange(t, c, addr, []byte("again"))
}

// TestUDPRoutes_IdleExpiry: a flow without payloads in either direction for the route's flow idle
// timeout ends, with its stream.
func TestUDPRoutes_IdleExpiry(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-idle"): true}, routes: map[string][]string{route: {cid("udp-idle")}}}, nil)
	t.Cleanup(m.Close)
	start(t, m, connectorID("udp-idle"), hello(route))
	u, addr, _ := udpGateway(t, m, route, time.Second)
	exchange(t, client(t), addr, []byte("x"))
	if u.Flows() != 1 {
		t.Fatalf("%d flows", u.Flows())
	}
	eventually(t, "an idle flow stays", func() bool { return u.Flows() == 0 })
	eventually(t, "the stream of an idle flow stays", func() bool { return m.Streams() == 0 })
}

// TestUDPRoutes_QueueFull: a flow whose stream does not move drops what does not fit in its queue,
// counted, and the port goes on serving other clients.
func TestUDPRoutes_QueueFull(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-full"): true}, routes: map[string][]string{route: {cid("udp-full")}}}, nil)
	t.Cleanup(m.Close)
	con := start(t, m, connectorID("udp-full"), hello(route))
	con.stall.Store(true)
	_, addr, reg := udpGateway(t, m, route, time.Minute)
	stuck := client(t)
	big := payload(60000)
	dropped := func() float64 {
		return counter(t, reg, "rpmgr_udp_datagrams_dropped_total", map[string]string{"route": route, "reason": "queue_full"})
	}
	for deadline := time.Now().Add(10 * time.Second); dropped() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("a stalled flow never dropped")
		}
		if _, err := stuck.WriteToUDP(big, addr); err != nil {
			t.Fatal(err)
		}
	}
	<-con.opens
	con.stall.Store(false) // the next flow is answered
	exchange(t, client(t), addr, []byte("still served"))
}

// TestUDPRoutes_FlowLimit: a port keeps at most its flow limit; datagrams of further client
// addresses are dropped and counted, and the flows it has go on.
func TestUDPRoutes_FlowLimit(t *testing.T) {
	gateway.SetMaxFlows(t, 2)
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-limit"): true}, routes: map[string][]string{route: {cid("udp-limit")}}}, nil)
	t.Cleanup(m.Close)
	start(t, m, connectorID("udp-limit"), hello(route))
	u, addr, reg := udpGateway(t, m, route, time.Minute)
	a, b, c := client(t), client(t), client(t)
	exchange(t, a, addr, []byte("a"))
	exchange(t, b, addr, []byte("b"))
	if _, err := c.WriteToUDP([]byte("c"), addr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a third flow was not dropped", func() bool {
		return counter(t, reg, "rpmgr_udp_datagrams_dropped_total", map[string]string{"route": route, "reason": "flow_limit"}) == 1
	})
	if u.Flows() != 2 {
		t.Fatalf("%d flows, want 2", u.Flows())
	}
	exchange(t, a, addr, []byte("still"))
}

// TestUDPRoutes_Apply: a port whose route stays keeps its flows across snapshots, a removed one
// closes, and an occupied port is reported.
func TestUDPRoutes_Apply(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-apply"): true}, routes: map[string][]string{route: {cid("udp-apply")}}}, nil)
	t.Cleanup(m.Close)
	start(t, m, connectorID("udp-apply"), hello(route))
	u, addr, _ := udpGateway(t, m, route, time.Minute)
	c := client(t)
	exchange(t, c, addr, []byte("x"))
	port := uint16(addr.Port) //nolint:gosec // G115: a port
	if st := u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: 2 * time.Minute}}); len(st) != 0 || u.Flows() != 1 {
		t.Fatalf("an unchanged port: %v, %d flows", st, u.Flows())
	}
	exchange(t, c, addr, []byte("y"))

	taken, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	other := ids.New("rt")
	st := u.Apply([]gateway.UDPRoute{{ID: other, Port: taken.LocalAddr().(*net.UDPAddr).AddrPort().Port()}})
	if len(st) != 1 || st[0].GetResourceId() != other || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE {
		t.Fatalf("an occupied port: %v", st)
	}
	eventually(t, "a removed port keeps its flows", func() bool { return u.Flows() == 0 && m.Streams() == 0 })
	if _, err := net.ListenUDP("udp", addr); err != nil {
		t.Fatalf("a removed port is still bound: %v", err)
	}
	u.Close()
	if st := u.Apply([]gateway.UDPRoute{{ID: route, Port: port}}); st != nil {
		t.Fatalf("apply after close: %v", st)
	}
}
