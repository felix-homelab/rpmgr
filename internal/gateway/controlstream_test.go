// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// pipeStream is a tunnel.Stream over one end of a loopback TCP connection.
type pipeStream struct{ *net.TCPConn }

func (s pipeStream) SetReliableBoundary() {}
func (s pipeStream) Abort()               { _ = s.SetLinger(0); _ = s.Close() }

// streamPair returns a stream for the gateway and the connector's end of it.
func streamPair(t *testing.T) (tunnel.Stream, *net.TCPConn) {
	t.Helper()
	front, back := tcpPair(t)
	return pipeStream{back.(*net.TCPConn)}, front
}

func controlOpen(first string) *tunnelv1.OpenRequest {
	return &tunnelv1.OpenRequest{OpenId: 1, Kind: tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH, FirstChunk: []byte(first)}
}

// TestControlStreams: only CONTROL_PASSTHROUGH is carried, the first chunk ahead of the stream's
// bytes, and at most four per connector at a time; a closed one frees its place.
func TestControlStreams(t *testing.T) {
	conns := make(chan net.Conn, 8)
	c := gateway.NewControlStreams(func(conn net.Conn) { conns <- conn })
	for _, k := range []tunnelv1.StreamKind{tunnelv1.StreamKind_STREAM_KIND_TCP, tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW,
		tunnelv1.StreamKind_STREAM_KIND_DIAG, tunnelv1.StreamKind_STREAM_KIND_RELAY_OUT} {
		if code, serve := c.Decide("con_a", &tunnelv1.OpenRequest{OpenId: 1, Kind: k, RouteId: "rt_1"}); code != tunnelv1.ResultCode_RESULT_CODE_PROTOCOL || serve != nil {
			t.Errorf("%s: %s", k, code)
		}
	}

	code, serve := c.Decide("con_a", controlOpen("Client"))
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatal(code)
	}
	st, peer := streamPair(t)
	go serve(st)
	first := <-conns
	if _, err := peer.Write([]byte("Hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 11)
	if _, err := io.ReadFull(first, b); err != nil || string(b) != "ClientHello" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := first.Write([]byte("ServerHello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, b); err != nil || string(b) != "ServerHello" {
		t.Fatalf("%q %v", b, err)
	}

	// Four at a time; the fifth decision is OVERLOADED, and a fifth stream accepted before the
	// others were counted is reset.
	var serves []func(tunnel.Stream)
	for range 4 {
		code, serve := c.Decide("con_a", controlOpen(""))
		if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatal(code)
		}
		serves = append(serves, serve)
	}
	for _, serve := range serves[:3] {
		st, _ := streamPair(t)
		go serve(st)
		<-conns
	}
	if c.Open("con_a") != 4 {
		t.Fatalf("%d open", c.Open("con_a"))
	}
	if code, _ := c.Decide("con_a", controlOpen("")); code != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
		t.Fatalf("a fifth: %s", code)
	}
	if code, _ := c.Decide("con_b", controlOpen("")); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("another connector: %s", code)
	}
	late, latePeer := streamPair(t)
	serves[3](late)
	_ = latePeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := latePeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("a stream above the limit was carried")
	}
	_ = first.Close()
	if c.Open("con_a") != 3 {
		t.Fatalf("%d open after a close", c.Open("con_a"))
	}
	if code, _ := c.Decide("con_a", controlOpen("")); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("after a close: %s", code)
	}
}

// quicConnector is a connector's QUIC data session to a gateway serving m, after the handshake.
func quicConnector(t *testing.T, m *gateway.Sessions, w *world) *tunnel.QUICSession {
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
		if s, err := ln.Accept(ctx); err == nil {
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
	if err := tunnel.WriteMessage(control, hello()); err != nil {
		t.Fatal(err)
	}
	if msg := (&tunnelv1.SessionMessage{}); tunnel.ReadMessage(control, msg) != nil || msg.GetWelcome() == nil {
		t.Fatalf("no SessionWelcome: %v", msg)
	}
	go func() {
		for tunnel.ReadMessage(control, &tunnelv1.SessionMessage{}) == nil {
		}
	}()
	return s
}

// openOwn opens a stream from the connector with open and returns it with the gateway's answer.
func openOwn(t *testing.T, s *tunnel.QUICSession, open *tunnelv1.StreamOpen) (tunnel.Stream, tunnelv1.ResultCode, error) {
	t.Helper()
	st, err := s.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if open != nil {
		if err := tunnel.WriteMessage(st, open); err != nil {
			t.Fatal(err)
		}
	} else if _, err := st.Write([]byte{5}); err != nil { // a length, then nothing
		t.Fatal(err)
	}
	res := &tunnelv1.StreamResult{}
	err = tunnel.ReadMessage(st, res)
	return st, res.GetCode(), err
}

// TestSessions_ConnectorOpenedStreams: on QUIC a connector opens its CONTROL_PASSTHROUGH stream
// itself and gets a StreamResult; the gateway splices it, refuses other kinds and malformed opens,
// refuses everything without a decision, and resets a stream without its StreamOpen in time.
func TestSessions_ConnectorOpenedStreams(t *testing.T) {
	gateway.SetTimeouts(t, 10*time.Second, 300*time.Millisecond)
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	f := gateway.NewForward(plain.Addr().String(), nil, nil)
	t.Cleanup(f.Close)
	w := newWorld(t)
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: w.gw.ID, Assignment: routeAssignment{w.con.ID},
		OnOpenRequest: gateway.NewControlStreams(f.Serve).Decide})
	t.Cleanup(m.Close)
	s := quicConnector(t, m, w)

	st, code, err := openOwn(t, s, &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH})
	if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("CONTROL_PASSTHROUGH: %s %v", code, err)
	}
	if _, err := st.Write([]byte("through the gateway")); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	if got, err := io.ReadAll(st); err != nil || string(got) != "through the gateway" {
		t.Fatalf("spliced: %q %v", got, err)
	}

	for _, tc := range []struct {
		open *tunnelv1.StreamOpen
		want tunnelv1.ResultCode
	}{
		{&tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: "rt_1"}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{&tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_DIAG}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{&tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_RELAY_OUT}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{&tunnelv1.StreamOpen{}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
		{&tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP}, tunnelv1.ResultCode_RESULT_CODE_PROTOCOL},
	} {
		if _, code, err := openOwn(t, s, tc.open); err != nil || code != tc.want {
			t.Errorf("%v: %s %v, want %s", tc.open, code, err, tc.want)
		}
	}
	if _, _, err := openOwn(t, s, nil); err == nil {
		t.Error("a stream without StreamOpen was answered")
	}

	other := newWorld(t)
	none := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: other.gw.ID, Assignment: routeAssignment{other.con.ID}})
	t.Cleanup(none.Close)
	if _, code, err := openOwn(t, quicConnector(t, none, other), &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH}); err != nil ||
		code != tunnelv1.ResultCode_RESULT_CODE_UNAUTHORIZED {
		t.Errorf("without a decision: %s %v", code, err)
	}
}
