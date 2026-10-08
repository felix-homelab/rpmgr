// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// assignment is a gateway snapshot's view of connectors that a test can change.
type assignment struct {
	mu     sync.Mutex
	known  map[string]bool
	routes map[string][]string
}

func (a *assignment) Known(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.known[id]
}

func (a *assignment) Connectors(route string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.routes[route]
}

func (a *assignment) forget(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.known, id)
}

var (
	testOrg = ids.New("org")
	names   sync.Map
)

// cid is the connector ID a test calls name.
func cid(name string) string {
	id, _ := names.LoadOrStore(name, ids.New("con"))
	return id.(string)
}

func connectorID(name string) pki.Identity {
	return pki.Identity{TrustDomain: td, Org: testOrg, Kind: pki.KindConnector, ID: cid(name)}
}

// certOf is a peer certificate with only the identity's URI, which is all Sessions reads; the
// TLS handshake that verified it is the tunnel's and the router's.
func certOf(id pki.Identity) *x509.Certificate {
	return &x509.Certificate{URIs: []*url.URL{id.SPIFFE()}}
}

// h2Session is a reverse HTTP/2 session over loopback TCP.
func h2Session(t *testing.T) (*tunnel.H2Gateway, *tunnel.H2Connector) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	dialled, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	con := tunnel.ServeH2Connector(dialled, tunnel.DefaultH2Windows())
	gw, err := tunnel.NewH2Gateway(<-accepted, tunnel.DefaultH2Windows())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close(); _ = con.Close() })
	return gw, con
}

// connector is the connector's end of one data session: it answers every stream with the code in
// answer, then echoes.
type connector struct {
	control tunnel.Stream
	welcome *tunnelv1.SessionWelcome
	msgs    chan *tunnelv1.SessionMessage // from the gateway, after the welcome
	opens   chan *tunnelv1.StreamOpen     // the streams the gateway opened
	served  chan error                    // Serve's result
	answer  atomic.Int32
	silent  atomic.Bool // accept streams but never answer
	stall   atomic.Bool // accept streams but neither answer nor read until the test ends
	unstall chan struct{}
	cancel  context.CancelFunc
}

func (c *connector) send(t *testing.T, msg *tunnelv1.SessionMessage) {
	t.Helper()
	if err := tunnel.WriteMessage(c.control, msg); err != nil {
		t.Fatal(err)
	}
}

// health reports a route's readiness and waits until the gateway has read it: the control stream
// is read in order, so a Pong after it means it took effect.
func (c *connector) health(t *testing.T, route string, ready bool) {
	t.Helper()
	c.send(t, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_RouteHealth{RouteHealth: &tunnelv1.RouteHealth{RouteId: route, Ready: ready}}})
	c.send(t, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Ping{Ping: &tunnelv1.Ping{Seq: 99}}})
	if msg := <-c.msgs; msg.GetPong().GetSeq() != 99 {
		t.Fatalf("got %v, want Pong{99}", msg)
	}
}

// serveErr waits for Serve to return.
func (c *connector) serveErr(t *testing.T) error {
	t.Helper()
	select {
	case err := <-c.served:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
		return nil
	}
}

// start runs Serve for the gateway's end of a new session from the connector id and answers the
// handshake with hello as the first message.
func start(t *testing.T, m *gateway.Sessions, id pki.Identity, first *tunnelv1.SessionMessage) *connector {
	t.Helper()
	gw, con := h2Session(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &connector{msgs: make(chan *tunnelv1.SessionMessage, 16), opens: make(chan *tunnelv1.StreamOpen, 16),
		served: make(chan error, 1), cancel: cancel, unstall: make(chan struct{})}
	t.Cleanup(func() { close(c.unstall) })
	go func() { c.served <- m.Serve(ctx, gw, certOf(id)) }()
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	control, err := con.Control(cctx)
	if err != nil {
		t.Fatalf("no session control stream: %v", err)
	}
	c.control = control
	if first == nil {
		return c
	}
	c.send(t, first)
	if first.GetHello() == nil {
		return c
	}
	msg := &tunnelv1.SessionMessage{}
	if err := tunnel.ReadMessage(control, msg); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("no SessionWelcome: %v %v", msg, err)
	}
	c.welcome = msg.GetWelcome()
	go func() {
		for {
			msg := &tunnelv1.SessionMessage{}
			if tunnel.ReadMessage(control, msg) != nil {
				close(c.msgs)
				return
			}
			c.msgs <- msg
		}
	}()
	go func() {
		for {
			st, err := con.AcceptStream(ctx)
			if err != nil {
				return
			}
			go c.handle(st)
		}
	}()
	return c
}

func (c *connector) handle(st tunnel.Stream) {
	defer func() { _ = st.Close() }()
	open := &tunnelv1.StreamOpen{}
	if tunnel.ReadMessage(st, open) != nil {
		return
	}
	c.opens <- open
	if c.stall.Load() {
		<-c.unstall
		return
	}
	if c.silent.Load() {
		_, _ = io.Copy(io.Discard, st)
		return
	}
	code := tunnelv1.ResultCode(c.answer.Load())
	if tunnel.WriteMessage(st, &tunnelv1.StreamResult{Code: code}) != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		return
	}
	_, _ = io.Copy(st, st)
	_ = st.CloseWrite()
}

func hello(ready ...string) *tunnelv1.SessionMessage {
	return &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Hello{Hello: &tunnelv1.SessionHello{ReadyRoutes: ready}}}
}

func newSessions(a *assignment, denied func(*x509.Certificate) bool) *gateway.Sessions {
	return gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: a, Denied: denied})
}

// eventually retries f for up to 5 s.
func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatal(what)
}

// TestSessions_Admission: a data session is admitted only from a connector of this trust domain
// that the snapshot knows and the deny-list does not name.
func TestSessions_Admission(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_ok"): true, cid("con_denied"): true}}
	m := newSessions(a, func(c *x509.Certificate) bool {
		id, err := pki.ParseSPIFFE(c.URIs[0], td)
		return err == nil && id.ID == cid("con_denied")
	})
	refused := func(name string, peer *x509.Certificate) error {
		t.Helper()
		gw, _ := h2Session(t)
		err := m.Serve(context.Background(), gw, peer)
		if err == nil {
			t.Fatalf("%s: admitted", name)
		}
		return err
	}
	if err := refused("denied", certOf(connectorID("con_denied"))); !errors.Is(err, pki.ErrDenied) {
		t.Fatalf("a denied connector: %v, want ErrDenied", err)
	}
	_ = refused("unknown", certOf(connectorID("con_unknown")))
	_ = refused("a gateway", certOf(pki.Identity{TrustDomain: td, Org: testOrg, Kind: pki.KindGateway, ID: ids.New("gw")}))
	other := connectorID("con_ok")
	other.TrustDomain = "rpmgr-0th3r000"
	_ = refused("another trust domain", certOf(other))
	_ = refused("no certificate", nil)
	_ = refused("no URI", &x509.Certificate{})

	c := start(t, m, connectorID("con_ok"), hello())
	if c.welcome.GetGatewayId() != "gw_01" {
		t.Fatalf("welcome %v", c.welcome)
	}
	if got := m.Count(); got["h2"] != 1 || len(got) != 1 {
		t.Fatalf("count %v", got)
	}
	c.send(t, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Ping{Ping: &tunnelv1.Ping{Seq: 7}}})
	if msg := <-c.msgs; msg.GetPong().GetSeq() != 7 {
		t.Fatalf("answer to Ping{7}: %v", msg)
	}
	c.send(t, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Goodbye{Goodbye: &tunnelv1.Goodbye{}}})
	if err := c.serveErr(t); err != nil {
		t.Fatalf("after Goodbye: %v", err)
	}
	eventually(t, "the session is still counted", func() bool { return len(m.Count()) == 0 })
}

// TestSessions_Hello: the first message must be SessionHello, and it must come in time.
func TestSessions_Hello(t *testing.T) {
	gateway.SetTimeouts(t, 200*time.Millisecond, time.Second)
	a := &assignment{known: map[string]bool{cid("con_1"): true}}
	m := newSessions(a, nil)
	c := start(t, m, connectorID("con_1"), &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Ping{Ping: &tunnelv1.Ping{Seq: 1}}})
	if err := c.serveErr(t); err == nil {
		t.Fatal("a session that started with Ping was admitted")
	}
	c = start(t, m, connectorID("con_1"), nil)
	if err := c.serveErr(t); err == nil {
		t.Fatal("a session without SessionHello was admitted")
	}
	if len(m.Count()) != 0 {
		t.Fatal("a refused session is counted")
	}
}

// TestSessions_ReadinessGatesStreams: streams for a route open only on sessions of connectors the
// snapshot assigns to it that reported it ready; an unassigned route is never opened.
func TestSessions_ReadinessGatesStreams(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_1"): true}, routes: map[string][]string{"r1": {cid("con_1")}}}
	m := newSessions(a, nil)
	c := start(t, m, connectorID("con_1"), hello("r2"))
	ctx := context.Background()
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a route not reported ready: %v", err)
	}
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r2"}); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a route the snapshot does not assign: %v", err)
	}
	c.health(t, "r1", true)
	st, code, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"})
	if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("a ready route: %s %v", code, err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	if b, err := io.ReadAll(st); err != nil || string(b) != "ping" {
		t.Fatalf("echo %q %v", b, err)
	}
	_ = st.Close()
	if open := <-c.opens; open.GetRouteId() != "r1" {
		t.Fatalf("the connector got %v", open)
	}
	c.health(t, "r1", false)
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a route reported not ready again: %v", err)
	}
	select {
	case open := <-c.opens:
		t.Fatalf("a stream reached the connector: %v", open)
	default:
	}
}

// TestSessions_Retry: DRAINING and OVERLOADED are retried once on another session; other codes
// and a single session are not retried.
func TestSessions_Retry(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_1"): true, cid("con_2"): true}, routes: map[string][]string{"r1": {cid("con_1"), cid("con_2")}}}
	m := newSessions(a, nil)
	c1 := start(t, m, connectorID("con_1"), hello("r1"))
	c2 := start(t, m, connectorID("con_2"), hello("r1"))
	ctx := context.Background()
	drain := func(c *connector) int {
		n := 0
		for {
			select {
			case <-c.opens:
				n++
			case <-time.After(100 * time.Millisecond):
				return n
			}
		}
	}

	// One session answers OVERLOADED: every open ends on the other.
	c1.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_OVERLOADED))
	for range 10 {
		st, code, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"})
		if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("%s %v", code, err)
		}
		_ = st.Close()
	}
	if n := drain(c2); n != 10 {
		t.Fatalf("%d of 10 streams on the session that accepts", n)
	}
	drain(c1)

	// Both DRAINING: two attempts, one per session, then the code.
	c2.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_DRAINING))
	c1.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_DRAINING))
	if st, code, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); st != nil || err != nil || code != tunnelv1.ResultCode_RESULT_CODE_DRAINING {
		t.Fatalf("%v %s %v", st, code, err)
	}
	if n1, n2 := drain(c1), drain(c2); n1 != 1 || n2 != 1 {
		t.Fatalf("attempts %d and %d, want one per session", n1, n2)
	}

	// Another code is final.
	c1.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED))
	c2.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED))
	if _, code, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); err != nil || code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("%s %v", code, err)
	}
	if n := drain(c1) + drain(c2); n != 1 {
		t.Fatalf("%d attempts for UPSTREAM_REFUSED", n)
	}

	// A single session: OVERLOADED once, with no other session to try.
	a.mu.Lock()
	a.routes["r1"] = []string{cid("con_1")}
	a.mu.Unlock()
	c1.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_OVERLOADED))
	if _, code, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); err != nil || code != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
		t.Fatalf("%s %v", code, err)
	}
	if n := drain(c1); n != 1 {
		t.Fatalf("%d attempts on the only session", n)
	}
}

// TestSessions_ResultTimeout: a connector that never answers StreamOpen holds the open for the
// result timeout, not longer; a cancelled context ends the wait at once.
func TestSessions_ResultTimeout(t *testing.T) {
	gateway.SetTimeouts(t, time.Second, 300*time.Millisecond)
	a := &assignment{known: map[string]bool{cid("con_1"): true}, routes: map[string][]string{"r1": {cid("con_1")}}}
	m := newSessions(a, nil)
	c := start(t, m, connectorID("con_1"), hello("r1"))
	c.silent.Store(true)
	begin := time.Now()
	if _, _, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrResultTimeout) {
		t.Fatalf("%v, want ErrResultTimeout", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Fatalf("took %s", d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v, want the context's error", err)
	}
}

// TestSessions_Drain: Drain tells every session its deadline and from then on admits no session
// and opens no stream.
func TestSessions_Drain(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_1"): true, cid("con_2"): true}, routes: map[string][]string{"r1": {cid("con_1")}}}
	m := newSessions(a, nil)
	c := start(t, m, connectorID("con_1"), hello("r1"))
	deadline := time.Now().Add(gateway.DrainPeriod).Truncate(time.Second)
	m.Drain(deadline)
	msg := <-c.msgs
	if !msg.GetDrain().GetDeadline().AsTime().Equal(deadline) {
		t.Fatalf("got %v, want Drain until %s", msg, deadline)
	}
	if _, _, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrDraining) {
		t.Fatalf("open while draining: %v", err)
	}
	gw, _ := h2Session(t)
	if err := m.Serve(context.Background(), gw, certOf(connectorID("con_2"))); !errors.Is(err, gateway.ErrDraining) {
		t.Fatalf("a new session while draining: %v", err)
	}
	m.Close()
	if err := c.serveErr(t); err == nil {
		t.Fatal("Close: the session ended without an error")
	}
}

// TestSessions_Recheck: a connector the deny-list names or the snapshot drops loses its live
// sessions at the next Recheck; the others keep theirs.
func TestSessions_Recheck(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_1"): true, cid("con_2"): true, cid("con_3"): true}}
	var denied sync.Map
	m := newSessions(a, func(c *x509.Certificate) bool {
		id, err := pki.ParseSPIFFE(c.URIs[0], td)
		_, ok := denied.Load(id.ID)
		return err == nil && ok
	})
	c1 := start(t, m, connectorID("con_1"), hello())
	c2 := start(t, m, connectorID("con_2"), hello())
	c3 := start(t, m, connectorID("con_3"), hello())
	m.Recheck()
	denied.Store(cid("con_1"), true)
	a.forget(cid("con_2"))
	m.Recheck()
	_ = c1.serveErr(t)
	_ = c2.serveErr(t)
	eventually(t, "the closed sessions are still counted", func() bool { return m.Count()["h2"] == 1 })
	select {
	case err := <-c3.served:
		t.Fatalf("an admitted connector lost its session: %v", err)
	default:
	}
	c3.cancel()
	_ = c3.serveErr(t)
	eventually(t, "a cancelled session is still counted", func() bool { return len(m.Count()) == 0 })
}

// TestSessions_DroppedConnectorKeepsStreams: a connector the snapshot drops keeps its session while
// a stream is open, gets no new stream, and loses the session when the stream ends, or at the end
// of the drain period; one assigned again in time keeps it.
func TestSessions_DroppedConnectorKeepsStreams(t *testing.T) {
	gateway.SetUnassignedDrain(t, 2*time.Second)
	a := &assignment{known: map[string]bool{cid("con_4"): true}, routes: map[string][]string{"r1": {cid("con_4")}}}
	m := newSessions(a, nil)
	c := start(t, m, connectorID("con_4"), hello("r1"))
	ctx := context.Background()
	open := func() tunnel.Stream {
		t.Helper()
		st, code, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"})
		if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("%s %v", code, err)
		}
		return st
	}
	echoOnce := func(st tunnel.Stream, msg string) {
		t.Helper()
		if _, err := st.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(msg))
		if _, err := io.ReadFull(st, b); err != nil || string(b) != msg {
			t.Fatalf("echo %q %v", b, err)
		}
	}

	// Dropped while a stream is open: the stream works on, no new stream opens.
	st := open()
	a.mu.Lock()
	delete(a.known, cid("con_4"))
	a.routes = map[string][]string{}
	a.mu.Unlock()
	m.Recheck()
	time.Sleep(300 * time.Millisecond)
	echoOnce(st, "still here")
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a new stream for a dropped connector: %v", err)
	}
	_ = st.CloseWrite()
	_, _ = io.ReadAll(st)
	_ = st.Close()
	if err := c.serveErr(t); err == nil {
		t.Fatal("the session ended without an error")
	}

	// Dropped and assigned again before the stream ends: the session stays.
	a.mu.Lock()
	a.known[cid("con_4")], a.routes["r1"] = true, []string{cid("con_4")}
	a.mu.Unlock()
	c = start(t, m, connectorID("con_4"), hello("r1"))
	st = open()
	a.forget(cid("con_4"))
	m.Recheck()
	time.Sleep(300 * time.Millisecond)
	a.mu.Lock()
	a.known[cid("con_4")] = true
	a.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	_ = st.Close()
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-c.served:
		t.Fatalf("a connector assigned again lost its session: %v", err)
	default:
	}

	// Dropped with a stream that never ends: closed at the end of the drain period.
	st = open()
	a.forget(cid("con_4"))
	begin := time.Now()
	m.Recheck()
	_ = c.serveErr(t)
	if d := time.Since(begin); d < 1500*time.Millisecond || d > 4*time.Second {
		t.Fatalf("closed after %s, want the 2 s drain period", d)
	}
	_ = st.Close()
}
