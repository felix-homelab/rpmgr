// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
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
	ranked map[string][]gateway.RouteConnector // instead of routes where set
}

func (a *assignment) Known(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.known[id]
}

func (a *assignment) Connectors(route string) []gateway.RouteConnector {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r, ok := a.ranked[route]; ok {
		return r
	}
	var out []gateway.RouteConnector
	for _, c := range a.routes[route] {
		out = append(out, gateway.RouteConnector{ID: c, Weight: 1})
	}
	return out
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

// goodbye ends the session. The gateway closes it as soon as it reads the Goodbye, which can be
// before the write learns that its frame went out; the write then reports the closed connection, so
// its error says nothing and serveErr checks that the gateway took the Goodbye.
func (c *connector) goodbye() {
	_ = tunnel.WriteMessage(c.control, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Goodbye{Goodbye: &tunnelv1.Goodbye{}}})
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

// healthAt reports a route ready at the priorities with a healthy target, and waits until the
// gateway has read it.
func (c *connector) healthAt(t *testing.T, route string, prios ...uint32) {
	t.Helper()
	c.send(t, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_RouteHealth{RouteHealth: &tunnelv1.RouteHealth{RouteId: route, Ready: true,
		ReadyPriorities: prios}}})
	c.send(t, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Ping{Ping: &tunnelv1.Ping{Seq: 98}}})
	if msg := <-c.msgs; msg.GetPong().GetSeq() != 98 {
		t.Fatalf("got %v, want Pong{98}", msg)
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
	if first.GetHello() == nil {
		// The gateway refuses any other first message and may close the session before the
		// write's flush returns, so the write's error says nothing; serveErr checks the refusal.
		_ = tunnel.WriteMessage(control, first)
		return c
	}
	c.send(t, first)
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
	c.goodbye()
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

// TestSessions_Retry: DRAINING and OVERLOADED are retried on another session, UPSTREAM_REFUSED and
// UPSTREAM_TIMEOUT on another connector (D90); other codes and a single session are not retried.
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

	// A target that refuses or does not answer: the other connector is tried once, then the code.
	for _, code := range []tunnelv1.ResultCode{tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT} {
		c1.answer.Store(int32(code))
		c2.answer.Store(int32(code))
		if st, got, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); st != nil || err != nil || got != code {
			t.Fatalf("%v %s %v", st, got, err)
		}
		if n1, n2 := drain(c1), drain(c2); n1 != 1 || n2 != 1 {
			t.Fatalf("%s: attempts %d and %d, want one per connector", code, n1, n2)
		}
	}

	// Another code is final.
	c1.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_PROTOCOL))
	c2.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_PROTOCOL))
	if _, code, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); err != nil || code != tunnelv1.ResultCode_RESULT_CODE_PROTOCOL {
		t.Fatalf("%s %v", code, err)
	}
	if n := drain(c1) + drain(c2); n != 1 {
		t.Fatalf("%d attempts for PROTOCOL", n)
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

// TestSessions_Disable (R22): a disabled gateway tells its sessions to move with the drain
// deadline; they keep their open streams although the snapshot no longer assigns their connector,
// and close at the deadline. Until Enable no session or stream is admitted, and a second Disable
// changes no deadline. Enabled again, the gateway admits new sessions, while a drained session
// opens no stream.
func TestSessions_Disable(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_1"): true, cid("con_2"): true}, routes: map[string][]string{"r1": {cid("con_1")}}}
	m := newSessions(a, nil)
	c1 := start(t, m, connectorID("con_1"), hello("r1"))
	ctx := context.Background()
	st, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	echo := func(s string) error {
		if _, err := st.Write([]byte(s)); err != nil {
			return err
		}
		b := make([]byte, len(s))
		if _, err := io.ReadFull(st, b); err != nil || string(b) != s {
			return fmt.Errorf("echo %q: %w", b, err)
		}
		return nil
	}
	if err := echo("before"); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	m.Disable(time.Second)
	msg := <-c1.msgs
	if d := msg.GetDrain(); d.GetReason() != "gateway disabled" || d.GetDeadline().AsTime().Before(begin.Add(time.Second)) ||
		d.GetDeadline().AsTime().After(time.Now().Add(time.Second)) {
		t.Fatalf("got %v, want Drain with a deadline in 1 s", msg)
	}
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrDraining) {
		t.Fatalf("a stream while disabled: %v", err)
	}
	gw, _ := h2Session(t)
	if err := m.Serve(ctx, gw, certOf(connectorID("con_2"))); !errors.Is(err, gateway.ErrDraining) {
		t.Fatalf("a new session while disabled: %v", err)
	}
	a.forget(cid("con_1"))
	m.Recheck()
	m.Disable(time.Hour)
	if err := echo("after"); err != nil {
		t.Fatalf("the open stream after the drain began: %v", err)
	}
	select {
	case msg := <-c1.msgs:
		t.Fatalf("a second message: %v", msg)
	case err := <-c1.served:
		t.Fatalf("the session ended before its deadline: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_ = c1.serveErr(t)
	if took := time.Since(begin); took < 900*time.Millisecond {
		t.Fatalf("the session closed after %s, before its deadline", took)
	}

	a.mu.Lock()
	a.known[cid("con_1")] = true
	a.mu.Unlock()
	m.Enable()
	old := start(t, m, connectorID("con_1"), hello("r1"))
	m.Disable(time.Hour)
	<-old.msgs
	m.Enable()
	if _, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a stream on a drained session: %v", err)
	}
	fresh := start(t, m, connectorID("con_1"), hello("r1"))
	if fresh.welcome == nil {
		t.Fatal("no session admitted after Enable")
	}
	if st, _, err := m.OpenStream(ctx, &tunnelv1.StreamOpen{RouteId: "r1"}); err != nil {
		t.Fatalf("a stream after Enable: %v", err)
	} else {
		_ = st.Close()
	}
	<-fresh.opens
	select {
	case open := <-old.opens:
		t.Fatalf("the drained session got a stream: %v", open)
	default:
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

// TestSessions_ConnectorCap: a connector holds at most MaxConnectorSessions data sessions to a
// gateway; one more is refused before its handshake, another connector is not affected, and a
// session that ends frees a slot.
func TestSessions_ConnectorCap(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_busy"): true, cid("con_other"): true}}
	m := newSessions(a, nil)
	busy := connectorID("con_busy")
	var held []*connector
	for range gateway.MaxConnectorSessions {
		held = append(held, start(t, m, busy, hello()))
	}
	if got := m.Count()["h2"]; got != gateway.MaxConnectorSessions {
		t.Fatalf("%d sessions admitted, want %d", got, gateway.MaxConnectorSessions)
	}
	gw, _ := h2Session(t)
	if err := m.Serve(context.Background(), gw, certOf(busy)); !errors.Is(err, gateway.ErrSessionCap) {
		t.Fatalf("one session more: %v, want ErrSessionCap", err)
	}
	other := start(t, m, connectorID("con_other"), hello())
	if other.welcome.GetGatewayId() != "gw_01" {
		t.Fatalf("another connector: %v", other.welcome)
	}

	held[0].goodbye()
	if err := held[0].serveErr(t); err != nil {
		t.Fatal(err)
	}
	busyLeft, others := gateway.MaxConnectorSessions-1, 1
	eventually(t, "the ended session still counts", func() bool { return m.Count()["h2"] == busyLeft+others })
	if again := start(t, m, busy, hello()); again.welcome == nil {
		t.Fatal("no session after one ended")
	}
}

// TestSessions_ConnectorRestart: a session of a new start of the connector, with another boot_id,
// closes the sessions of the earlier start at once, so that they neither take streams nor fill the
// cap; sessions of the same start, of another connector, or without a boot_id stay.
func TestSessions_ConnectorRestart(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_r"): true, cid("con_o"): true},
		routes: map[string][]string{"r1": {cid("con_r")}}}
	m := newSessions(a, nil)
	booted := func(boot string) *tunnelv1.SessionMessage {
		h := hello("r1")
		h.GetHello().BootId = boot
		return h
	}
	id := connectorID("con_r")
	var first []*connector
	for range gateway.MaxConnectorSessions - 2 {
		first = append(first, start(t, m, id, booted("boot-1")))
	}
	unnamed := start(t, m, id, hello("r1")) // an agent that names no boot_id
	other := start(t, m, connectorID("con_o"), booted("boot-1"))
	if got := m.Count()["h2"]; got != gateway.MaxConnectorSessions {
		t.Fatalf("%d sessions before the restart, want %d", got, gateway.MaxConnectorSessions)
	}

	// The restarted connector gets its session although the earlier start held all but one slot.
	again := start(t, m, id, booted("boot-2"))
	for _, c := range first {
		_ = c.serveErr(t) // closed: its error says only how the close reached the read
	}
	eventually(t, "the earlier start's sessions still count", func() bool { return m.Count()["h2"] == 3 })
	for range 3 {
		st, code, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"})
		if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("a stream after the restart: %s %v", code, err)
		}
		_ = st.Close()
		select {
		case <-again.opens:
		case <-unnamed.opens:
		case <-time.After(5 * time.Second):
			t.Fatal("the stream reached no live session")
		}
	}
	more := start(t, m, id, booted("boot-2"))
	select {
	case err := <-again.served:
		t.Fatalf("a session of the same start ended: %v", err)
	case err := <-unnamed.served:
		t.Fatalf("a session without a boot_id ended: %v", err)
	case err := <-other.served:
		t.Fatalf("another connector's session ended: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if more.welcome == nil || m.Count()["h2"] != 4 {
		t.Fatalf("a second session of the new start: %v, %d sessions", more.welcome, m.Count()["h2"])
	}
}

// TestSessions_Ranks: streams go to the connectors of the lowest priority with a ready session, in
// the share of their weights, 0 counting as 1; a lower priority takes them only when no connector
// of a better one is ready (D90).
func TestSessions_Ranks(t *testing.T) {
	con1, con2, con3 := cid("rank_1"), cid("rank_2"), cid("rank_3")
	a := &assignment{known: map[string]bool{con1: true, con2: true, con3: true}, ranked: map[string][]gateway.RouteConnector{
		"r1": {{ID: con1, Weight: 1}, {ID: con2, Weight: 3}, {ID: con3, Priority: 10, Weight: 100}}}}
	m := newSessions(a, nil)
	cs := []*connector{start(t, m, connectorID("rank_1"), hello("r1")), start(t, m, connectorID("rank_2"), hello("r1")),
		start(t, m, connectorID("rank_3"), hello("r1"))}
	count := func(n int) [3]int {
		t.Helper()
		var got [3]int
		for range n {
			st, code, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"})
			if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
				t.Fatalf("%s %v", code, err)
			}
			select {
			case <-cs[0].opens:
				got[0]++
			case <-cs[1].opens:
				got[1]++
			case <-cs[2].opens:
				got[2]++
			case <-time.After(5 * time.Second):
				t.Fatal("no stream reached a connector")
			}
			_ = st.Close()
		}
		return got
	}

	// Weights 1 and 3 share priority 0; the connector of priority 10 gets nothing.
	got := count(400)
	if share := float64(got[1]) / 400; got[2] != 0 || share < 0.65 || share > 0.85 {
		t.Fatalf("streams per connector %v, want about 100, 300 and 0", got)
	}

	// Priority 0 not ready: priority 10 takes every stream.
	cs[0].health(t, "r1", false)
	cs[1].health(t, "r1", false)
	if got := count(20); got != [3]int{0, 0, 20} {
		t.Fatalf("streams per connector %v with priority 0 not ready", got)
	}

	// Ready again, with weights of 0: both share priority 0 alike.
	cs[0].health(t, "r1", true)
	cs[1].health(t, "r1", true)
	a.mu.Lock()
	a.ranked["r1"] = []gateway.RouteConnector{{ID: con1}, {ID: con2}, {ID: con3, Priority: 10, Weight: 100}}
	a.mu.Unlock()
	if got := count(100); got[0] < 25 || got[1] < 25 || got[2] != 0 {
		t.Fatalf("streams per connector %v with weights of 0", got)
	}
}

// TestSessions_Fallback: a target that refuses or does not answer passes the stream to another
// entry, of the same priority first, then of the next, which may be the same connector at a worse
// priority; an entry is tried once whatever its connector's sessions, an open tries at most four,
// and a route's only entry is not tried again (D90).
func TestSessions_Fallback(t *testing.T) {
	names := []string{"fb_1", "fb_2", "fb_3", "fb_4", "fb_5"}
	a := &assignment{known: map[string]bool{}, ranked: map[string][]gateway.RouteConnector{}}
	for _, n := range names {
		a.known[cid(n)] = true
	}
	a.ranked["r1"] = []gateway.RouteConnector{{ID: cid("fb_1"), Weight: 1}, {ID: cid("fb_2"), Priority: 5, Weight: 1}}
	m := newSessions(a, nil)
	c1a, c1b := start(t, m, connectorID("fb_1"), hello("r1")), start(t, m, connectorID("fb_1"), hello("r1"))
	c2 := start(t, m, connectorID("fb_2"), hello("r1"))
	c3, c4 := start(t, m, connectorID("fb_3"), hello("r1")), start(t, m, connectorID("fb_4"), hello("r1"))
	c5 := start(t, m, connectorID("fb_5"), hello("r1"))
	drain := func(cs ...*connector) int {
		n := 0
		for _, c := range cs {
			for done := false; !done; {
				select {
				case <-c.opens:
					n++
				case <-time.After(100 * time.Millisecond):
					done = true
				}
			}
		}
		return n
	}
	open := func() (tunnel.Stream, tunnelv1.ResultCode) {
		t.Helper()
		st, code, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"})
		if err != nil {
			t.Fatal(err)
		}
		return st, code
	}
	// rank sets the route's entries, after the snapshot without them made the gateway forget what
	// passive health learnt of them, so each step starts afresh.
	rank := func(entries ...gateway.RouteConnector) {
		a.mu.Lock()
		a.ranked["r1"] = nil
		a.mu.Unlock()
		m.Recheck()
		a.mu.Lock()
		a.ranked["r1"] = entries
		a.mu.Unlock()
	}

	// Priority 0's connector refuses on both its sessions: each stream tries it once, then priority
	// 5, until passive health passes over it after its third refusal in a row.
	for _, code := range []tunnelv1.ResultCode{tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT} {
		rank(gateway.RouteConnector{ID: cid("fb_1"), Weight: 1}, gateway.RouteConnector{ID: cid("fb_2"), Priority: 5, Weight: 1})
		c1a.answer.Store(int32(code))
		c1b.answer.Store(int32(code))
		for range 5 {
			st, got := open()
			if got != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
				t.Fatalf("%s from fb_1: %s, want the stream on fb_2", code, got)
			}
			_ = st.Close()
		}
		if n1, n2 := drain(c1a, c1b), drain(c2); n1 != 3 || n2 != 5 {
			t.Fatalf("%s: %d attempts on fb_1 and %d on fb_2, want 3 and 5", code, n1, n2)
		}
	}

	// Five connectors of one priority that all refuse: four attempts, then the code.
	rank(gateway.RouteConnector{ID: cid("fb_1")}, gateway.RouteConnector{ID: cid("fb_2")}, gateway.RouteConnector{ID: cid("fb_3")},
		gateway.RouteConnector{ID: cid("fb_4")}, gateway.RouteConnector{ID: cid("fb_5")})
	for _, c := range []*connector{c1a, c1b, c2, c3, c4, c5} {
		c.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED))
	}
	if st, got := open(); st != nil || got != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("%v %s, want UPSTREAM_REFUSED", st, got)
	}
	if n := drain(c1a, c1b, c2, c3, c4, c5); n != 4 {
		t.Fatalf("%d attempts, want 4", n)
	}

	// One connector at priorities 0 and 5, another at 0: a refusal at fb_1's priority 0 goes to
	// fb_2's priority 0 before fb_1's priority 5, and each stream names its entry's priority.
	rank(gateway.RouteConnector{ID: cid("fb_1"), Weight: 1, Ranked: true}, gateway.RouteConnector{ID: cid("fb_1"), Priority: 5, Weight: 1, Ranked: true},
		gateway.RouteConnector{ID: cid("fb_2"), Weight: 1, Ranked: true})
	c2.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_NO_ERROR))
	priorities := func(cs ...*connector) []uint32 {
		var out []uint32
		for _, c := range cs {
			for done := false; !done; {
				select {
				case o := <-c.opens:
					if o.TargetPriority == nil {
						t.Fatal("a ranked entry's stream names no priority")
					}
					out = append(out, o.GetTargetPriority())
				case <-time.After(100 * time.Millisecond):
					done = true
				}
			}
		}
		return out
	}
	for range 10 {
		st, got := open()
		if got != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("%s, want the stream on fb_2", got)
		}
		_ = st.Close()
	}
	if p1, p2 := priorities(c1a, c1b), priorities(c2); slices.Contains(p1, 5) || len(p2) != 10 || slices.ContainsFunc(p2, func(p uint32) bool { return p != 0 }) {
		t.Fatalf("priorities named to fb_1 %v and fb_2 %v, want fb_1 at 0 only and fb_2 at 0 ten times", p1, p2)
	}
	// Without fb_2, fb_1's priority 5 is the next entry.
	rank(gateway.RouteConnector{ID: cid("fb_1"), Weight: 1, Ranked: true}, gateway.RouteConnector{ID: cid("fb_1"), Priority: 5, Weight: 1, Ranked: true})
	if st, got := open(); st != nil || got != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("%v %s, want UPSTREAM_REFUSED", st, got)
	}
	if got := priorities(c1a, c1b); !slices.Equal(got, []uint32{0, 5}) && !slices.Equal(got, []uint32{5, 0}) {
		t.Fatalf("priorities named to fb_1 %v, want 0 then 5", got)
	}

	// The route's only entry refuses: no other attempt, not even on its connector's other session;
	// an unranked entry names no priority.
	rank(gateway.RouteConnector{ID: cid("fb_1"), Weight: 1})
	if st, got := open(); st != nil || got != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED {
		t.Fatalf("%v %s, want UPSTREAM_REFUSED", st, got)
	}
	var opens []*tunnelv1.StreamOpen
	for _, c := range []*connector{c1a, c1b} {
		for done := false; !done; {
			select {
			case o := <-c.opens:
				opens = append(opens, o)
			case <-time.After(100 * time.Millisecond):
				done = true
			}
		}
	}
	if len(opens) != 1 || opens[0].TargetPriority != nil {
		t.Fatalf("streams %v on the only entry, want one that names no priority", opens)
	}
}

// TestSessions_UDPFlowNamesNoPriority: a UDP flow sends before its answer and is not retried on
// another entry, so it names no priority and the connector falls through its own targets (D90).
func TestSessions_UDPFlowNamesNoPriority(t *testing.T) {
	con := cid("udp_1")
	a := &assignment{known: map[string]bool{con: true}, ranked: map[string][]gateway.RouteConnector{
		"r1": {{ID: con, Weight: 1, Ranked: true}, {ID: con, Priority: 5, Weight: 1, Ranked: true}}}}
	m := newSessions(a, nil)
	c := start(t, m, connectorID("udp_1"), hello("r1"))
	for _, kind := range []tunnelv1.StreamKind{tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW, tunnelv1.StreamKind_STREAM_KIND_TCP} {
		st, err := m.Open(context.Background(), &tunnelv1.StreamOpen{Kind: kind, RouteId: "r1"})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case o := <-c.opens:
			if named := o.TargetPriority != nil; named != (kind == tunnelv1.StreamKind_STREAM_KIND_TCP) {
				t.Fatalf("%s: a priority named %v (%v)", kind, named, o.TargetPriority)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no stream reached the connector")
		}
		_ = st.Close()
	}
}

// TestSessions_HealthyPriorities (D133): a connector that names its route's priorities with a
// healthy target gets streams only for those of its ranked entries: the route fails over to the
// next priority and back once the better one is healthy again, which BestPriority, the http routes'
// failback, follows; a connector that names none, as one without health.active, is ready at every
// priority; an unranked entry's stream tries every priority, so readiness alone counts; a route
// with no healthy target anywhere has no session.
func TestSessions_HealthyPriorities(t *testing.T) {
	con := cid("hp_1")
	a := &assignment{known: map[string]bool{con: true}, ranked: map[string][]gateway.RouteConnector{
		"r1": {{ID: con, Weight: 1, Ranked: true}, {ID: con, Priority: 5, Weight: 1, Ranked: true}}}}
	m := newSessions(a, nil)
	c := start(t, m, connectorID("hp_1"), hello("r1"))
	priority := func() uint32 {
		t.Helper()
		st, code, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"})
		if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("%s %v", code, err)
		}
		_ = st.Close()
		select {
		case o := <-c.opens:
			return o.GetTargetPriority()
		case <-time.After(5 * time.Second):
			t.Fatal("no stream reached the connector")
		}
		return 0
	}
	best := func(want uint32) {
		t.Helper()
		if p, ok := m.BestPriority("r1"); !ok || p != want {
			t.Fatalf("BestPriority %d %t, want %d", p, ok, want)
		}
	}
	// The hello says ready, naming no priorities: every priority, the best first.
	if p := priority(); p != 0 {
		t.Fatalf("a connector without priorities: stream at %d, want 0", p)
	}
	best(0)
	c.healthAt(t, "r1", 5)
	for range 5 {
		if p := priority(); p != 5 {
			t.Fatalf("priority 0 without a healthy target: stream at %d, want 5", p)
		}
	}
	best(5)
	c.healthAt(t, "r1", 0, 5)
	if p := priority(); p != 0 {
		t.Fatalf("priority 0 healthy again: stream at %d, want 0", p)
	}
	best(0)

	// An unranked entry: the stream names no priority and the connector picks among the healthy.
	a.mu.Lock()
	a.ranked["r1"] = []gateway.RouteConnector{{ID: con, Weight: 1}}
	a.mu.Unlock()
	c.healthAt(t, "r1", 5)
	if st, code, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"}); err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("an unranked entry: %s %v", code, err)
	} else {
		_ = st.Close()
		if o := <-c.opens; o.TargetPriority != nil {
			t.Fatalf("an unranked entry's stream names priority %d", o.GetTargetPriority())
		}
	}

	// No healthy target anywhere: the connector reports the route not ready, and no session serves.
	c.health(t, "r1", false)
	if _, _, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"}); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("no healthy target: %v, want ErrNoSession", err)
	}
	if _, ok := m.BestPriority("r1"); ok {
		t.Fatal("a best priority without a healthy target")
	}
}

// handedOff returns the next message of c's session, which is Drain{handoff} when the gateway told
// it to move for a hand-off.
func handedOff(t *testing.T, c *connector) *tunnelv1.Drain {
	t.Helper()
	select {
	case msg := <-c.msgs:
		return msg.GetDrain()
	case <-time.After(5 * time.Second):
		t.Fatal("no message")
		return nil
	}
}

// TestSessions_ConnectorHandoff: a session that names the earlier boot_id in handoff_from drains the
// sessions of that start with the hand-off drain instead of closing them; they take no new stream
// and stay open. A handoff_from that names an unknown boot_id or another connector's changes
// nothing for the other connector, and the earlier start closes as a restart's; a second hand-off
// in a row drains the process of the first and closes the one before it.
func TestSessions_ConnectorHandoff(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_r"): true, cid("con_o"): true},
		routes: map[string][]string{"r1": {cid("con_r")}}}
	const drain = 90 * time.Second
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: a, HandoffDrain: drain})
	booted := func(boot, from string) *tunnelv1.SessionMessage {
		h := hello("r1")
		h.GetHello().BootId, h.GetHello().HandoffFrom = boot, from
		return h
	}
	id := connectorID("con_r")
	old := start(t, m, id, booted("boot-1", ""))
	other := start(t, m, connectorID("con_o"), booted("boot-o", ""))

	begin := time.Now()
	next := start(t, m, id, booted("boot-2", "boot-1"))
	d := handedOff(t, old)
	if d.GetReason() != "handoff" || d.GetDeadline().AsTime().Before(begin.Add(drain-time.Second)) || d.GetDeadline().AsTime().After(begin.Add(drain+5*time.Second)) {
		t.Fatalf("got %v, want Drain{handoff} in %v", d, drain)
	}
	select {
	case err := <-old.served:
		t.Fatalf("the old process's session ended: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if got := m.Count()["h2"]; got != 3 {
		t.Fatalf("%d sessions, want the old, the new and the other connector's", got)
	}
	for range 4 { // streams go to the new process's session only
		st, code, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"})
		if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.Fatalf("a stream: %s %v", code, err)
		}
		_ = st.Close()
		select {
		case <-next.opens:
		case <-old.opens:
			t.Fatal("a stream went to a drained session")
		case <-time.After(5 * time.Second):
			t.Fatal("no stream arrived")
		}
	}

	// A second hand-off: the process of the first drains, the one before it closes.
	third := start(t, m, id, booted("boot-3", "boot-2"))
	if d := handedOff(t, next); d.GetReason() != "handoff" {
		t.Fatalf("got %v, want Drain{handoff}", d)
	}
	_ = old.serveErr(t)
	select {
	case err := <-next.served:
		t.Fatalf("the first new process's session ended: %v", err)
	case err := <-third.served:
		t.Fatalf("the newest session ended: %v", err)
	case err := <-other.served:
		t.Fatalf("another connector's session ended: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	// An unknown boot_id, and the boot_id of another connector's process, are no hand-off.
	_ = start(t, m, id, booted("boot-4", "boot-unknown"))
	_ = next.serveErr(t)
	_ = third.serveErr(t)
	_ = start(t, m, id, booted("boot-5", "boot-o"))
	select {
	case err := <-other.served:
		t.Fatalf("another connector's session ended: %v", err)
	case msg := <-other.msgs:
		t.Fatalf("another connector's session got %v", msg)
	case <-time.After(200 * time.Millisecond):
	}
}
