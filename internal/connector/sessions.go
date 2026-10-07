// SPDX-License-Identifier: Apache-2.0

// Package connector is the connector role (docs/02-architecture.md): its data sessions to every
// gateway of its routes, and the streams it delivers to targets on its host.
package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// The transports a gateway entry asks for (docs/03-connections.md, "Transport selection").
const (
	TransportAuto = "auto"
	TransportQUIC = "quic"
	TransportH2   = "h2"
)

// h2Sessions is how many TCP connections the connector keeps per gateway on the h2 transport, so
// that packet loss blocks at most half the streams (docs/03-connections.md, "Transports and
// fallback").
const h2Sessions = 2

// Variables for tests.
var (
	// welcomeTimeout bounds the wait for the control stream and the SessionWelcome.
	welcomeTimeout = 10 * time.Second
	// retireAfter is how long a session no gateway entry needs any more keeps its streams.
	retireAfter = 30 * time.Second
)

// Gateway is a gateway the connector keeps data sessions to, from its snapshot.
type Gateway struct {
	ID string
	// Endpoints are the gateway's own tunnel endpoints, host:port, tried in order.
	Endpoints []string
	// Transports are the transports its routes need: TransportQUIC, TransportH2 or TransportAuto.
	// Until happy eyeballs (docs/03-connections.md), auto tries QUIC first and falls back to h2 on
	// each connection attempt.
	Transports []string
	// Routes are the connector's routes on the gateway.
	Routes []string
}

func (g Gateway) equal(o Gateway) bool {
	return g.ID == o.ID && slices.Equal(g.Endpoints, o.Endpoints) && slices.Equal(g.Transports, o.Transports) &&
		slices.Equal(g.Routes, o.Routes)
}

// Options configure Sessions.
type Options struct {
	// TLS returns the client configuration for a gateway: the connector's certificate, the pinned
	// root, ServerName <gateway-id>.gateway.<td> and exactly that gateway's identity.
	TLS func(gatewayID string) (*tls.Config, error)
	// Hello returns the SessionHello without its ready routes, which Sessions fills in.
	Hello func() *tunnelv1.SessionHello
	// Streams takes a stream the gateway opened, after its StreamOpen; it writes the StreamResult
	// and closes the stream. Nil answers ROUTE_UNKNOWN.
	Streams func(ctx context.Context, gatewayID string, st tunnel.Stream, open *tunnelv1.StreamOpen)
	// QUIC is the UDP transport for QUIC sessions; nil leaves QUIC unavailable.
	QUIC   *quic.Transport
	Budget *tunnel.Budget
	// Dial opens a TCP connection to a gateway; nil dials directly.
	Dial   func(ctx context.Context, addr string) (net.Conn, error)
	Logger *slog.Logger
}

// Sessions keeps the connector's data sessions: one QUIC session or two TCP connections per
// gateway and transport, redialled with backoff, each told which of the gateway's routes are
// ready (docs/03-connections.md, "Data session").
type Sessions struct {
	o      Options
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	gateways map[string]*gatewayLinks
	ready    map[string]bool
	wg       sync.WaitGroup
}

// gatewayLinks are the links of one gateway entry.
type gatewayLinks struct {
	g        Gateway
	cancel   context.CancelFunc
	sessions map[*session]bool
}

// session is one established data session.
type session struct {
	gateway   string
	transport string
	s         tunnel.Session
	send      func(*tunnelv1.SessionMessage) error
	requests  *tunnel.OpenRequester
	draining  atomic.Bool
	streams   atomic.Int64
}

// New returns the connector's data sessions; Close ends them.
func New(o Options) *Sessions {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Budget == nil {
		o.Budget = tunnel.NewBudget(tunnel.DefaultWindowBudget)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Sessions{o: o, ctx: ctx, cancel: cancel, gateways: map[string]*gatewayLinks{}, ready: map[string]bool{}}
}

// Set makes the gateway entries those of the applied snapshot: links of new or changed entries
// start, and the sessions of removed or changed ones keep their streams for up to 30 s before
// they close.
func (m *Sessions) Set(gws []Gateway) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]Gateway{}
	for _, g := range gws {
		want[g.ID] = g
	}
	for id, gl := range m.gateways {
		if g, ok := want[id]; ok && gl.g.equal(g) {
			delete(want, id)
			continue
		}
		gl.cancel()
		for s := range gl.sessions {
			m.retire(s)
		}
		delete(m.gateways, id)
	}
	for _, g := range want {
		ctx, cancel := context.WithCancel(m.ctx)
		gl := &gatewayLinks{g: g, cancel: cancel, sessions: map[*session]bool{}}
		m.gateways[g.ID] = gl
		for _, tr := range g.Transports {
			n := 1
			if tr == TransportH2 {
				n = h2Sessions
			}
			for range n {
				m.wg.Go(func() { m.link(ctx, gl, tr) })
			}
		}
	}
}

// retire stops opening streams on s and closes it when its last stream has ended, at most
// retireAfter later.
func (m *Sessions) retire(s *session) {
	s.draining.Store(true)
	m.wg.Go(func() {
		deadline := time.Now().Add(retireAfter)
		for s.streams.Load() > 0 && time.Now().Before(deadline) {
			select {
			case <-s.s.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
		_ = s.s.Close()
	})
}

// SetReady records whether a route is ready on this host and tells every session to a gateway
// with that route.
func (m *Sessions) SetReady(h *tunnelv1.RouteHealth) {
	m.mu.Lock()
	m.ready[h.GetRouteId()] = h.GetReady()
	var to []*session
	for _, gl := range m.gateways {
		if slices.Contains(gl.g.Routes, h.GetRouteId()) {
			for s := range gl.sessions {
				to = append(to, s)
			}
		}
	}
	m.mu.Unlock()
	for _, s := range to {
		if err := s.send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_RouteHealth{RouteHealth: h}}); err != nil {
			m.o.Logger.Debug("cannot send RouteHealth", "gateway", s.gateway, "error", err)
		}
	}
}

// Count returns the number of established sessions per gateway and transport, "<id>/<transport>".
func (m *Sessions) Count() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for id, gl := range m.gateways {
		for s := range gl.sessions {
			out[id+"/"+s.transport]++
		}
	}
	return out
}

// Close ends every session and waits for the links.
func (m *Sessions) Close() {
	m.cancel()
	m.wg.Wait()
}

// link keeps one session of transport tr to the gateway until ctx ends: it dials, runs the
// session, and dials again after a backoff of up to 15 s. On Drain it dials a replacement while
// the draining session keeps its streams.
func (m *Sessions) link(ctx context.Context, gl *gatewayLinks, tr string) {
	b := agent.DataBackoff()
	for ctx.Err() == nil {
		start := time.Now()
		s, used, err := m.dial(ctx, gl.g, tr)
		if err == nil {
			drained := make(chan struct{})
			done := make(chan error, 1)
			m.wg.Go(func() { done <- m.serve(ctx, gl, s, used, drained) })
			select {
			case err = <-done:
			case <-drained:
				err = errors.New("the gateway is draining")
			}
			b.Healthy(time.Since(start))
		}
		if ctx.Err() != nil {
			return
		}
		wait := b.Next(0)
		m.o.Logger.Info("data session to a gateway ended", "gateway", gl.g.ID, "transport", tr, "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// dial opens a session of transport tr, trying the endpoints in order; auto tries QUIC on every
// endpoint first, then h2.
func (m *Sessions) dial(ctx context.Context, g Gateway, tr string) (tunnel.Session, string, error) {
	cfg, err := m.o.TLS(g.ID)
	if err != nil {
		return nil, "", err
	}
	order := []string{tr}
	if tr == TransportAuto {
		order = []string{TransportQUIC, TransportH2}
	}
	var errs []error
	for _, t := range order {
		for _, ep := range g.Endpoints {
			var s tunnel.Session
			switch t {
			case TransportQUIC:
				s, err = m.dialQUIC(ctx, ep, cfg)
			default:
				s, err = m.dialH2(ctx, ep, cfg)
			}
			if err == nil {
				return s, t, nil
			}
			errs = append(errs, fmt.Errorf("%s %s: %w", t, ep, err))
		}
	}
	return nil, "", errors.Join(errs...)
}

// serve runs an established session: SessionHello with the ready routes, the SessionWelcome from
// the expected gateway, Pings, the streams the gateway opens and the messages it sends. It closes
// drained once the gateway sends Drain and returns when the session ends. ctx bounds only the
// handshake: once established, a session ends with the gateway, with Close, or retired by Set.
func (m *Sessions) serve(ctx context.Context, gl *gatewayLinks, ts tunnel.Session, tr string, drained chan struct{}) error {
	defer func() { _ = ts.Close() }()
	stop := context.AfterFunc(m.ctx, func() { _ = ts.Close() })
	defer stop()
	wctx, cancel := context.WithTimeout(ctx, welcomeTimeout)
	defer cancel()
	control, err := ts.Control(wctx)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	send := func(msg *tunnelv1.SessionMessage) error {
		mu.Lock()
		defer mu.Unlock()
		return tunnel.WriteMessage(control, msg)
	}
	hello := &tunnelv1.SessionHello{}
	if m.o.Hello != nil {
		hello = m.o.Hello()
	}
	s := &session{gateway: gl.g.ID, transport: tr, s: ts, send: send, requests: tunnel.NewOpenRequester(send, 0)}
	m.mu.Lock()
	for _, r := range gl.g.Routes {
		if m.ready[r] {
			hello.ReadyRoutes = append(hello.ReadyRoutes, r)
		}
	}
	m.mu.Unlock()
	if err := send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Hello{Hello: hello}}); err != nil {
		return err
	}
	welcome, err := readWelcome(wctx, control)
	if err != nil {
		return err
	}
	if welcome.GetGatewayId() != gl.g.ID {
		return fmt.Errorf("connector: the gateway says it is %q, not %q", welcome.GetGatewayId(), gl.g.ID)
	}
	m.mu.Lock()
	if ctx.Err() != nil { // Set removed the entry during the handshake
		m.mu.Unlock()
		return ctx.Err()
	}
	gl.sessions[s] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(gl.sessions, s)
		m.mu.Unlock()
	}()
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	go func() { _ = tunnel.SendPings(sctx, send, tunnel.PingInterval) }()
	go m.accept(sctx, s)
	var once sync.Once
	for {
		msg := &tunnelv1.SessionMessage{}
		if err := tunnel.ReadMessage(control, msg); err != nil {
			return err
		}
		switch {
		case msg.GetDrain() != nil:
			s.draining.Store(true)
			once.Do(func() { close(drained) })
		case msg.GetOpenRejected() != nil:
			s.requests.Rejected(msg.GetOpenRejected())
		case msg.GetGoodbye() != nil:
			return fmt.Errorf("connector: Goodbye from the gateway: %s", msg.GetGoodbye().GetCode())
		}
	}
}

// readWelcome reads the SessionWelcome within ctx.
func readWelcome(ctx context.Context, control tunnel.Stream) (*tunnelv1.SessionWelcome, error) {
	stop := context.AfterFunc(ctx, control.Abort)
	defer stop()
	msg := &tunnelv1.SessionMessage{}
	if err := tunnel.ReadMessage(control, msg); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("connector: no SessionWelcome in time")
		}
		return nil, err
	}
	if msg.GetWelcome() == nil {
		return nil, errors.New("connector: the gateway's first message is not SessionWelcome")
	}
	return msg.GetWelcome(), nil
}

// accept reads the StreamOpen of every stream the gateway opens and hands the stream to the answer
// of an OpenRequest or to Streams.
func (m *Sessions) accept(ctx context.Context, s *session) {
	for {
		st, err := s.s.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			stop := time.AfterFunc(welcomeTimeout, st.Abort)
			open := &tunnelv1.StreamOpen{}
			err := tunnel.ReadMessage(st, open)
			if !stop.Stop() || err != nil {
				st.Abort()
				return
			}
			if open.GetOpenId() != 0 {
				s.requests.Accepted(st, open)
				return
			}
			s.streams.Add(1)
			cs := &countedStream{Stream: st, s: s}
			if m.o.Streams == nil {
				_ = tunnel.WriteMessage(cs, &tunnelv1.StreamResult{Code: tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN})
				_ = cs.Close()
				return
			}
			m.o.Streams(ctx, s.gateway, cs, open)
		}()
	}
}

// countedStream ends its count in the session's streams when it is closed or aborted.
type countedStream struct {
	tunnel.Stream
	s    *session
	once sync.Once
}

func (c *countedStream) done() { c.once.Do(func() { c.s.streams.Add(-1) }) }

func (c *countedStream) Abort() {
	c.done()
	c.Stream.Abort()
}

func (c *countedStream) Close() error {
	c.done()
	return c.Stream.Close()
}
