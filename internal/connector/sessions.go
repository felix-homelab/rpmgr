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
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// The transport policies of a route (docs/03-connections.md, "Transport selection").
const (
	TransportAuto = "auto"
	TransportQUIC = "quic"
	TransportH2   = "h2"
)

// transportMemory is the one link to an in-process gateway: h2 over in-memory connections, which
// carries every route to that gateway whatever its transport policy.
const transportMemory = "memory"

// h2Sessions is how many TCP connections the connector keeps per gateway on the h2 transport, so
// that packet loss blocks at most half the streams (docs/03-connections.md, "Transports and
// fallback"; D124).
const h2Sessions = 2

// quicSessions is how many QUIC sessions the connector keeps per gateway, each with its own
// congestion window, so that loss slows a quarter of the streams (docs/03-connections.md,
// "Transports and fallback"; D123).
const quicSessions = 4

// Variables for tests.
var (
	// welcomeTimeout bounds the wait for the control stream and the SessionWelcome.
	welcomeTimeout = 10 * time.Second
	// retireGrace is how long a retired session stays open at least, for streams the gateway
	// opened before it read the RouteHealth that withdrew the routes.
	retireGrace = time.Second
)

// Gateway is a gateway the connector keeps data sessions to, from its snapshot.
type Gateway struct {
	ID string
	// Endpoints are the gateway's own tunnel endpoints, host:port, tried in order.
	Endpoints []string
	// Routes maps each of the connector's routes on the gateway to its effective transport policy:
	// TransportAuto, TransportQUIC or TransportH2.
	Routes map[string]string
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
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// LocalAddr returns the local source address towards an endpoint, the key of the transport
	// cache; nil asks the kernel.
	LocalAddr func(ctx context.Context, endpoint string) (netip.Addr, error)
	// Metrics, if set, report the sessions' round-trip times.
	Metrics *Metrics
	// InProcess, if set, is a gateway in the same process.
	InProcess *InProcess
	Now       func() time.Time
	Logger    *slog.Logger
}

// InProcess is a gateway that runs in the connector's process, all-in-one's
// (docs/02-architecture.md, "All-in-one"). The connector keeps one data session to it over
// connections that Dial makes in memory, with TLS and reverse HTTP/2 as over TCP, for every route
// whatever its transport policy, and never dials its endpoints.
type InProcess struct {
	GatewayID string
	Dial      func(ctx context.Context) (net.Conn, error)
}

// Sessions keeps the connector's data sessions (docs/03-connections.md, "Data session",
// "Transport selection"). Per gateway it runs a link for each transport policy its routes need:
// a pinned link holds four QUIC sessions or two TCP connections and never falls back; the auto link
// races QUIC against TCP and keeps the winner's sessions; an in-process gateway gets one link in
// memory for all its routes. Each session announces exactly the ready routes of its link's policy,
// so the gateway opens a route's streams only on sessions of the route's transport.
type Sessions struct {
	o      Options
	ctx    context.Context
	cancel context.CancelFunc
	choose *chooser
	wg     sync.WaitGroup

	mu       sync.Mutex
	gateways map[string]*gatewayState
	ready    map[string]bool
}

type gatewayState struct {
	g     Gateway
	links map[string]*link // by transport policy
	// gone are the routes a newer snapshot took from the gateway, until the end of their route
	// drain period, during which the gateway may still open streams for them.
	gone map[string]time.Time
}

// link keeps the sessions of one transport policy to one gateway.
type link struct {
	gw       string        // the gateway's ID
	gs       *gatewayState // its entry; gs.g under Sessions.mu
	policy   string
	cancel   context.CancelFunc
	sessions map[*session]bool // established and not retired
	failed   error             // the last dial error; nil while a session is up
}

// session is one data session of a link.
type session struct {
	l         *link
	transport string
	s         tunnel.Session
	send      func(*tunnelv1.SessionMessage) error
	requests  *tunnel.OpenRequester
	streams   atomic.Int64
	pingSeq   atomic.Uint64   // the last Ping sent
	pingAt    atomic.Int64    // when, in Unix nanoseconds
	srtt      atomic.Int64    // the smoothed round-trip time from Ping and Pong, 0 before the first
	announced map[string]bool // routes reported ready on it; under Sessions.mu
	retired   bool            // under Sessions.mu
}

// outgoing is a message to send after Sessions.mu is released.
type outgoing struct {
	s   *session
	msg *tunnelv1.SessionMessage
}

// New returns the connector's data sessions; Close ends them.
func New(o Options) *Sessions {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Budget == nil {
		o.Budget = tunnel.NewBudget(tunnel.DefaultWindowBudget)
	}
	if o.LocalAddr == nil {
		o.LocalAddr = localAddr
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Sessions{o: o, ctx: ctx, cancel: cancel, choose: newChooser(o.Now), gateways: map[string]*gatewayState{},
		ready: map[string]bool{}}
	o.Metrics.watch(s)
	return s
}

// policies are the transport policies a gateway entry needs links for.
func policies(g Gateway) map[string]bool {
	out := map[string]bool{}
	for _, p := range g.Routes {
		out[p] = true
	}
	return out
}

// Set makes the gateway entries those of the applied snapshot. Links that are still needed keep
// their sessions and are told which routes they now carry; new links start; a link no longer
// needed, or every link of a gateway whose endpoints changed, retires its sessions, which close
// after their last stream has ended.
func (m *Sessions) Set(gws []Gateway) {
	m.mu.Lock()
	var out []outgoing
	want := map[string]Gateway{}
	for _, g := range gws {
		if m.o.InProcess != nil && g.ID == m.o.InProcess.GatewayID {
			routes := make(map[string]string, len(g.Routes))
			for r := range g.Routes {
				routes[r] = transportMemory
			}
			g.Routes = routes
		}
		want[g.ID] = g
	}
	for id, gs := range m.gateways {
		g, ok := want[id]
		if ok && slices.Equal(g.Endpoints, gs.g.Endpoints) {
			delete(want, id)
			now := m.o.Now()
			for r := range gs.g.Routes {
				if _, still := g.Routes[r]; !still {
					gs.gone[r] = now.Add(routeDrain)
				}
			}
			for r, until := range gs.gone {
				if _, back := g.Routes[r]; back || !now.Before(until) {
					delete(gs.gone, r)
				}
			}
			gs.g = g
			need := policies(g)
			for p, l := range gs.links {
				if !need[p] {
					out = append(out, m.stopLink(l)...)
					delete(gs.links, p)
				}
			}
			for p := range need {
				if gs.links[p] == nil {
					m.startLink(gs, p)
				}
			}
			for _, l := range gs.links {
				for s := range l.sessions {
					out = append(out, m.announce(s)...)
				}
			}
			continue
		}
		for _, l := range gs.links {
			out = append(out, m.stopLink(l)...)
		}
		delete(m.gateways, id)
	}
	for _, g := range want {
		gs := &gatewayState{g: g, links: map[string]*link{}, gone: map[string]time.Time{}}
		m.gateways[g.ID] = gs
		for p := range policies(g) {
			m.startLink(gs, p)
		}
	}
	m.mu.Unlock()
	m.flush(out)
}

func (m *Sessions) startLink(gs *gatewayState, policy string) {
	ctx, cancel := context.WithCancel(m.ctx)
	l := &link{gw: gs.g.ID, gs: gs, policy: policy, cancel: cancel, sessions: map[*session]bool{}}
	gs.links[policy] = l
	m.wg.Go(func() {
		switch policy {
		case TransportQUIC, TransportH2, transportMemory:
			m.runMode(ctx, l, policy, nil, nil)
		default:
			m.runAuto(ctx, l)
		}
	})
}

// stopLink ends a link; its sessions retire. Under m.mu.
func (m *Sessions) stopLink(l *link) []outgoing {
	l.cancel()
	var out []outgoing
	for s := range l.sessions {
		out = append(out, m.retire(s)...)
	}
	return out
}

// retire withdraws every route from s and closes it once its last stream has ended. Under m.mu.
func (m *Sessions) retire(s *session) []outgoing {
	if s.retired {
		return nil
	}
	s.retired = true
	delete(s.l.sessions, s)
	var out []outgoing
	for _, r := range slices.Sorted(maps.Keys(s.announced)) {
		out = append(out, outgoing{s, health(r, false)})
	}
	s.announced = map[string]bool{}
	m.wg.Go(func() {
		grace := time.After(retireGrace)
		for {
			select {
			case <-s.s.Done():
				return
			case <-m.ctx.Done():
				return
			case <-grace:
				grace = nil
			case <-time.After(100 * time.Millisecond):
			}
			if grace == nil && s.streams.Load() == 0 {
				_ = s.s.Close()
				return
			}
		}
	})
	return out
}

func health(route string, ready bool) *tunnelv1.SessionMessage {
	return &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_RouteHealth{RouteHealth: &tunnelv1.RouteHealth{RouteId: route, Ready: ready}}}
}

// serves reports whether the gateway of s serves route by the applied snapshot, or did until less
// than the route drain period ago. A retired session keeps the gateway entry it was retired with.
func (m *Sessions) serves(s *session, route string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := s.l.gs.g.Routes[route]; ok {
		return true
	}
	until, ok := s.l.gs.gone[route]
	return ok && m.o.Now().Before(until)
}

// wanted are the routes s should announce: the ready routes of its link's policy. Under m.mu.
func (m *Sessions) wanted(s *session) map[string]bool {
	out := map[string]bool{}
	for r, p := range s.l.gs.g.Routes {
		if p == s.l.policy && m.ready[r] {
			out[r] = true
		}
	}
	return out
}

// announce brings what s announced up to date. Under m.mu.
func (m *Sessions) announce(s *session) []outgoing {
	if s.retired {
		return nil
	}
	want := m.wanted(s)
	var out []outgoing
	for _, r := range slices.Sorted(maps.Keys(want)) {
		if !s.announced[r] {
			out = append(out, outgoing{s, health(r, true)})
		}
	}
	for _, r := range slices.Sorted(maps.Keys(s.announced)) {
		if !want[r] {
			out = append(out, outgoing{s, health(r, false)})
		}
	}
	s.announced = want
	return out
}

func (m *Sessions) flush(out []outgoing) {
	for _, o := range out {
		if err := o.s.send(o.msg); err != nil {
			m.o.Logger.Debug("cannot send to a gateway", "gateway", o.s.l.gw, "error", err)
		}
	}
}

// SetReady records whether a route is ready on this host and tells the sessions that carry it.
// Only Ready is used: why a route is not ready goes to the controller, not to gateways.
func (m *Sessions) SetReady(h *tunnelv1.RouteHealth) {
	m.mu.Lock()
	m.ready[h.GetRouteId()] = h.GetReady()
	var out []outgoing
	for _, gs := range m.gateways {
		if p, ok := gs.g.Routes[h.GetRouteId()]; ok && gs.links[p] != nil {
			for s := range gs.links[p].sessions {
				out = append(out, m.announce(s)...)
			}
		}
	}
	m.mu.Unlock()
	m.flush(out)
}

// pingEvery is the session Ping's interval in nanoseconds, tunnel.PingInterval. A test changes it,
// so it is atomic: a session of an earlier test may still start its pings meanwhile.
var pingEvery atomic.Int64

func init() { pingEvery.Store(int64(tunnel.PingInterval)) }

// ping sends a Ping, noting when.
func (s *session) ping(msg *tunnelv1.SessionMessage) error {
	if p := msg.GetPing(); p != nil {
		s.pingAt.Store(time.Now().UnixNano())
		s.pingSeq.Store(p.GetSeq())
	}
	return s.send(msg)
}

// pong takes the Pong of the last Ping into the smoothed round-trip time, with the gain of
// RFC 6298, 1/8.
func (s *session) pong(seq uint64) {
	if seq != s.pingSeq.Load() {
		return
	}
	sample := time.Now().UnixNano() - s.pingAt.Load()
	if old := s.srtt.Load(); old > 0 {
		sample = old + (sample-old)/8
	}
	s.srtt.Store(sample)
}

// rtt is the session's smoothed round-trip time: the transport's if it measures one, as QUIC
// does, else the Ping's; 0 while unknown.
func (s *session) rtt() time.Duration {
	if q, ok := s.s.(interface{ RTT() time.Duration }); ok && q.RTT() > 0 {
		return q.RTT()
	}
	return time.Duration(s.srtt.Load())
}

// RTTKey names the sessions to one gateway over one transport.
type RTTKey struct{ Gateway, Transport string }

// RTTs returns the lowest known round-trip time of the established sessions per gateway and
// transport.
func (m *Sessions) RTTs() map[RTTKey]time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[RTTKey]time.Duration{}
	for id, gs := range m.gateways {
		for _, l := range gs.links {
			for s := range l.sessions {
				k := RTTKey{id, s.transport}
				if rtt := s.rtt(); rtt > 0 && (out[k] == 0 || rtt < out[k]) {
					out[k] = rtt
				}
			}
		}
	}
	return out
}

// Count returns the number of established sessions that carry routes, per "<gateway>/<transport>".
func (m *Sessions) Count() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for id, gs := range m.gateways {
		for _, l := range gs.links {
			for s := range l.sessions {
				out[id+"/"+s.transport]++
			}
		}
	}
	return out
}

// Status returns the routes whose pinned transport, or whose in-memory link to an in-process
// gateway, cannot be established: not_ready(transport_unavailable) with the transport (quic, h2 or
// memory) as detail, when no gateway of the route has a session of that transport and a dial of it
// failed. A pin never falls back.
func (m *Sessions) Status() []*agentv1.ResourceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	served, failed := map[string]bool{}, map[string]string{}
	for _, gs := range m.gateways {
		for r, p := range gs.g.Routes {
			// Any link with a session serves the route, an auto link too: a route the in-process
			// gateway carries in memory may be on auto towards another gateway.
			l := gs.links[p]
			switch {
			case l != nil && len(l.sessions) > 0:
				served[r] = true
			case p == TransportAuto || l == nil:
			case l.failed != nil:
				failed[r] = p
			}
		}
	}
	var out []*agentv1.ResourceStatus
	for _, r := range slices.Sorted(maps.Keys(failed)) {
		if !served[r] {
			out = append(out, &agentv1.ResourceStatus{ResourceId: r, Reason: agentv1.NotReadyReason_NOT_READY_REASON_TRANSPORT_UNAVAILABLE,
				Detail: failed[r]})
		}
	}
	return out
}

// Close ends every session and waits for the links.
func (m *Sessions) Close() {
	m.cancel()
	m.mu.Lock()
	for _, gs := range m.gateways {
		for _, l := range gs.links {
			for s := range l.sessions {
				_ = s.s.Close()
			}
		}
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// modeHooks let the auto link end a mode from its slots; a pinned link has none.
type modeHooks struct {
	// ended sees every failed dial (dialled true) and every ended session; true ends the mode.
	ended func(err error, dialled bool) bool
	// moved is asked before every redial; true, for a new local source address, ends the mode.
	moved func() bool
	// live counts the mode's established sessions, so that a failed dial of one slot ends the
	// mode only while no other slot has a session.
	live atomic.Int32
}

// sessionsOf is how many sessions a link keeps on transport tr: four for QUIC, two for h2 and one
// in memory.
func sessionsOf(tr string) int {
	switch tr {
	case TransportQUIC:
		return quicSessions
	case TransportH2:
		return h2Sessions
	}
	return 1
}

// runMode keeps the sessions of transport tr on link l until ctx ends, sessionsOf(tr) of them,
// each in a slot of its own that redials with a backoff of up to 15 s; first, if set, is the first
// session of the first slot.
func (m *Sessions) runMode(ctx context.Context, l *link, tr string, first tunnel.Session, hooks *modeHooks) {
	n := sessionsOf(tr)
	var wg sync.WaitGroup
	for i := range n {
		f := first
		if i > 0 {
			f = nil
		}
		wg.Go(func() { m.slot(ctx, l, tr, f, hooks) })
	}
	wg.Wait()
}

func (m *Sessions) slot(ctx context.Context, l *link, tr string, first tunnel.Session, hooks *modeHooks) {
	b := agent.DataBackoff()
	for ctx.Err() == nil {
		start := time.Now()
		ts, err := first, error(nil)
		first = nil
		if ts == nil {
			ts, err = m.dialTransport(ctx, l.gs, tr)
		}
		if err != nil {
			m.mu.Lock()
			l.failed = err
			m.mu.Unlock()
			if ctx.Err() != nil || (hooks != nil && hooks.ended(err, true)) {
				return
			}
		} else {
			if hooks != nil {
				hooks.live.Add(1)
			}
			err = m.run(ctx, l, ts, ts.Transport())
			if hooks != nil {
				hooks.live.Add(-1)
			}
			b.Healthy(time.Since(start))
			if ctx.Err() != nil || (hooks != nil && hooks.ended(err, false)) {
				return
			}
		}
		wait := b.Next(0)
		m.o.Logger.Info("data session to a gateway ended", "gateway", l.gw, "transport", tr, "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		// The source address can change while the slot waits: a dial from a new one races again.
		if hooks != nil && hooks.moved() {
			return
		}
	}
}

// errDrained ends a session's run when the gateway drains: the session keeps its streams until
// the gateway closes it, and the slot dials a replacement.
var errDrained = errors.New("connector: the gateway is draining")

// run serves an established session until it ends, the gateway drains it, or ctx ends, which
// retires it.
func (m *Sessions) run(ctx context.Context, l *link, ts tunnel.Session, tr string) error {
	s := &session{l: l, transport: tr, s: ts, announced: map[string]bool{}}
	drained := make(chan struct{})
	done := make(chan error, 1)
	m.wg.Go(func() { done <- m.serve(ctx, s, drained) })
	select {
	case err := <-done:
		return err
	case <-drained:
		m.mu.Lock()
		out := m.retire(s)
		m.mu.Unlock()
		m.flush(out)
		return errDrained
	case <-ctx.Done():
		m.mu.Lock()
		out := m.retire(s)
		m.mu.Unlock()
		m.flush(out)
		return ctx.Err()
	}
}

// runAuto runs the auto link: the cached winner for the local source address, h2 while QUIC is
// demoted, or a race; while on h2 it re-probes QUIC, and a QUIC session that times out demotes
// QUIC for an hour. A switch retires the old sessions, so their open connections finish.
func (m *Sessions) runAuto(ctx context.Context, l *link) {
	gw := l.gw
	b := agent.DataBackoff()
	var handover tunnel.Session
	for ctx.Err() == nil {
		m.mu.Lock()
		ep := l.gs.g.Endpoints[0]
		m.mu.Unlock()
		local, err := m.o.LocalAddr(ctx, ep)
		if err != nil {
			local = netip.Addr{}
		}
		tr, first := m.choose.plan(gw, local), handover
		handover = nil
		if first != nil {
			tr = TransportQUIC
		} else if tr == "" {
			s, won, err := m.race(ctx, l)
			if err != nil {
				m.mu.Lock()
				l.failed = err
				m.mu.Unlock()
				m.o.Logger.Info("no transport to a gateway", "gateway", gw, "error", err)
				select {
				case <-ctx.Done():
				case <-time.After(b.Next(0)):
				}
				continue
			}
			m.choose.won(gw, local, won)
			tr, first = won, s
		}
		mctx, switchMode := context.WithCancel(ctx)
		var probed atomic.Pointer[tunnel.Session]
		// The next connection from a new local source address starts a new race.
		moved := func() bool {
			if now, err := m.o.LocalAddr(ctx, ep); err != nil || now == local {
				return false
			}
			switchMode()
			return true
		}
		var hooks *modeHooks
		ended := func(err error, dialled bool) bool {
			switch {
			case dialled && hooks.live.Load() > 0:
				// Another slot of the mode has a session: this one retries with its backoff, as a
				// gateway that refuses a session beyond its cap leaves the others in service.
				return moved()
			case dialled:
				m.choose.forget(gw, local)
			case tr == TransportQUIC && isBlackhole(err):
				m.o.Logger.Warn("QUIC to a gateway timed out; using TCP for an hour", "gateway", gw)
				m.choose.blackholed(gw)
			default:
				return moved()
			}
			switchMode()
			return true
		}
		var wg sync.WaitGroup
		hooks = &modeHooks{ended: ended, moved: moved}
		wg.Go(func() { m.runMode(mctx, l, tr, first, hooks) })
		if tr == TransportH2 {
			wg.Go(func() {
				if s := m.reprobe(mctx, l); s != nil {
					m.choose.won(gw, local, TransportQUIC)
					probed.Store(&s)
					switchMode()
				}
			})
		}
		wg.Wait()
		switchMode()
		if p := probed.Load(); p != nil {
			handover = *p
		}
	}
	if handover != nil {
		_ = handover.Close()
	}
}

// reprobe tries QUIC every reprobeEvery while QUIC is not demoted, and returns the first session
// that comes up, or nil when ctx ends.
func (m *Sessions) reprobe(ctx context.Context, l *link) tunnel.Session {
	t := time.NewTicker(reprobeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if !m.choose.mayProbe(l.gw) {
			continue
		}
		if s, err := m.dialTransport(ctx, l.gs, TransportQUIC); err == nil {
			if ctx.Err() != nil {
				_ = s.Close()
				return nil
			}
			return s
		}
	}
}

// race dials QUIC, and TCP raceDelay later or as soon as QUIC fails; the first session wins and
// the other dial is cancelled, or its session closed.
func (m *Sessions) race(ctx context.Context, l *link) (tunnel.Session, string, error) {
	type result struct {
		s   tunnel.Session
		tr  string
		err error
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, 2)
	dial := func(tr string) {
		go func() {
			s, err := m.dialTransport(rctx, l.gs, tr)
			results <- result{s, tr, err}
		}()
	}
	dial(TransportQUIC)
	timer := time.NewTimer(raceDelay)
	defer timer.Stop()
	pending, tcp := 1, false
	startTCP := func() {
		if !tcp {
			tcp = true
			pending++
			dial(TransportH2)
		}
	}
	var errs []error
	for pending > 0 {
		select {
		case <-timer.C:
			startTCP()
		case r := <-results:
			pending--
			if r.err == nil {
				go func(n int) {
					for range n {
						if o := <-results; o.err == nil {
							_ = o.s.Close()
						}
					}
				}(pending)
				return r.s, r.tr, nil
			}
			errs = append(errs, r.err)
			startTCP()
		}
	}
	return nil, "", errors.Join(errs...)
}

// dialTransport opens a session of transport tr to the gateway, trying its endpoints in order.
func (m *Sessions) dialTransport(ctx context.Context, gs *gatewayState, tr string) (tunnel.Session, error) {
	m.mu.Lock()
	g := gs.g
	m.mu.Unlock()
	cfg, err := m.o.TLS(g.ID)
	if err != nil {
		return nil, err
	}
	if tr == transportMemory {
		s, err := m.dialMemory(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("in process: %w", err)
		}
		return s, nil
	}
	var errs []error
	for _, ep := range g.Endpoints {
		var s tunnel.Session
		if tr == TransportQUIC {
			s, err = m.dialQUIC(ctx, ep, cfg)
		} else {
			s, err = m.dialH2(ctx, ep, cfg)
		}
		if err == nil {
			return s, nil
		}
		errs = append(errs, fmt.Errorf("%s %s: %w", tr, ep, err))
	}
	return nil, errors.Join(errs...)
}

// fitReady lists in hello as many of the ready routes as the message limit leaves room for, in
// order, and returns them; RouteHealth messages after the welcome announce the others, so that a
// connector with any number of routes keeps its SessionHello within tunnel.MaxMessage
// (docs/03-connections.md, "Framing").
func fitReady(hello *tunnelv1.SessionHello, ready []string) map[string]bool {
	msg := &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Hello{Hello: hello}}
	hello.ReadyRoutes = nil
	// The hello is a field of the SessionMessage, whose length prefix grows with it: keep a margin
	// for that, and check the result below.
	room := tunnel.MaxMessage - proto.Size(msg) - 8
	n := 0
	for _, r := range ready {
		size := protowire.SizeTag(5) + protowire.SizeBytes(len(r)) // field 5, ready_routes
		if size > room {
			break
		}
		room -= size
		n++
	}
	hello.ReadyRoutes = ready[:n]
	for n > 0 && proto.Size(msg) > tunnel.MaxMessage {
		n--
		hello.ReadyRoutes = ready[:n]
	}
	sent := make(map[string]bool, n)
	for _, r := range ready[:n] {
		sent[r] = true
	}
	return sent
}

// serve runs an established session: SessionHello with the ready routes of the link's policy, the
// SessionWelcome from the expected gateway, Pings, the streams the gateway opens and the messages
// it sends. It closes drained once the gateway sends Drain and returns when the session ends. ctx
// bounds only the handshake: once established, a session ends with the gateway, with Close, or
// when it is retired and idle.
func (m *Sessions) serve(ctx context.Context, s *session, drained chan struct{}) error {
	ts := s.s
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
	s.send = func(msg *tunnelv1.SessionMessage) error {
		mu.Lock()
		defer mu.Unlock()
		return tunnel.WriteMessage(control, msg)
	}
	s.requests = tunnel.NewOpenRequester(s.send, 0)
	hello := &tunnelv1.SessionHello{}
	if m.o.Hello != nil {
		hello = m.o.Hello()
	}
	m.mu.Lock()
	want := m.wanted(s)
	m.mu.Unlock()
	sent := fitReady(hello, slices.Sorted(maps.Keys(want)))
	if err := s.send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Hello{Hello: hello}}); err != nil {
		return err
	}
	welcome, err := readWelcome(wctx, control)
	if err != nil {
		return err
	}
	if id := s.l.gw; welcome.GetGatewayId() != id {
		return fmt.Errorf("connector: the gateway says it is %q, not %q", welcome.GetGatewayId(), id)
	}
	m.mu.Lock()
	if ctx.Err() != nil { // the link stopped during the handshake
		m.mu.Unlock()
		return ctx.Err()
	}
	s.announced = sent
	s.l.sessions[s] = true
	s.l.failed = nil
	out := m.announce(s) // the ready routes the hello had no room for, and changes during the handshake
	m.mu.Unlock()
	m.flush(out)
	defer func() {
		m.mu.Lock()
		delete(s.l.sessions, s)
		m.mu.Unlock()
	}()
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	go func() { _ = tunnel.SendPings(sctx, s.ping, time.Duration(pingEvery.Load())) }()
	go m.accept(sctx, s)
	var once sync.Once
	for {
		msg := &tunnelv1.SessionMessage{}
		if err := tunnel.ReadMessage(control, msg); err != nil {
			return err
		}
		switch {
		case msg.GetDrain() != nil:
			once.Do(func() { close(drained) })
		case msg.GetPong() != nil:
			s.pong(msg.GetPong().GetSeq())
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
// of an OpenRequest or to Streams. A stream for a route that the gateway does not serve gets
// ROUTE_UNKNOWN: a gateway of one group never reaches the targets of another group's routes
// (docs/04-security.md, "Threat model").
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
			foreign := m.o.Streams != nil && routed(open) && !m.serves(s, open.GetRouteId())
			if m.o.Streams == nil || foreign {
				if foreign {
					m.o.Logger.Warn("refused a stream for a route the gateway does not serve", "gateway", s.l.gw, "route", open.GetRouteId())
				}
				_ = tunnel.WriteMessage(cs, &tunnelv1.StreamResult{Code: tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN})
				cs.SetReliableBoundary()
				_ = cs.CloseWrite()
				_ = cs.Close()
				return
			}
			m.o.Streams(ctx, s.l.gw, cs, open)
		}()
	}
}

// routed reports whether open is a well-formed stream of a route, which the gateway must serve;
// Streams answers any other with its own code.
func routed(open *tunnelv1.StreamOpen) bool {
	k := open.GetKind()
	return (k == tunnelv1.StreamKind_STREAM_KIND_TCP || k == tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW) &&
		tunnel.CheckStreamOpen(open) == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR
}

// countedStream ends its count in the session's streams when it is closed or aborted.
type countedStream struct {
	tunnel.Stream
	s    *session
	once sync.Once
}

func (c *countedStream) done() { c.once.Do(func() { c.s.streams.Add(-1) }) }

// Unwrap returns the transport's stream, for its QUIC stream ID.
func (c *countedStream) Unwrap() tunnel.Stream { return c.Stream }

func (c *countedStream) Abort() {
	c.done()
	c.Stream.Abort()
}

func (c *countedStream) Close() error {
	c.done()
	return c.Stream.Close()
}
