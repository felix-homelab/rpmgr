// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// The data-session timing (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	// DrainPeriod is how long a draining gateway keeps its sessions' streams.
	DrainPeriod = 60 * time.Second
	// blockedAfter is how long a stream write may take before its session counts as blocked
	// and is passed over for new streams [V VB-18].
	blockedAfter = 200 * time.Millisecond
	protoMinor   = 0
	// MaxConnectorSessions is how many data sessions one connector identity may hold to a gateway
	// at once (docs/03-connections.md, "Establishment").
	MaxConnectorSessions = 16
	// capWarnEvery limits the warnings about one connector at the cap.
	capWarnEvery = time.Minute
)

// Variables for tests.
var (
	// helloTimeout bounds the wait for a session's SessionHello.
	helloTimeout = 10 * time.Second
	// resultTimeout bounds the wait for a stream's StreamResult.
	resultTimeout = 10 * time.Second
	// unassignedDrain is how long the sessions of a connector the snapshot dropped keep their
	// streams: the route drain period (docs/03-connections.md, "Timeouts, keepalive and backoff").
	unassignedDrain = 30 * time.Second
	// activeWindow is how recently a stream must have been opened or have carried a byte to count
	// in its session's load: an idle pooled HTTP stream or a quiet UDP flow does not (D90).
	activeWindow = 5 * time.Second
)

// Errors of Open and OpenStream.
var (
	ErrNoSession     = errors.New("gateway: no ready data session for the route")
	ErrDraining      = errors.New("gateway: the gateway is draining")
	ErrResultTimeout = errors.New("gateway: no StreamResult in time")
	// ErrSessionCap refuses a data session beyond MaxConnectorSessions.
	ErrSessionCap = fmt.Errorf("gateway: the connector already holds %d data sessions to this gateway", MaxConnectorSessions)
)

// Assignment is what the gateway's snapshot says about connectors.
type Assignment interface {
	// Known reports whether the connector serves any route of this gateway.
	Known(connectorID string) bool
	// Connectors returns the connectors that serve the route, with their rank for it.
	Connectors(routeID string) []RouteConnector
}

// RouteConnector is a connector that serves a route at one priority of its targets of the route: a
// stream goes to an entry of the lowest priority whose connector has a ready session, chosen by
// weight (D90).
type RouteConnector struct {
	ID       string
	Priority uint32
	Weight   uint32 // 0 counts as 1
	// Ranked: the controller ranked it, so a stream names the priority to the connector.
	Ranked bool
}

// SessionsOptions configure Sessions.
type SessionsOptions struct {
	TrustDomain string
	GatewayID   string
	Assignment  Assignment
	// Denied is the deny-list check; nil denies nothing.
	Denied       func(*x509.Certificate) bool
	Capabilities []string
	// OnOpenRequest decides a stream a connector asks for, an OpenRequest on HTTP/2 or a stream it
	// opened on QUIC (CONTROL_PASSTHROUGH); nil refuses every one with UNAUTHORIZED.
	OnOpenRequest func(connectorID string, r *tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream))
	// OnChange, if set, is called after a data session was added or removed, for the report to
	// the controller.
	OnChange func()
	// Metrics, if set, records the sessions and the routes' streams.
	Metrics *Metrics
	Now     func() time.Time
	Logger  *slog.Logger
}

// Sessions holds the gateway's data sessions from connectors (docs/03-connections.md, "Data
// session", "Multiple gateways"): it admits a session only from a connector the snapshot knows and
// the deny-list does not name, keeps each session's ready routes from RouteHealth, and opens user
// streams on the ready sessions of a route's connectors by power of two choices.
type Sessions struct {
	o SessionsOptions

	mu          sync.Mutex
	byConnector map[string][]*dataSession
	capWarned   map[string]time.Time // when a connector at the cap was last warned about
	draining    bool                 // the gateway stops
	disabled    bool                 // the gateway is disabled (R22) until Enable
}

// NewSessions returns the session manager.
func NewSessions(o SessionsOptions) *Sessions {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Sessions{o: o, byConnector: map[string][]*dataSession{}, capWarned: map[string]time.Time{}}
	o.Metrics.watch(s)
	return s
}

// metrics returns the gateway's metrics, nil for none.
func (m *Sessions) metrics() *Metrics {
	if m == nil {
		return nil
	}
	return m.o.Metrics
}

// dataSession is one connector's session.
type dataSession struct {
	connector string
	peer      *x509.Certificate
	s         tunnel.Session
	send      func(*tunnelv1.SessionMessage) error
	now       func() time.Time
	inflight  atomic.Int64
	streamsMu sync.Mutex
	streams   map[*trackedStream]struct{} // open, for the load
	retiring  atomic.Bool                 // the snapshot dropped the connector; retire runs
	drained   atomic.Bool                 // told to move; it opens no new stream and closes at its deadline
	// writing is the start, in Unix nanoseconds, of a stream write still in progress, or 0. With
	// concurrent writers it tracks one of them, which is enough to notice a session whose writes
	// all block.
	writing atomic.Int64
	readyMu sync.Mutex
	ready   map[string]bool
}

func (d *dataSession) isReady(route string) bool {
	d.readyMu.Lock()
	defer d.readyMu.Unlock()
	return d.ready[route]
}

// rtt is the session's round-trip time where the transport knows it, else 1 ms.
func (d *dataSession) rtt() time.Duration {
	if r, ok := d.s.(interface{ RTT() time.Duration }); ok && r.RTT() > 0 {
		return r.RTT()
	}
	return time.Millisecond
}

// score is the smoothed RTT times the active streams, plus one; lower is better.
func (d *dataSession) score(now time.Time) int64 { return int64(d.rtt()) * (d.active(now) + 1) }

// active counts the session's streams opened or used within activeWindow.
func (d *dataSession) active(now time.Time) int64 {
	cut := now.Add(-activeWindow).UnixNano()
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()
	var n int64
	for t := range d.streams {
		if t.last.Load() >= cut {
			n++
		}
	}
	return n
}

// track adds a stream to the session's load, until untrack.
func (d *dataSession) track(t *trackedStream) {
	d.inflight.Add(1)
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()
	if d.streams == nil {
		d.streams = map[*trackedStream]struct{}{}
	}
	d.streams[t] = struct{}{}
}

func (d *dataSession) untrack(t *trackedStream) {
	d.inflight.Add(-1)
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()
	delete(d.streams, t)
}

// blocked reports whether a stream write has taken longer than blockedAfter.
func (d *dataSession) blocked(now time.Time) bool {
	start := d.writing.Load()
	return start != 0 && now.Sub(time.Unix(0, start)) > blockedAfter
}

// Serve runs one data session from the connector with certificate peer until it ends or ctx is
// done: it refuses an unknown or denied connector, answers SessionHello, which must come within
// helloTimeout, and then reads the session control stream.
func (m *Sessions) Serve(ctx context.Context, s tunnel.Session, peer *x509.Certificate) error {
	defer func() { _ = s.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	id, err := m.identify(peer)
	if err != nil {
		return err
	}
	if err := m.admits(id.ID); err != nil {
		return err
	}
	hctx, cancel := context.WithTimeout(ctx, helloTimeout)
	control, err := s.Control(hctx)
	cancel()
	if err != nil {
		return err
	}
	var mu sync.Mutex
	send := func(msg *tunnelv1.SessionMessage) error {
		mu.Lock()
		defer mu.Unlock()
		return tunnel.WriteMessage(control, msg)
	}
	hello, err := readHello(control)
	if err != nil {
		return err
	}
	d := &dataSession{connector: id.ID, peer: peer, s: s, send: send, now: m.o.Now, ready: map[string]bool{}}
	for _, r := range hello.GetReadyRoutes() {
		d.ready[r] = true
	}
	// Registered before the welcome, so that a Drain or Recheck from now on reaches the session.
	if err := m.add(d); err != nil {
		return err
	}
	defer m.remove(d)
	if err := send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Welcome{Welcome: &tunnelv1.SessionWelcome{
		GatewayId: m.o.GatewayID, ProtoMinor: protoMinor, Capabilities: m.o.Capabilities}}}); err != nil {
		return err
	}
	decide := func(r *tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream)) {
		if m.o.OnOpenRequest == nil {
			return tunnelv1.ResultCode_RESULT_CODE_UNAUTHORIZED, nil
		}
		return m.o.OnOpenRequest(id.ID, r)
	}
	resp := tunnel.NewOpenResponder(send, s.OpenStream, decide)
	if s.Transport() == "quic" {
		go acceptOpened(ctx, s, decide)
	}
	for {
		msg := &tunnelv1.SessionMessage{}
		if err := tunnel.ReadMessage(control, msg); err != nil {
			return err
		}
		switch {
		case msg.GetPing() != nil:
			if err := send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Pong{Pong: &tunnelv1.Pong{Seq: msg.GetPing().GetSeq()}}}); err != nil {
				return err
			}
		case msg.GetRouteHealth() != nil:
			h := msg.GetRouteHealth()
			d.readyMu.Lock()
			d.ready[h.GetRouteId()] = h.GetReady()
			d.readyMu.Unlock()
		case msg.GetOpenRequest() != nil:
			go func(r *tunnelv1.OpenRequest) {
				if err := resp.Handle(ctx, r); err != nil {
					m.o.Logger.Warn("cannot answer an OpenRequest", "connector", id.ID, "error", err)
				}
			}(msg.GetOpenRequest())
		case msg.GetGoodbye() != nil:
			return nil
		}
	}
}

// acceptOpened serves the streams a connector opens on a QUIC session: each starts with its
// StreamOpen within the StreamResult timeout and gets a StreamResult; decide answers it as it
// answers an OpenRequest on HTTP/2.
func acceptOpened(ctx context.Context, s tunnel.Session, decide func(*tunnelv1.OpenRequest) (tunnelv1.ResultCode, func(tunnel.Stream))) {
	for {
		st, err := s.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			stop := time.AfterFunc(resultTimeout, st.Abort)
			open := &tunnelv1.StreamOpen{}
			err := tunnel.ReadMessage(st, open)
			if !stop.Stop() || err != nil {
				st.Abort()
				return
			}
			code := tunnel.CheckStreamOpen(open)
			var serve func(tunnel.Stream)
			if code == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
				code, serve = decide(&tunnelv1.OpenRequest{Kind: open.GetKind(), RouteId: open.GetRouteId()})
			}
			if err := tunnel.WriteMessage(st, &tunnelv1.StreamResult{Code: code}); err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
				st.SetReliableBoundary()
				_ = st.CloseWrite()
				_ = st.Close()
				return
			}
			if serve == nil {
				_ = st.Close()
				return
			}
			serve(st)
		}()
	}
}

// identify checks the peer: a connector of this trust domain that the snapshot knows and the
// deny-list does not name.
func (m *Sessions) identify(peer *x509.Certificate) (pki.Identity, error) {
	if peer == nil || len(peer.URIs) != 1 {
		return pki.Identity{}, errors.New("gateway: the peer has no rpmgr identity")
	}
	id, err := pki.ParseSPIFFE(peer.URIs[0], m.o.TrustDomain)
	switch {
	case err != nil:
		return id, err
	case id.Kind != pki.KindConnector:
		return id, errors.New("gateway: data sessions come from connectors")
	case m.o.Denied != nil && m.o.Denied(peer):
		return id, pki.ErrDenied
	case !m.o.Assignment.Known(id.ID):
		return id, errors.New("gateway: the connector serves no route of this gateway")
	}
	return id, nil
}

func readHello(control tunnel.Stream) (*tunnelv1.SessionHello, error) {
	type result struct {
		msg *tunnelv1.SessionMessage
		err error
	}
	got := make(chan result, 1)
	go func() {
		msg := &tunnelv1.SessionMessage{}
		err := tunnel.ReadMessage(control, msg)
		got <- result{msg, err}
	}()
	select {
	case r := <-got:
		if r.err != nil {
			return nil, r.err
		}
		if r.msg.GetHello() == nil {
			return nil, errors.New("gateway: the first message must be SessionHello")
		}
		return r.msg.GetHello(), nil
	case <-time.After(helloTimeout):
		control.Abort()
		return nil, errors.New("gateway: no SessionHello in time")
	}
}

// admits reports why the gateway takes no new data session from the connector id: it is
// draining or disabled, or the connector holds MaxConnectorSessions already.
func (m *Sessions) admits(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.admitsLocked(id)
}

// admitsLocked is admits under m.mu.
func (m *Sessions) admitsLocked(id string) error {
	switch {
	case m.draining || m.disabled:
		return ErrDraining
	case len(m.byConnector[id]) >= MaxConnectorSessions:
		if now := m.o.Now(); now.Sub(m.capWarned[id]) >= capWarnEvery {
			m.capWarned[id] = now
			m.o.Logger.Warn("refusing a data session of a connector at the cap", "connector", id, "sessions", MaxConnectorSessions)
		}
		return ErrSessionCap
	}
	return nil
}

// add registers d unless the gateway started draining or the connector reached the cap
// meanwhile.
func (m *Sessions) add(d *dataSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.admitsLocked(d.connector); err != nil {
		return err
	}
	m.byConnector[d.connector] = append(m.byConnector[d.connector], d)
	if m.o.OnChange != nil {
		defer m.o.OnChange()
	}
	return nil
}

// Recheck applies a new deny-list or snapshot to the live sessions; the gateway calls it after
// applying either. A session whose connector the deny-list now names closes at once, because
// revocation takes effect at once. A connector the snapshot no longer assigns a route of this
// gateway only lost its routes: no new stream is opened on its sessions, which close after their
// last stream has ended, at the latest after the route drain period (docs/03-connections.md,
// "Configuration reconciliation"). A drained session the deny-list does not name keeps its
// deadline.
func (m *Sessions) Recheck() {
	m.mu.Lock()
	var denied, dropped []*dataSession
	for _, ds := range m.byConnector {
		for _, d := range ds {
			switch {
			case m.o.Denied != nil && m.o.Denied(d.peer):
				denied = append(denied, d)
			case !m.o.Assignment.Known(d.connector) && !d.drained.Load() && d.retiring.CompareAndSwap(false, true):
				dropped = append(dropped, d)
			}
		}
	}
	m.mu.Unlock()
	for _, d := range denied {
		m.o.Logger.Info("closing the data session of a revoked connector", "connector", d.connector)
		_ = d.s.Close()
	}
	for _, d := range dropped {
		go m.retire(d)
	}
}

// retire closes the session of a connector the snapshot dropped once its streams have ended, at
// the latest after unassignedDrain, unless a later snapshot assigns the connector again.
func (m *Sessions) retire(d *dataSession) {
	defer d.retiring.Store(false)
	deadline := time.Now().Add(unassignedDrain)
	for time.Now().Before(deadline) && d.inflight.Load() > 0 {
		if m.o.Assignment.Known(d.connector) {
			return
		}
		select {
		case <-d.s.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !m.o.Assignment.Known(d.connector) {
		m.o.Logger.Info("closing the data session of a connector without routes here", "connector", d.connector)
		_ = d.s.Close()
	}
}

func (m *Sessions) remove(d *dataSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byConnector[d.connector] = slices.DeleteFunc(m.byConnector[d.connector], func(x *dataSession) bool { return x == d })
	if len(m.byConnector[d.connector]) == 0 {
		delete(m.byConnector, d.connector)
		delete(m.capWarned, d.connector)
	}
	if m.o.OnChange != nil {
		defer m.o.OnChange()
	}
}

// Report returns the gateway's data sessions for the controller (docs/03-connections.md,
// "Configuration reconciliation"): one per connector and transport, with the lowest smoothed
// round-trip time any of them knows, 0 if none does.
func (m *Sessions) Report() []*agentv1.DataSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	type key struct{ connector, transport string }
	best := map[key]time.Duration{}
	for con, ds := range m.byConnector {
		for _, d := range ds {
			k := key{con, d.s.Transport()}
			rtt, known := best[k]
			if r, ok := d.s.(interface{ RTT() time.Duration }); ok && r.RTT() > 0 && (!known || rtt == 0 || r.RTT() < rtt) {
				rtt = r.RTT()
			}
			best[k] = rtt
		}
	}
	out := make([]*agentv1.DataSession, 0, len(best))
	for k, rtt := range best {
		ds := &agentv1.DataSession{ConnectorId: k.connector, Transport: agentv1.Transport_TRANSPORT_H2}
		if k.transport == "quic" {
			ds.Transport = agentv1.Transport_TRANSPORT_QUIC
		}
		if rtt > 0 {
			ds.Rtt = durationpb.New(rtt)
		}
		out = append(out, ds)
	}
	slices.SortFunc(out, func(a, b *agentv1.DataSession) int {
		return cmp.Or(cmp.Compare(a.GetConnectorId(), b.GetConnectorId()), cmp.Compare(a.GetTransport(), b.GetTransport()))
	})
	return out
}

// rankedSessions is an entry of a route, a connector at one priority of its targets, with the
// connector's ready sessions.
type rankedSessions struct {
	RouteConnector
	sessions []*dataSession
}

// tier is a connector at one priority of its targets of a route.
type tier struct {
	connector string
	priority  uint32
}

// passedOver are the entries and sessions an open does not try again.
type passedOver struct {
	tiers    map[tier]bool
	sessions map[*dataSession]bool
}

// candidates are the route's entries whose connector has a ready session, each with those
// sessions, less the ones skip names.
func (m *Sessions) candidates(route string, skip passedOver) []rankedSessions {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []rankedSessions
	for _, c := range m.o.Assignment.Connectors(route) {
		if skip.tiers[tier{c.ID, c.Priority}] {
			continue
		}
		r := rankedSessions{RouteConnector: c}
		for _, d := range m.byConnector[c.ID] {
			if d.isReady(route) && !d.drained.Load() && !skip.sessions[d] {
				r.sessions = append(r.sessions, d)
			}
		}
		if len(r.sessions) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// BestTier returns the lowest priority of the route's entries whose connector has a ready
// session, with those entries' connectors, and false when there is none.
func (m *Sessions) BestTier(route string) (uint32, map[string]bool, bool) {
	if m == nil {
		return 0, nil, false
	}
	cands := m.candidates(route, passedOver{})
	if len(cands) == 0 {
		return 0, nil, false
	}
	best, cons := lowest(cands), map[string]bool{}
	for _, c := range cands {
		if c.Priority == best {
			cons[c.ID] = true
		}
	}
	return best, cons, true
}

func lowest(cands []rankedSessions) uint32 {
	best := cands[0].Priority
	for _, c := range cands[1:] {
		best = min(best, c.Priority)
	}
	return best
}

// choose picks a session among cands, which must not be empty: an entry of the lowest priority at
// random by weight, then one of its connector's sessions by pick. While another entry of the
// priority has a session whose writes are not blocked, an entry whose sessions all are is passed
// over. It returns the entry's index too.
func choose(cands []rankedSessions, now time.Time) (int, *dataSession) {
	best := lowest(cands)
	flowing := func(c rankedSessions) bool {
		return slices.ContainsFunc(c.sessions, func(d *dataSession) bool { return !d.blocked(now) })
	}
	anyFlowing := slices.ContainsFunc(cands, func(c rankedSessions) bool { return c.Priority == best && flowing(c) })
	eligible := func(c rankedSessions) bool { return c.Priority == best && (!anyFlowing || flowing(c)) }
	var total int64
	for _, c := range cands {
		if eligible(c) {
			total += int64(max(c.Weight, 1))
		}
	}
	n := randN(total)
	for i, c := range cands {
		if !eligible(c) {
			continue
		}
		if w := int64(max(c.Weight, 1)); n >= w {
			n -= w
			continue
		}
		return i, pick(c.sessions, now)
	}
	return 0, pick(cands[0].sessions, now) // not reached: n < total
}

// pick chooses among sessions by power of two choices: two at random, the one with the lower
// score; a session whose writes are blocked loses against one whose are not.
func pick(sessions []*dataSession, now time.Time) *dataSession {
	if len(sessions) == 1 {
		return sessions[0]
	}
	i, j := int(randN(int64(len(sessions)))), int(randN(int64(len(sessions)-1)))
	if j >= i {
		j++
	}
	a, b := sessions[i], sessions[j]
	switch ab, bb := a.blocked(now), b.blocked(now); {
	case ab && !bb:
		return b
	case bb && !ab:
		return a
	}
	if b.score(now) < a.score(now) {
		return b
	}
	return a
}

func randN(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

// Open opens a stream for open's route on one of its ready sessions and writes open; a session at
// its stream limit is passed over. The caller reads the StreamResult (OpenStream) and must Close
// or Abort the stream, which ends its count in the session's load.
func (m *Sessions) Open(ctx context.Context, open *tunnelv1.StreamOpen) (tunnel.Stream, error) {
	return m.open(ctx, open, passedOver{})
}

// open is Open passing over the entries and sessions skip names. A ranked entry's priority goes
// into open, so that its connector dials only its targets of that priority (D90).
func (m *Sessions) open(ctx context.Context, open *tunnelv1.StreamOpen, skip passedOver) (*trackedStream, error) {
	m.mu.Lock()
	draining := m.draining || m.disabled
	m.mu.Unlock()
	if draining {
		return nil, ErrDraining
	}
	cands := m.candidates(open.GetRouteId(), skip)
	for len(cands) > 0 {
		i, d := choose(cands, m.o.Now())
		st, err := d.s.OpenStream(ctx)
		if err != nil {
			if cands[i].sessions = slices.DeleteFunc(cands[i].sessions, func(x *dataSession) bool { return x == d }); len(cands[i].sessions) == 0 {
				cands = slices.Delete(cands, i, i+1)
			}
			continue
		}
		open.TargetPriority = nil
		if c := cands[i]; c.Ranked {
			open.TargetPriority = &c.Priority
		}
		ts := &trackedStream{Stream: st, d: d, tier: cands[i].RouteConnector}
		ts.last.Store(m.o.Now().UnixNano())
		d.track(ts)
		if err := tunnel.WriteMessage(ts, open); err != nil {
			ts.Abort()
			return nil, err
		}
		ts.open, ts.in, ts.out = m.o.Metrics.stream(open.GetRouteId(), d.s.Transport())
		return ts, nil
	}
	return nil, ErrNoSession
}

// OpenStream opens a stream for open's route and reads its StreamResult within 10 s. On DRAINING
// or OVERLOADED it tries another session; on UPSTREAM_REFUSED or UPSTREAM_TIMEOUT another entry,
// of the same priority first, then of the next, which may be the same connector at a worse
// priority; at most openAttempts streams in all (docs/03-connections.md, "Framing", D90). It
// returns the stream only with NO_ERROR, otherwise the last result code.
func (m *Sessions) OpenStream(ctx context.Context, open *tunnelv1.StreamOpen) (tunnel.Stream, tunnelv1.ResultCode, error) {
	st, res, err := m.OpenStreamResult(ctx, open)
	return st, res.GetCode(), err
}

// OpenStreamResult is OpenStream returning the whole StreamResult, with the target the
// connector chose; it is nil after an error.
func (m *Sessions) OpenStreamResult(ctx context.Context, open *tunnelv1.StreamOpen) (tunnel.Stream, *tunnelv1.StreamResult, error) {
	start := time.Now()
	ctx, span := otel.Tracer(tracerName).Start(ctx, "rpmgr.gateway.open_stream", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("rpmgr.route", open.GetRouteId())))
	defer span.End()
	tunnel.SetTraceContext(ctx, open)
	st, res, err := m.openStreamResult(ctx, open)
	m.o.Metrics.opened(open.GetRouteId(), start, res, err)
	if err != nil || res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		span.SetStatus(codes.Error, cmp.Or(res.GetCode().String(), fmt.Sprint(err)))
	}
	return st, res, err
}

// tracerName names the gateway's spans (docs/10-operations.md, "Traces").
const tracerName = "github.com/felix-homelab/rpmgr/internal/gateway"

// openAttempts bounds the streams one OpenStream opens, and so its time: each waits at most for
// its StreamResult.
const openAttempts = 4

func (m *Sessions) openStreamResult(ctx context.Context, open *tunnelv1.StreamOpen) (tunnel.Stream, *tunnelv1.StreamResult, error) {
	var last *tunnelv1.StreamResult
	skip := passedOver{tiers: map[tier]bool{}, sessions: map[*dataSession]bool{}}
	for attempt := range openAttempts {
		st, err := m.open(ctx, open, skip)
		if attempt > 0 && errors.Is(err, ErrNoSession) {
			return nil, last, nil // no other session to try
		}
		if err != nil {
			return nil, nil, err
		}
		res, err := readResult(ctx, st)
		if err != nil {
			st.Abort()
			return nil, nil, err
		}
		last = res
		switch res.GetCode() {
		case tunnelv1.ResultCode_RESULT_CODE_NO_ERROR:
			return st, res, nil
		case tunnelv1.ResultCode_RESULT_CODE_DRAINING, tunnelv1.ResultCode_RESULT_CODE_OVERLOADED:
			skip.sessions[st.d] = true
		case tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT:
			// Another entry may reach its target; the client has sent nothing over the stream yet,
			// as every caller relays only after NO_ERROR.
			skip.tiers[tier{st.d.connector, st.tier.Priority}] = true
			m.o.Logger.Debug("trying another target of the route", "route", open.GetRouteId(), "connector", st.d.connector,
				"priority", st.tier.Priority, "code", res.GetCode())
		default:
			_ = st.Close()
			return nil, res, nil
		}
		_ = st.Close()
	}
	return nil, last, nil
}

// readResult reads a stream's StreamResult, aborting the stream after resultTimeout or when ctx
// is done.
func readResult(ctx context.Context, st tunnel.Stream) (*tunnelv1.StreamResult, error) {
	timer := time.AfterFunc(resultTimeout, st.Abort)
	stop := context.AfterFunc(ctx, st.Abort)
	res := &tunnelv1.StreamResult{}
	err := tunnel.ReadMessage(st, res)
	// A stopper that reports false has run: the stream is aborted even if the read succeeded.
	timedOut, cancelled := !timer.Stop(), !stop()
	switch {
	case timedOut:
		return nil, ErrResultTimeout
	case cancelled:
		return nil, ctx.Err()
	case err != nil:
		return nil, err
	}
	return res, nil
}

// Drain tells every session to move before deadline, normally now plus DrainPeriod, and from then
// on admits no new session and opens no new stream; each session closes at the deadline.
func (m *Sessions) Drain(deadline time.Time) {
	m.mu.Lock()
	m.draining = true
	m.mu.Unlock()
	m.drain(deadline, "gateway shutdown")
}

// Disable drains the sessions as Drain does, for a disabled gateway (R22), with the deadline
// period from now. Until Enable, no new session or stream is admitted. A session already drained
// keeps its deadline.
func (m *Sessions) Disable(period time.Duration) {
	m.mu.Lock()
	m.disabled = true
	m.mu.Unlock()
	m.drain(m.o.Now().Add(period), "gateway disabled")
}

// Enable admits new sessions again after Disable; the drained ones still close at their deadline.
func (m *Sessions) Enable() {
	m.mu.Lock()
	m.disabled = false
	m.mu.Unlock()
}

// drain tells each session not yet drained to move before deadline, and closes it then.
func (m *Sessions) drain(deadline time.Time, reason string) {
	m.mu.Lock()
	var all []*dataSession
	for _, ds := range m.byConnector {
		for _, d := range ds {
			if !d.drained.Swap(true) {
				all = append(all, d)
			}
		}
	}
	m.mu.Unlock()
	for _, d := range all {
		_ = d.send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Drain{Drain: &tunnelv1.Drain{
			Reason: reason, Deadline: timestamppb.New(deadline)}}})
		time.AfterFunc(deadline.Sub(m.o.Now()), func() { _ = d.s.Close() })
	}
}

// Close ends every session.
func (m *Sessions) Close() {
	m.mu.Lock()
	var all []*dataSession
	for _, ds := range m.byConnector {
		all = append(all, ds...)
	}
	m.mu.Unlock()
	for _, d := range all {
		_ = d.s.Close()
	}
}

// Datagrams returns the datagram multiplexer of the session a stream from Open runs on, or nil on
// the TCP transport.
func (m *Sessions) Datagrams(st tunnel.Stream) *tunnel.Datagrams {
	ts, ok := st.(*trackedStream)
	if !ok {
		return nil
	}
	if q, ok := ts.d.s.(*tunnel.QUICSession); ok {
		return q.Datagrams()
	}
	return nil
}

// Streams returns the number of streams in flight on all sessions.
func (m *Sessions) Streams() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, ds := range m.byConnector {
		for _, d := range ds {
			n += d.inflight.Load()
		}
	}
	return n
}

// Count returns the number of sessions per transport, for the data_sessions report.
func (m *Sessions) Count() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, ds := range m.byConnector {
		for _, d := range ds {
			out[d.s.Transport()]++
		}
	}
	return out
}

// StreamConnector returns the connector a stream of OpenStreamResult goes to, as the certificate of
// its data session names it; "" for another stream.
func StreamConnector(st tunnel.Stream) string {
	if ts, ok := st.(*trackedStream); ok {
		return ts.d.connector
	}
	return ""
}

// trackedStream counts a stream in its session's load and its route's metrics, and notes blocked
// writes.
type trackedStream struct {
	tunnel.Stream
	d       *dataSession
	tier    RouteConnector // the entry it was opened for
	last    atomic.Int64   // Unix nanoseconds of the open or the latest byte, for the load
	once    sync.Once
	open    prometheus.Gauge   // nil without metrics
	in, out prometheus.Counter // bytes towards the service and back
}

func (t *trackedStream) Write(p []byte) (int, error) {
	start := t.d.now().UnixNano()
	t.d.writing.CompareAndSwap(0, start)
	n, err := t.Stream.Write(p)
	t.d.writing.CompareAndSwap(start, 0)
	if n > 0 {
		t.last.Store(start)
	}
	if t.in != nil {
		t.in.Add(float64(n))
	}
	return n, err
}

func (t *trackedStream) Read(p []byte) (int, error) {
	n, err := t.Stream.Read(p)
	if n > 0 {
		t.last.Store(t.d.now().UnixNano())
	}
	if t.out != nil {
		t.out.Add(float64(n))
	}
	return n, err
}

func (t *trackedStream) done() {
	t.once.Do(func() {
		t.d.untrack(t)
		if t.open != nil {
			t.open.Dec()
		}
	})
}

// markActive counts a stream of Open as active now, for a byte that does not pass through it,
// such as a UDP flow's datagram.
func markActive(st tunnel.Stream) {
	if ts, ok := st.(*trackedStream); ok {
		ts.last.Store(ts.d.now().UnixNano())
	}
}

// streamPriority returns the priority a stream of OpenStreamResult was opened at, and whether the
// controller ranked it.
func streamPriority(st tunnel.Stream) (uint32, bool) {
	if ts, ok := st.(*trackedStream); ok {
		return ts.tier.Priority, ts.tier.Ranked
	}
	return 0, false
}

// Unwrap returns the transport's stream, for its QUIC stream ID.
func (t *trackedStream) Unwrap() tunnel.Stream { return t.Stream }

func (t *trackedStream) Abort() {
	t.done()
	t.Stream.Abort()
}

func (t *trackedStream) Close() error {
	t.done()
	return t.Stream.Close()
}
