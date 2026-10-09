// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"
	"time"

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
)

// Errors of Open and OpenStream.
var (
	ErrNoSession     = errors.New("gateway: no ready data session for the route")
	ErrDraining      = errors.New("gateway: the gateway is draining")
	ErrResultTimeout = errors.New("gateway: no StreamResult in time")
)

// Assignment is what the gateway's snapshot says about connectors.
type Assignment interface {
	// Known reports whether the connector serves any route of this gateway.
	Known(connectorID string) bool
	// Connectors returns the connectors that serve the route.
	Connectors(routeID string) []string
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
	Now      func() time.Time
	Logger   *slog.Logger
}

// Sessions holds the gateway's data sessions from connectors (docs/03-connections.md, "Data
// session", "Multiple gateways"): it admits a session only from a connector the snapshot knows and
// the deny-list does not name, keeps each session's ready routes from RouteHealth, and opens user
// streams on the ready sessions of a route's connectors by power of two choices.
type Sessions struct {
	o SessionsOptions

	mu          sync.Mutex
	byConnector map[string][]*dataSession
	draining    bool // the gateway stops
	disabled    bool // the gateway is disabled (R22) until Enable
}

// NewSessions returns the session manager.
func NewSessions(o SessionsOptions) *Sessions {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Sessions{o: o, byConnector: map[string][]*dataSession{}}
}

// dataSession is one connector's session.
type dataSession struct {
	connector string
	peer      *x509.Certificate
	s         tunnel.Session
	send      func(*tunnelv1.SessionMessage) error
	now       func() time.Time
	inflight  atomic.Int64
	retiring  atomic.Bool // the snapshot dropped the connector; retire runs
	drained   atomic.Bool // told to move; it opens no new stream and closes at its deadline
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

// score is the smoothed RTT times the streams in flight, plus one; lower is better.
func (d *dataSession) score() int64 { return int64(d.rtt()) * (d.inflight.Load() + 1) }

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
	m.mu.Lock()
	draining := m.draining || m.disabled
	m.mu.Unlock()
	if draining {
		return ErrDraining
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
	if !m.add(d) {
		return ErrDraining
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

// add registers d unless the gateway started draining meanwhile.
func (m *Sessions) add(d *dataSession) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining || m.disabled {
		return false
	}
	m.byConnector[d.connector] = append(m.byConnector[d.connector], d)
	if m.o.OnChange != nil {
		defer m.o.OnChange()
	}
	return true
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

// candidates are the ready sessions of the route's connectors.
func (m *Sessions) candidates(route string) []*dataSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*dataSession
	for _, c := range m.o.Assignment.Connectors(route) {
		for _, d := range m.byConnector[c] {
			if d.isReady(route) && !d.drained.Load() {
				out = append(out, d)
			}
		}
	}
	return out
}

// pick chooses among sessions by power of two choices: two at random, the one with the lower
// score; a session whose writes are blocked loses against one whose are not.
func pick(sessions []*dataSession, now time.Time) *dataSession {
	if len(sessions) == 1 {
		return sessions[0]
	}
	i, j := randN(len(sessions)), randN(len(sessions)-1)
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
	if b.score() < a.score() {
		return b
	}
	return a
}

func randN(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// Open opens a stream for open's route on one of its ready sessions and writes open; a session at
// its stream limit is passed over. The caller reads the StreamResult (OpenStream) and must Close
// or Abort the stream, which ends its count in the session's load.
func (m *Sessions) Open(ctx context.Context, open *tunnelv1.StreamOpen) (tunnel.Stream, error) {
	return m.open(ctx, open, nil)
}

// open is Open without the session skip.
func (m *Sessions) open(ctx context.Context, open *tunnelv1.StreamOpen, skip *dataSession) (*trackedStream, error) {
	m.mu.Lock()
	draining := m.draining || m.disabled
	m.mu.Unlock()
	if draining {
		return nil, ErrDraining
	}
	cands := slices.DeleteFunc(m.candidates(open.GetRouteId()), func(x *dataSession) bool { return x == skip })
	for len(cands) > 0 {
		d := pick(cands, m.o.Now())
		st, err := d.s.OpenStream(ctx)
		if err != nil {
			cands = slices.DeleteFunc(cands, func(x *dataSession) bool { return x == d })
			continue
		}
		ts := &trackedStream{Stream: st, d: d}
		d.inflight.Add(1)
		if err := tunnel.WriteMessage(ts, open); err != nil {
			ts.Abort()
			return nil, err
		}
		return ts, nil
	}
	return nil, ErrNoSession
}

// OpenStream opens a stream for open's route and reads its StreamResult within 10 s; on DRAINING
// or OVERLOADED it tries once more on another session (docs/03-connections.md, "Framing"). It
// returns the stream only with NO_ERROR, otherwise the last result code.
func (m *Sessions) OpenStream(ctx context.Context, open *tunnelv1.StreamOpen) (tunnel.Stream, tunnelv1.ResultCode, error) {
	st, res, err := m.OpenStreamResult(ctx, open)
	return st, res.GetCode(), err
}

// OpenStreamResult is OpenStream returning the whole StreamResult, with the target the
// connector chose; it is nil after an error.
func (m *Sessions) OpenStreamResult(ctx context.Context, open *tunnelv1.StreamOpen) (tunnel.Stream, *tunnelv1.StreamResult, error) {
	var (
		last  *tunnelv1.StreamResult
		tried *dataSession
	)
	for attempt := range 2 {
		st, err := m.open(ctx, open, tried)
		if attempt == 1 && errors.Is(err, ErrNoSession) {
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
		code := res.GetCode()
		if code == tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			return st, res, nil
		}
		_ = st.Close()
		if code != tunnelv1.ResultCode_RESULT_CODE_DRAINING && code != tunnelv1.ResultCode_RESULT_CODE_OVERLOADED {
			break
		}
		tried = st.d
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

// trackedStream counts a stream in its session's load and notes blocked writes.
type trackedStream struct {
	tunnel.Stream
	d    *dataSession
	once sync.Once
}

func (t *trackedStream) Write(p []byte) (int, error) {
	start := t.d.now().UnixNano()
	t.d.writing.CompareAndSwap(0, start)
	n, err := t.Stream.Write(p)
	t.d.writing.CompareAndSwap(start, 0)
	return n, err
}

func (t *trackedStream) done() { t.once.Do(func() { t.d.inflight.Add(-1) }) }

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
