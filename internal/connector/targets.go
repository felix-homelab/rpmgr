// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// dialUpstream bounds the dial of a target (docs/03-connections.md, "Timeouts, keepalive and
// backoff"); a StreamOpen may ask for less.
const dialUpstream = 5 * time.Second

// routeDrain is how long a removed route still takes streams; a variable for tests.
var routeDrain = 30 * time.Second

// Route is a route as the connector serves it, from its snapshot.
type Route struct {
	ID string
	// UDP routes take UDP_FLOW streams, tcp_udp routes (Both) both kinds, every other route TCP
	// streams.
	UDP, Both bool
	// Targets are tried by priority, lowest first, and by weight within a priority.
	Targets []Target
}

// Target is one destination of a route on the connector's host.
type Target struct {
	ID string
	// Host is an IP address or a name, with Port; or UnixPath instead.
	Host     string
	Port     uint16
	UnixPath string
	// ProxyProtocol is "v1", "v2", or "none" or empty for no PROXY header.
	ProxyProtocol string
	Weight        uint32
	Priority      uint32
}

func (t Target) String() string {
	if t.UnixPath != "" {
		return t.UnixPath
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// blockDetail is the readiness detail of a target the policy does not allow: the target, and the
// entry of deny_targets that refuses it if one does, or that it is one of rpmgr's own ports
// (policy.BlockedError.Detail).
func (t Target) blockDetail(p *policy.Policy) string {
	e := &policy.BlockedError{Target: t.String()}
	if t.UnixPath != "" {
		e.Denied = p.DeniedByUnix(t.UnixPath)
	} else if ip, err := netip.ParseAddr(t.Host); err == nil {
		e.Denied, e.Own = p.DeniedBy(ip, t.Port), p.Own(ip, t.Port)
	}
	return e.Detail()
}

// allowed reports whether the policy allows the target as far as it is known before dialling: a
// name is checked on its resolved address when it is dialled.
func (t Target) allowed(p *policy.Policy) bool {
	if t.UnixPath != "" {
		return p.AllowsUnix(t.UnixPath)
	}
	if ip, err := netip.ParseAddr(t.Host); err == nil {
		return p.Allows(ip, t.Port)
	}
	return p != nil && p.Invalid == nil
}

// TargetsOptions configure Targets.
type TargetsOptions struct {
	// Policy returns the connector-local policy in force.
	Policy func() *policy.Policy
	// OnHealth gets every change of a route's readiness; normally Sessions.SetReady.
	OnHealth func(*tunnelv1.RouteHealth)
	// UDPMetrics count the udp flows' oversize and dropped payloads; nil keeps them unregistered.
	UDPMetrics *tunnel.UDPMetrics
	// Metrics, if set, time the dials and count the refused ones.
	Metrics *Metrics
	Logger  *slog.Logger
}

// Targets serves the streams gateways open (docs/03-connections.md, "One stream per user
// connection"): for a route of the snapshot, or one removed less than the route drain period ago,
// it dials a target that the connector-local policy allows, writes the PROXY header the target
// asks for, answers StreamResult and relays. It also reports each route's readiness: a route whose
// every target the policy blocks is not_ready(blocked_by_local_policy).
type Targets struct {
	o TargetsOptions

	mu       sync.Mutex
	routes   map[string]Route
	draining map[string]drainingRoute
	health   map[string]*tunnelv1.RouteHealth
	// refused holds, per route, the targets whose dial the policy refused on the resolved address,
	// with the refusal's detail: a name, which the policy judges only once it resolves. A dial of
	// the target that succeeds, a snapshot and a policy change clear them (#551).
	refused map[string]map[string]string
	gen     uint64                // counts Rechecks, so that a dial begun before one records no refusal after it
	live    map[net.Conn]struct{} // the relayed target connections, which a stricter policy closes
	probes  chan struct{}         // the certificate probes running, at most maxProbes
}

type drainingRoute struct {
	r     Route
	until time.Time
}

// NewTargets returns the stream handler of the connector.
func NewTargets(o TargetsOptions) *Targets {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.UDPMetrics == nil {
		o.UDPMetrics, _ = tunnel.NewUDPMetrics(nil)
	}
	return &Targets{o: o, routes: map[string]Route{}, draining: map[string]drainingRoute{}, health: map[string]*tunnelv1.RouteHealth{},
		refused: map[string]map[string]string{}, live: map[net.Conn]struct{}{}, probes: make(chan struct{}, maxProbes)}
}

// Set makes routes the snapshot's routes. A route no longer among them is reported not ready at
// once and still takes streams for the route drain period.
func (t *Targets) Set(routes []Route) {
	t.mu.Lock()
	now := time.Now()
	next := map[string]Route{}
	for _, r := range routes {
		next[r.ID] = r
		delete(t.draining, r.ID)
	}
	var gone []string
	for id, r := range t.routes {
		if _, ok := next[id]; !ok {
			t.draining[id] = drainingRoute{r: r, until: now.Add(routeDrain)}
			delete(t.health, id)
			gone = append(gone, id)
		}
	}
	for id, d := range t.draining {
		if now.After(d.until) {
			delete(t.draining, id)
		}
	}
	t.routes = next
	// A target may keep its ID with a new address: a dial of the old route refused now is not its.
	clear(t.refused)
	t.gen++
	t.mu.Unlock()
	for _, id := range gone {
		t.report(&tunnelv1.RouteHealth{RouteId: id})
	}
	t.Recheck()
}

// Recheck evaluates every route's readiness against the policy in force and reports the changes;
// the connector calls it when the policy file changed, and Set after each snapshot. It forgets the
// names whose dial the policy refused, which the next dial judges again. It also resets every
// relayed connection to a target the policy no longer allows, so that a target taken out of the
// policy is not reachable through a connection opened before, such as an upstream's pooled HTTP/2
// connection.
func (t *Targets) Recheck() {
	p := t.o.Policy()
	t.mu.Lock()
	clear(t.refused)
	t.gen++
	var changed []*tunnelv1.RouteHealth
	for _, id := range slices.Sorted(maps.Keys(t.routes)) {
		if h := t.updateHealthLocked(id, readiness(t.routes[id], p, nil)); h != nil {
			changed = append(changed, h)
		}
	}
	var blocked []net.Conn
	for c := range t.live {
		if !connAllowed(c, p) {
			blocked = append(blocked, c)
		}
	}
	t.mu.Unlock()
	for _, h := range changed {
		t.reportRoute(h)
	}
	for _, c := range blocked {
		t.o.Logger.Info("the local policy no longer allows a target: its connection is reset", "target", c.RemoteAddr().String())
		if l, ok := c.(interface{ SetLinger(sec int) error }); ok {
			_ = l.SetLinger(0)
		}
		_ = c.Close()
	}
}

// trackAllowed records a target connection until the returned function is called, and reports
// whether the policy in force allows it. It checks under the lock Recheck takes after the policy
// changed, so either Recheck finds the connection or this check sees the new policy.
func (t *Targets) trackAllowed(c net.Conn) (func(), bool) {
	t.mu.Lock()
	t.live[c] = struct{}{}
	allowed := connAllowed(c, t.o.Policy())
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		delete(t.live, c)
		t.mu.Unlock()
	}, allowed
}

// connAllowed reports whether the policy allows the address a target connection goes to.
func connAllowed(c net.Conn, p *policy.Policy) bool {
	if p == nil || p.Invalid != nil {
		return false
	}
	var ap netip.AddrPort
	switch a := c.RemoteAddr().(type) {
	case *net.UnixAddr:
		return p.AllowsUnix(a.Name)
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	default:
		return true
	}
	return p.Allows(ap.Addr().Unmap(), ap.Port())
}

// readiness is the route's readiness under the policy: ready while one of its targets is allowed
// and not among refused, the targets whose dial the policy refused on the resolved address.
func readiness(r Route, p *policy.Policy, refused map[string]string) *tunnelv1.RouteHealth {
	h := &tunnelv1.RouteHealth{RouteId: r.ID}
	if p == nil || p.Invalid != nil {
		h.Reason = agentv1.NotReadyReason_NOT_READY_REASON_POLICY_INVALID
		return h
	}
	for _, tg := range r.Targets {
		detail, wasRefused := refused[tg.ID]
		if tg.allowed(p) && !wasRefused {
			return &tunnelv1.RouteHealth{RouteId: r.ID, Ready: true} // no detail of the others: one state, one report
		}
		if h.Detail != "" {
			continue
		}
		if wasRefused {
			h.Detail = detail
		} else {
			h.Detail = tg.blockDetail(p)
		}
	}
	h.Reason = agentv1.NotReadyReason_NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY
	return h
}

func (t *Targets) report(h *tunnelv1.RouteHealth) {
	if t.o.OnHealth != nil {
		t.o.OnHealth(h)
	}
}

// reportRoute reports a change of a route's readiness, then again for as long as the route's
// readiness changed meanwhile: reports of several goroutines may arrive out of order, and the last
// one must carry the route's state, as Sessions keep the last. No lock is held while reporting,
// which sends to gateways.
func (t *Targets) reportRoute(h *tunnelv1.RouteHealth) {
	for h != nil {
		t.report(h)
		t.mu.Lock()
		cur := t.health[h.GetRouteId()]
		t.mu.Unlock()
		if cur == nil || sameHealth(cur, h) {
			return
		}
		h = cur
	}
}

func sameHealth(a, b *tunnelv1.RouteHealth) bool {
	return a.GetReady() == b.GetReady() && a.GetReason() == b.GetReason() && a.GetDetail() == b.GetDetail()
}

// updateHealthLocked records the route's readiness and returns it if it changed, to be reported
// once t.mu is released; nil if it did not. Under t.mu.
func (t *Targets) updateHealthLocked(route string, h *tunnelv1.RouteHealth) *tunnelv1.RouteHealth {
	if old := t.health[route]; old != nil && sameHealth(old, h) {
		return nil
	}
	t.health[route] = h
	return h
}

// generation returns the count of snapshots and Rechecks, which a dial takes with its route.
func (t *Targets) generation() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gen
}

// blocked records a dial of the route's target that the policy refused on the resolved address,
// unless a snapshot or Recheck came after the dial took its route (gen): it judges the target anew.
// Only that target counts as blocked: the route is not ready once none of its targets is allowed
// (#551), and stays ready while another one is.
func (t *Targets) blocked(route, target, detail string, gen uint64) {
	t.o.Metrics.refused(route)
	p := t.o.Policy()
	t.mu.Lock()
	r, active := t.routes[route]
	var h *tunnelv1.RouteHealth
	if active && gen == t.gen {
		if t.refused[route] == nil {
			t.refused[route] = map[string]string{}
		}
		t.refused[route][target] = detail
		h = t.updateHealthLocked(route, readiness(r, p, t.refused[route]))
	}
	t.mu.Unlock()
	t.reportRoute(h)
}

// dialled records a dial of the route's target that the policy allowed: a name refused before
// resolves to an allowed address now, and counts as allowed again, unless a snapshot or Recheck
// came after the dial took its route (gen).
func (t *Targets) dialled(route, target string, gen uint64) {
	t.mu.Lock()
	var h *tunnelv1.RouteHealth
	if _, was := t.refused[route][target]; was && gen == t.gen {
		delete(t.refused[route], target)
		if r, active := t.routes[route]; active {
			h = t.updateHealthLocked(route, readiness(r, t.o.Policy(), t.refused[route]))
		}
	}
	t.mu.Unlock()
	t.reportRoute(h)
}

// Status returns the routes that are not ready, for the resource status of Applied.
func (t *Targets) Status() []*agentv1.ResourceStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*agentv1.ResourceStatus
	for _, id := range slices.Sorted(maps.Keys(t.routes)) {
		if h := t.health[id]; h != nil && !h.GetReady() {
			out = append(out, &agentv1.ResourceStatus{ResourceId: id, Reason: h.GetReason(), Detail: h.GetDetail()})
		}
	}
	return out
}

// route returns a route of the snapshot, or one draining, with the generation it is of.
func (t *Targets) route(id string) (Route, uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r, ok := t.routes[id]; ok {
		return r, t.gen, true
	}
	if d, ok := t.draining[id]; ok && time.Now().Before(d.until) {
		return d.r, t.gen, true
	}
	return Route{}, t.gen, false
}

// Handle serves one stream the gateway opened; it is Options.Streams. A UDP_FLOW stream is one
// flow of a udp route, relayed through a socket of its own.
func (t *Targets) Handle(ctx context.Context, gatewayID string, st tunnel.Stream, open *tunnelv1.StreamOpen) {
	_, span := otel.Tracer("github.com/felix-homelab/rpmgr/internal/connector").Start(tunnel.TraceContext(ctx, open), "rpmgr.connector.dial",
		trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String("rpmgr.route", open.GetRouteId())))
	code, conn, target := t.open(ctx, open)
	// The connection is recorded before the answer and checked against the policy in force then,
	// so a reload either finds it or refuses it here (#525).
	untrack := func() {}
	if conn != nil {
		var allowed bool
		if untrack, allowed = t.trackAllowed(conn); !allowed {
			untrack()
			_ = conn.Close()
			conn, code, target = nil, tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED, ""
		}
	}
	defer untrack()
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		span.SetStatus(codes.Error, code.String())
	}
	span.End()
	if err := tunnel.WriteMessage(st, &tunnelv1.StreamResult{Code: code, TargetId: target}); err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		if conn != nil {
			_ = conn.Close()
		}
		if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			t.o.Logger.Debug("stream refused", "gateway", gatewayID, "route", open.GetRouteId(), "code", code)
		}
		st.SetReliableBoundary()
		_ = st.CloseWrite()
		_ = st.Close()
		return
	}
	st.SetReliableBoundary()
	if open.GetKind() == tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW {
		t.relayUDP(ctx, open.GetRouteId(), st, conn)
		return
	}
	tunnel.Relay(st, conn)
}

func isBlocked(err error) bool {
	var b *policy.BlockedError
	return errors.As(err, &b)
}

// open checks the StreamOpen and dials a target of its route; it returns the target's ID with the
// connection.
func (t *Targets) open(ctx context.Context, open *tunnelv1.StreamOpen) (tunnelv1.ResultCode, net.Conn, string) {
	if c := tunnel.CheckStreamOpen(open); c != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		return c, nil, ""
	}
	r, gen, ok := t.route(open.GetRouteId())
	switch kind := open.GetKind(); {
	case kind != tunnelv1.StreamKind_STREAM_KIND_TCP && kind != tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW:
		return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL, nil, ""
	case !ok:
		return tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN, nil, ""
	case !r.Both && r.UDP != (kind == tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW):
		return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL, nil, ""
	case kind == tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW:
		return t.dialUDP(ctx, r, open, gen)
	}
	timeout := dialUpstream
	if ms := open.GetOpenTimeoutMs(); ms > 0 && time.Duration(ms)*time.Millisecond < timeout {
		timeout = time.Duration(ms) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := &net.Dialer{KeepAlive: tcpKeepAlive, Control: policy.Control(t.o.Policy)}
	code := tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED
	for _, tg := range order(targetsFor(r, open)) {
		network := "tcp"
		if tg.UnixPath != "" {
			network = "unix"
		}
		conn, err := t.o.Metrics.dial(ctx, d, r.ID, network, tg.String(), isBlocked)
		if err != nil {
			var b *policy.BlockedError
			if errors.As(err, &b) {
				t.blocked(r.ID, tg.ID, b.Detail(), gen)
				continue
			}
			code = codeOf(err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		t.dialled(r.ID, tg.ID, gen)
		if h := proxyHeader(tg, open); h != nil {
			if _, err := h.WriteTo(conn); err != nil {
				_ = conn.Close()
				code = tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_RESET
				continue
			}
		}
		return tunnelv1.ResultCode_RESULT_CODE_NO_ERROR, conn, tg.ID
	}
	return code, nil, ""
}

// codeOf maps a dial error to its result code.
func codeOf(err error) tunnelv1.ResultCode {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT
	case errors.Is(err, syscall.ECONNRESET):
		return tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_RESET
	}
	return tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED // refused, unreachable, or a name that does not resolve
}

// targetsFor returns the targets of a route that a stream may use: those of the priority it names,
// which the gateway chose among the route's connectors (D90), else all of them. A priority this
// connector has no target at, as when the gateway runs a newer snapshot than the connector, names
// none.
func targetsFor(r Route, open *tunnelv1.StreamOpen) []Target {
	if open.TargetPriority == nil {
		return r.Targets
	}
	named := slices.DeleteFunc(slices.Clone(r.Targets), func(t Target) bool { return t.Priority != open.GetTargetPriority() })
	if len(named) == 0 {
		return r.Targets
	}
	return named
}

// order returns the targets by priority, lowest first, each priority in a random order weighted by
// the targets' weights (a weight of 0 counts as 1).
func order(ts []Target) []Target {
	type keyed struct {
		t   Target
		key float64
	}
	ks := make([]keyed, len(ts))
	for i, t := range ts {
		w := float64(max(t.Weight, 1))
		// Weighted random sampling without replacement: the largest u^(1/w) first.
		ks[i] = keyed{t: t, key: math.Pow(uniform(), 1/w)}
	}
	slices.SortStableFunc(ks, func(a, b keyed) int {
		if a.t.Priority != b.t.Priority {
			return int(a.t.Priority) - int(b.t.Priority)
		}
		switch {
		case a.key > b.key:
			return -1
		case a.key < b.key:
			return 1
		}
		return 0
	})
	out := make([]Target, len(ks))
	for i, k := range ks {
		out[i] = k.t
	}
	return out
}

// uniform returns a random number in (0, 1].
func uniform() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11+1) / (1 << 53)
}

// proxyHeader is the PROXY protocol header for the target, or nil. Without the client's or the
// listener's address it is a LOCAL header in v2 and UNKNOWN in v1.
func proxyHeader(t Target, open *tunnelv1.StreamOpen) *proxyproto.Header {
	var version byte
	switch t.ProxyProtocol {
	case "v1":
		version = 1
	case "v2":
		version = 2
	default:
		return nil
	}
	src, okSrc := netip.AddrFromSlice(open.GetSrcIp())
	dst, okDst := netip.AddrFromSlice(open.GetDstIp())
	if !okSrc || !okDst {
		return &proxyproto.Header{Version: version, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	}
	return proxyproto.HeaderProxyFromAddrs(version,
		&net.TCPAddr{IP: src.AsSlice(), Port: int(open.GetSrcPort())}, //nolint:gosec // G115: CheckStreamOpen bounds ports
		&net.TCPAddr{IP: dst.AsSlice(), Port: int(open.GetDstPort())}) //nolint:gosec // G115: CheckStreamOpen bounds ports
}
