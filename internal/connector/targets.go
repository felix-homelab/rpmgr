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
	// UDP routes take UDP_FLOW streams, every other route TCP streams.
	UDP bool
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
	return &Targets{o: o, routes: map[string]Route{}, draining: map[string]drainingRoute{}, health: map[string]*tunnelv1.RouteHealth{}}
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
	t.mu.Unlock()
	for _, id := range gone {
		t.report(&tunnelv1.RouteHealth{RouteId: id})
	}
	t.Recheck()
}

// Recheck evaluates every route's readiness against the policy in force and reports the changes;
// the connector calls it when the policy file changed.
func (t *Targets) Recheck() {
	p := t.o.Policy()
	t.mu.Lock()
	var changed []*tunnelv1.RouteHealth
	for _, id := range slices.Sorted(maps.Keys(t.routes)) {
		h := readiness(t.routes[id], p)
		if old := t.health[id]; old == nil || old.GetReady() != h.GetReady() || old.GetReason() != h.GetReason() || old.GetDetail() != h.GetDetail() {
			t.health[id] = h
			changed = append(changed, h)
		}
	}
	t.mu.Unlock()
	for _, h := range changed {
		t.report(h)
	}
}

func readiness(r Route, p *policy.Policy) *tunnelv1.RouteHealth {
	h := &tunnelv1.RouteHealth{RouteId: r.ID}
	if p == nil || p.Invalid != nil {
		h.Reason = agentv1.NotReadyReason_NOT_READY_REASON_POLICY_INVALID
		return h
	}
	for _, tg := range r.Targets {
		if tg.allowed(p) {
			h.Ready = true
			return h
		}
		if h.Detail == "" {
			h.Detail = tg.String()
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

// blocked marks a route not ready after a dial the policy refused on a resolved address.
func (t *Targets) blocked(route, target string) {
	t.o.Metrics.refused(route)
	h := &tunnelv1.RouteHealth{RouteId: route, Reason: agentv1.NotReadyReason_NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY, Detail: target}
	t.mu.Lock()
	old := t.health[route]
	_, active := t.routes[route]
	if active {
		t.health[route] = h
	}
	t.mu.Unlock()
	if active && (old == nil || old.GetReady() || old.GetDetail() != target) {
		t.report(h)
	}
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

func (t *Targets) route(id string) (Route, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r, ok := t.routes[id]; ok {
		return r, true
	}
	if d, ok := t.draining[id]; ok && time.Now().Before(d.until) {
		return d.r, true
	}
	return Route{}, false
}

// Handle serves one stream the gateway opened; it is Options.Streams. A UDP_FLOW stream is one
// flow of a udp route, relayed through a socket of its own.
func (t *Targets) Handle(ctx context.Context, gatewayID string, st tunnel.Stream, open *tunnelv1.StreamOpen) {
	code, conn, target := t.open(ctx, open)
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
	r, ok := t.route(open.GetRouteId())
	switch kind := open.GetKind(); {
	case kind != tunnelv1.StreamKind_STREAM_KIND_TCP && kind != tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW:
		return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL, nil, ""
	case !ok:
		return tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN, nil, ""
	case r.UDP != (kind == tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW):
		return tunnelv1.ResultCode_RESULT_CODE_PROTOCOL, nil, ""
	case r.UDP:
		return t.dialUDP(ctx, r, open)
	}
	timeout := dialUpstream
	if ms := open.GetOpenTimeoutMs(); ms > 0 && time.Duration(ms)*time.Millisecond < timeout {
		timeout = time.Duration(ms) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := &net.Dialer{KeepAlive: tcpKeepAlive, Control: policy.Control(t.o.Policy)}
	code := tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED
	for _, tg := range order(r.Targets) {
		network := "tcp"
		if tg.UnixPath != "" {
			network = "unix"
		}
		conn, err := t.o.Metrics.dial(ctx, d, r.ID, network, tg.String(), isBlocked)
		if err != nil {
			var b *policy.BlockedError
			if errors.As(err, &b) {
				t.blocked(r.ID, b.Target)
				continue
			}
			code = codeOf(err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
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
