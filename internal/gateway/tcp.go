// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// Variables for tests.
var (
	// routeDrain is how long the connections of a removed route stay open (docs/03-connections.md,
	// "Timeouts, keepalive and backoff").
	routeDrain = 30 * time.Second
	// rebindEvery is how often a port that was in use is tried again.
	rebindEvery = 5 * time.Second
)

// TCPRoute is a tcp route as the gateway serves it, from its snapshot.
type TCPRoute struct {
	ID   string
	Port uint16
	// IdleTimeout closes a connection without traffic in either direction for this long; 0 never.
	IdleTimeout time.Duration
	// Access is who may connect.
	Access Access
	// Connect is set for a route in http_connect mode, whose port is a CONNECT listener.
	Connect *Connect
	// Limit is the route's limit state; nil limits nothing.
	Limit *RouteLimit
}

// TCPOptions configure TCPRoutes.
type TCPOptions struct {
	// Host is the address the routes' ports listen on: the host of listen.tcp, "" for every
	// interface.
	Host     string
	Sessions *Sessions
	// Revision returns the revision of the applied snapshot, which every StreamOpen carries.
	Revision func() *agentv1.Revision
	// OnChange is told that a route became ready without a new snapshot: its port was bound after
	// all. It must not block; it may be nil.
	OnChange func()
	// Certificates and Default serve the TLS of CONNECT listeners in the mode ConnectTLSBasic.
	Certificates *Certificates
	Default      *tls.Certificate
	Logger       *slog.Logger
	// Listen opens a route's TCP listener on addr (host:port); nil is net.Listen. A gateway that
	// a hand-off started takes the ports the old process handed over here.
	Listen func(port uint16, addr string) (net.Listener, error)
}

// TCPRoutes serves the gateway's tcp routes on their public ports (docs/03-connections.md, "One
// stream per user connection", "Configuration reconciliation"): each connection becomes a stream
// to a connector of the route. A route whose port stays the same keeps its listener and its
// connections across snapshots; a port no route uses any more stops accepting at once and closes
// its connections after the route drain period.
type TCPRoutes struct {
	o      TCPOptions
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	basic *BasicAuth // the proxy credentials of CONNECT listeners

	mu      sync.Mutex
	ports   map[uint16]*portListener
	pending map[uint16][]TCPRoute // ports that could not be bound yet
	status  map[string]*agentv1.ResourceStatus
	closed  bool
	retry   *time.Timer
	removal removalDrain
}

// Bound reports whether a route listens on the port.
func (r *TCPRoutes) Bound(port uint16) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.ports[port]
	return ok
}

// portListener is one public port and its connections: a tcp route's, or a CONNECT listener's
// routes.
type portListener struct {
	ln      net.Listener
	route   atomic.Pointer[TCPRoute]     // a plain tcp route
	connect atomic.Pointer[connectTable] // or a CONNECT listener's routes
	mu      sync.Mutex
	conns   map[net.Conn]string // by the ID of the route they reach; "" while a CONNECT is read
}

// set makes routes the port's: one plain route, or the routes of a CONNECT listener.
func (pl *portListener) set(routes []TCPRoute) {
	if routes[0].Connect != nil {
		pl.connect.Store(newConnectTable(routes))
		pl.route.Store(nil)
		return
	}
	pl.route.Store(&routes[0])
	pl.connect.Store(nil)
}

// NewTCPRoutes returns the tcp route listeners; Close stops them.
func NewTCPRoutes(o TCPOptions) *TCPRoutes {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPRoutes{o: o, ctx: ctx, cancel: cancel, ports: map[uint16]*portListener{}, pending: map[uint16][]TCPRoute{},
		status: map[string]*agentv1.ResourceStatus{}, basic: NewBasicAuth(nil)}
}

// Apply makes routes the served ones and returns the routes that are not ready: a port that cannot
// be bound is not_ready(port_in_use) and is tried again every few seconds. Listeners for new
// ports are bound before anything changes, then swapped in.
func (t *TCPRoutes) Apply(routes []TCPRoute) []*agentv1.ResourceStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	want := map[uint16][]TCPRoute{} // one plain route per port, or the routes of a CONNECT listener
	var rules []BasicAuthRule
	for _, r := range routes {
		want[r.Port] = append(want[r.Port], r)
		if r.Connect != nil {
			rules = append(rules, r.Connect.BasicAuth...)
		}
	}
	t.basic.Retain(rules)
	// Prepare.
	bound := map[uint16]net.Listener{}
	t.pending = map[uint16][]TCPRoute{}
	t.status = map[string]*agentv1.ResourceStatus{}
	for port, rs := range want {
		if t.ports[port] != nil {
			continue
		}
		ln, err := t.listen(port)
		if err != nil {
			t.notBound(port, rs, err)
			continue
		}
		bound[port] = ln
	}
	// Swap.
	for port, pl := range t.ports {
		if rs, ok := want[port]; ok {
			oldRoute, oldTable := pl.route.Load(), pl.connect.Load()
			pl.set(rs)
			pl.enforce(oldRoute, oldTable)
			continue
		}
		delete(t.ports, port)
		t.retire(pl)
	}
	for port, ln := range bound {
		t.serve(ln, want[port])
	}
	if len(t.pending) > 0 && t.retry == nil {
		t.retry = time.AfterFunc(rebindEvery, t.rebind)
	}
	return t.statusLocked()
}

func (t *TCPRoutes) listen(port uint16) (net.Listener, error) {
	addr := net.JoinHostPort(t.o.Host, strconv.Itoa(int(port)))
	if t.o.Listen != nil {
		return t.o.Listen(port, addr)
	}
	return net.Listen("tcp", addr)
}

// notBound records the routes of a port that could not be bound. Under t.mu.
func (t *TCPRoutes) notBound(port uint16, rs []TCPRoute, err error) {
	t.pending[port] = rs
	reason := agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT
	if errors.Is(err, syscall.EADDRINUSE) {
		reason = agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE
	}
	for _, r := range rs {
		t.status[r.ID] = &agentv1.ResourceStatus{ResourceId: r.ID, Reason: reason, Detail: "port " + strconv.Itoa(int(port)) + ": " + err.Error()}
		t.o.Logger.Warn("cannot listen on a route's port", "route", r.ID, "port", port, "error", err)
	}
}

// rebind tries the pending ports again.
func (t *TCPRoutes) rebind() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.retry = nil
	if t.closed {
		return
	}
	bound := false
	for _, port := range slices.Sorted(maps.Keys(t.pending)) {
		rs := t.pending[port]
		ln, err := t.listen(port)
		if err != nil {
			continue
		}
		delete(t.pending, port)
		for _, r := range rs {
			delete(t.status, r.ID)
		}
		t.serve(ln, rs)
		t.o.Logger.Info("listening on a route's port after all", "route", rs[0].ID, "port", port)
		bound = true
	}
	if bound && t.o.OnChange != nil {
		t.o.OnChange()
	}
	if len(t.pending) > 0 {
		t.retry = time.AfterFunc(rebindEvery, t.rebind)
	}
}

// Status returns the routes that are not ready.
func (t *TCPRoutes) Status() []*agentv1.ResourceStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.statusLocked()
}

func (t *TCPRoutes) statusLocked() []*agentv1.ResourceStatus {
	var out []*agentv1.ResourceStatus
	for _, id := range slices.Sorted(maps.Keys(t.status)) {
		out = append(out, t.status[id])
	}
	return out
}

// serve starts accepting on a new port. Under t.mu.
func (t *TCPRoutes) serve(ln net.Listener, rs []TCPRoute) {
	pl := &portListener{ln: ln, conns: map[net.Conn]string{}}
	pl.set(rs)
	t.ports[rs[0].Port] = pl
	t.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Checked and recorded under pl.mu, which enforce takes after Apply swapped the route
			// in: either enforce sees the connection, or the check sees the new rules (#523). A
			// CONNECT's route is known only once its request is read; a peer that no route of the
			// listener admits is dropped at once.
			pl.mu.Lock()
			r, table := pl.route.Load(), pl.connect.Load()
			if r != nil && !r.Access.AllowsAddr(c.RemoteAddr()) || table != nil && !table.admits(c.RemoteAddr()) {
				pl.mu.Unlock()
				abort(c)
				continue
			}
			// A CONNECT's limits apply once its route is known (handleConnect).
			release, id := func() {}, ""
			if r != nil {
				if ok, _, _ := r.Limit.Admit(addrOf(c.RemoteAddr()), false); !ok {
					pl.mu.Unlock()
					abort(c) // over a rate of the route or of its client: reset before a stream opens
					continue
				}
				var ok bool
				if release, ok = r.Limit.Acquire(); !ok {
					pl.mu.Unlock()
					abort(c) // over the route's connection limit: reset before a stream opens
					continue
				}
				id = r.ID
			}
			pl.conns[c] = id
			pl.mu.Unlock()
			t.wg.Go(func() {
				defer func() {
					release()
					pl.mu.Lock()
					delete(pl.conns, c)
					pl.mu.Unlock()
				}()
				if table != nil {
					t.handleConnect(c, pl, table)
					return
				}
				t.handle(c, r)
			})
		}
	})
}

// retire stops accepting on pl and closes its connections after the route drain period. Under
// t.mu.
func (t *TCPRoutes) retire(pl *portListener) {
	_ = pl.ln.Close()
	time.AfterFunc(t.removal.period(), pl.abortAll)
}

// SetRemovalDrain sets how long the connections of a route removed from now on stay open; 0 is
// the route drain period.
func (t *TCPRoutes) SetRemovalDrain(d time.Duration) { t.removal.Store(int64(d)) }

// removalDrain is how long the connections of a removed route stay open: the route drain period,
// or for a disabled gateway the gateway drain period (R22).
type removalDrain struct{ atomic.Int64 }

func (r *removalDrain) period() time.Duration {
	if d := time.Duration(r.Load()); d > 0 {
		return d
	}
	return routeDrain
}

// enforce resets the connections the port's new routes no longer allow, given the route or
// CONNECT table the port had before: a tightened policy applies at once (docs/03-connections.md,
// "Configuration reconciliation"). A CONNECT tunnel is reset when its listener's org, mode or name
// changed, its route went or changed its credentials, or the route's access rules refuse it now;
// a connection still reading its CONNECT is left to its own check.
func (pl *portListener) enforce(oldRoute *TCPRoute, oldTable *connectTable) {
	r, table := pl.route.Load(), pl.connect.Load()
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for c, id := range pl.conns {
		switch {
		case r != nil && oldRoute != nil && r.Access.Same(oldRoute.Access):
		case r != nil && oldRoute != nil:
			if !r.Access.AllowsAddr(c.RemoteAddr()) {
				abort(c)
			}
		case table != nil && oldTable != nil:
			if id != "" && !table.keeps(oldTable, id, c.RemoteAddr()) {
				abort(c)
			}
		default: // the port changed between a plain route and a CONNECT listener, or the listener changed
			abort(c)
		}
	}
}

func (pl *portListener) abortAll() {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for c := range pl.conns {
		abort(c)
	}
}

// lingerer is a TCP connection, or a wrapper of one, that can be reset.
type lingerer interface{ SetLinger(sec int) error }

// abort resets c, so the client sees the failure at once; a connection that cannot be reset is
// closed.
func abort(c net.Conn) {
	if l, ok := c.(lingerer); ok {
		_ = l.SetLinger(0)
	}
	_ = c.Close()
}

// Drain stops accepting on every port and binds no new ones; open connections carry on until
// Close.
func (t *TCPRoutes) Drain() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.retry != nil {
		t.retry.Stop()
	}
	for _, pl := range t.ports {
		_ = pl.ln.Close()
	}
}

// Conns returns the number of open public connections.
func (t *TCPRoutes) Conns() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, pl := range t.ports {
		pl.mu.Lock()
		n += len(pl.conns)
		pl.mu.Unlock()
	}
	return n
}

// Close stops every listener and closes every connection.
func (t *TCPRoutes) Close() {
	t.cancel()
	t.mu.Lock()
	t.closed = true
	if t.retry != nil {
		t.retry.Stop()
	}
	for port, pl := range t.ports {
		_ = pl.ln.Close()
		pl.abortAll()
		delete(t.ports, port)
	}
	t.mu.Unlock()
	t.wg.Wait()
}

// handle carries one public connection over a stream to a connector of the route. A connection
// that gets no stream is reset, as an unreachable service would reset it.
func (t *TCPRoutes) handle(c net.Conn, r *TCPRoute) {
	carry(t.ctx, t.o.Sessions, t.o.Revision, t.o.Logger, c, r.ID, "", r.IdleTimeout, r.Limit)
}

// carry opens a stream for a route on one of its connectors' sessions and relays c over it, with
// the client's and the listener's address and, for TLS passthrough, the SNI in StreamOpen. A
// connection that gets no stream is reset, as an unreachable service would reset it. lim limits its
// bandwidth.
func carry(ctx context.Context, s *Sessions, rev func() *agentv1.Revision, logger *slog.Logger, c net.Conn, routeID, sni string,
	idle time.Duration, lim *RouteLimit) {
	st, err := openStream(ctx, s, rev, c, routeID, sni)
	if err != nil {
		logger.Debug("no stream for a connection", "route", routeID, "error", err)
		abort(c)
		return
	}
	relayConn(st, c, idle, lim)
}

// openStream opens a stream for a route on one of its connectors' sessions, for the connection c.
func openStream(ctx context.Context, s *Sessions, rev func() *agentv1.Revision, c net.Conn, routeID, sni string) (tunnel.Stream, error) {
	open := &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: routeID, Sni: sni}
	if rev != nil {
		open.SnapshotRev = rev()
	}
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ap := a.AddrPort()
		open.SrcIp, open.SrcPort = ap.Addr().Unmap().AsSlice(), uint32(ap.Port())
	}
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		ap := a.AddrPort()
		open.DstIp, open.DstPort = ap.Addr().Unmap().AsSlice(), uint32(ap.Port())
	}
	st, code, err := s.OpenStream(ctx, open)
	if err == nil && code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		err = fmt.Errorf("gateway: stream refused: %v", code)
	}
	return st, err
}

// relayConn relays c over the stream st, within the route's bandwidth lim, closing c after the
// route's idle timeout without traffic; 0 never.
func relayConn(st tunnel.Stream, c net.Conn, idle time.Duration, lim *RouteLimit) {
	if idle > 0 {
		c = newIdleConn(c, idle)
	}
	tunnel.Relay(st, lim.Conn(c))
}

// idleConn closes its connection when no byte moved in either direction for the idle timeout.
type idleConn struct {
	net.Conn
	idle  time.Duration
	last  atomic.Int64
	timer *time.Timer
}

func newIdleConn(c net.Conn, idle time.Duration) *idleConn {
	ic := &idleConn{Conn: c, idle: idle}
	ic.touch()
	ic.timer = time.AfterFunc(idle, ic.check)
	return ic
}

func (c *idleConn) touch() { c.last.Store(time.Now().UnixNano()) }

func (c *idleConn) check() {
	if left := c.idle - time.Since(time.Unix(0, c.last.Load())); left > 0 {
		c.timer.Reset(left)
		return
	}
	abort(c.Conn)
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

// CloseWrite half-closes the connection, as Relay needs.
func (c *idleConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

// SetLinger lets Relay reset the connection.
func (c *idleConn) SetLinger(sec int) error {
	if l, ok := c.Conn.(lingerer); ok {
		return l.SetLinger(sec)
	}
	return nil
}

func (c *idleConn) Close() error {
	c.timer.Stop()
	return c.Conn.Close()
}
