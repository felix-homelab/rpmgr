// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
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
}

// TCPOptions configure TCPRoutes.
type TCPOptions struct {
	// Host is the address the routes' ports listen on: the host of listen.tcp, "" for every
	// interface.
	Host     string
	Sessions *Sessions
	// Revision returns the revision of the applied snapshot, which every StreamOpen carries.
	Revision func() *agentv1.Revision
	Logger   *slog.Logger
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

	mu      sync.Mutex
	ports   map[uint16]*portListener
	pending map[uint16]TCPRoute // ports that could not be bound yet
	status  map[string]*agentv1.ResourceStatus
	closed  bool
	retry   *time.Timer
}

// portListener is one public port and its connections.
type portListener struct {
	ln    net.Listener
	route atomic.Pointer[TCPRoute]
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// NewTCPRoutes returns the tcp route listeners; Close stops them.
func NewTCPRoutes(o TCPOptions) *TCPRoutes {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPRoutes{o: o, ctx: ctx, cancel: cancel, ports: map[uint16]*portListener{}, pending: map[uint16]TCPRoute{},
		status: map[string]*agentv1.ResourceStatus{}}
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
	want := map[uint16]TCPRoute{}
	for _, r := range routes {
		want[r.Port] = r
	}
	// Prepare.
	bound := map[uint16]net.Listener{}
	t.pending = map[uint16]TCPRoute{}
	t.status = map[string]*agentv1.ResourceStatus{}
	for port, r := range want {
		if t.ports[port] != nil {
			continue
		}
		ln, err := t.listen(port)
		if err != nil {
			t.notBound(r, err)
			continue
		}
		bound[port] = ln
	}
	// Swap.
	for port, pl := range t.ports {
		if r, ok := want[port]; ok {
			pl.route.Store(&r)
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
	return net.Listen("tcp", net.JoinHostPort(t.o.Host, strconv.Itoa(int(port))))
}

// notBound records a route whose port could not be bound. Under t.mu.
func (t *TCPRoutes) notBound(r TCPRoute, err error) {
	t.pending[r.Port] = r
	reason := agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT
	if errors.Is(err, syscall.EADDRINUSE) {
		reason = agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE
	}
	t.status[r.ID] = &agentv1.ResourceStatus{ResourceId: r.ID, Reason: reason, Detail: "port " + strconv.Itoa(int(r.Port)) + ": " + err.Error()}
	t.o.Logger.Warn("cannot listen on a route's port", "route", r.ID, "port", r.Port, "error", err)
}

// rebind tries the pending ports again.
func (t *TCPRoutes) rebind() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.retry = nil
	if t.closed {
		return
	}
	for _, port := range slices.Sorted(maps.Keys(t.pending)) {
		r := t.pending[port]
		ln, err := t.listen(port)
		if err != nil {
			continue
		}
		delete(t.pending, port)
		delete(t.status, r.ID)
		t.serve(ln, r)
		t.o.Logger.Info("listening on a route's port after all", "route", r.ID, "port", port)
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
func (t *TCPRoutes) serve(ln net.Listener, r TCPRoute) {
	pl := &portListener{ln: ln, conns: map[net.Conn]struct{}{}}
	pl.route.Store(&r)
	t.ports[r.Port] = pl
	t.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			pl.mu.Lock()
			pl.conns[c] = struct{}{}
			pl.mu.Unlock()
			t.wg.Go(func() {
				defer func() {
					pl.mu.Lock()
					delete(pl.conns, c)
					pl.mu.Unlock()
				}()
				t.handle(c, pl.route.Load())
			})
		}
	})
}

// retire stops accepting on pl and closes its connections after the route drain period. Under
// t.mu.
func (t *TCPRoutes) retire(pl *portListener) {
	_ = pl.ln.Close()
	time.AfterFunc(routeDrain, pl.abortAll)
}

func (pl *portListener) abortAll() {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for c := range pl.conns {
		abort(c)
	}
}

func abort(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
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
	open := &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: r.ID}
	if t.o.Revision != nil {
		open.SnapshotRev = t.o.Revision()
	}
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ap := a.AddrPort()
		open.SrcIp, open.SrcPort = ap.Addr().Unmap().AsSlice(), uint32(ap.Port())
	}
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		ap := a.AddrPort()
		open.DstIp, open.DstPort = ap.Addr().Unmap().AsSlice(), uint32(ap.Port())
	}
	st, code, err := t.o.Sessions.OpenStream(t.ctx, open)
	if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.o.Logger.Debug("no stream for a connection", "route", r.ID, "code", code, "error", err)
		abort(c)
		return
	}
	if r.IdleTimeout > 0 {
		c = newIdleConn(c, r.IdleTimeout)
	}
	tunnel.Relay(st, c)
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
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.SetLinger(sec)
	}
	return nil
}

func (c *idleConn) Close() error {
	c.timer.Stop()
	return c.Conn.Close()
}
