// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// flowQueue is how many payloads a flow queues towards its connector before it drops.
const flowQueue = 64

// maxFlows is how many flows a route port keeps (docs/03-connections.md, "UDP routes"); a
// variable for tests.
var maxFlows = 4096

// UDPRoute is a udp route as the gateway serves it, from its snapshot.
type UDPRoute struct {
	ID       string
	Port     uint16
	FlowIdle time.Duration
}

// UDPOptions configure UDPRoutes.
type UDPOptions struct {
	Host     string // the address the routes' ports listen on
	Sessions *Sessions
	Revision func() *agentv1.Revision
	Metrics  *tunnel.UDPMetrics
	Logger   *slog.Logger
}

// UDPRoutes serves the gateway's udp routes (docs/03-connections.md, "UDP routes"): a flow is one
// client address on a route's port; its first datagram opens a UDP_FLOW stream to a connector of
// the route, and its payloads travel as datagrams, or as frames on the stream when they do not fit
// or the session runs over TCP. A port whose route stays keeps its socket and flows across
// snapshots.
type UDPRoutes struct {
	o      UDPOptions
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	ports  map[uint16]*udpPort
	status map[string]*agentv1.ResourceStatus
	closed bool
}

type udpPort struct {
	conn  *net.UDPConn
	route atomic.Pointer[UDPRoute]
	mu    sync.Mutex
	flows map[netip.AddrPort]*flow
}

// flow is one client address on a port.
type flow struct {
	client netip.AddrPort
	queue  chan []byte
	last   atomic.Int64
	done   chan struct{}
	once   sync.Once
}

func (f *flow) touch()              { f.last.Store(time.Now().UnixNano()) }
func (f *flow) close()              { f.once.Do(func() { close(f.done) }) }
func (f *flow) idle() time.Duration { return time.Since(time.Unix(0, f.last.Load())) }

// NewUDPRoutes returns the udp route sockets; Close stops them.
func NewUDPRoutes(o UDPOptions) *UDPRoutes {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Metrics == nil {
		o.Metrics, _ = tunnel.NewUDPMetrics(nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &UDPRoutes{o: o, ctx: ctx, cancel: cancel, ports: map[uint16]*udpPort{}, status: map[string]*agentv1.ResourceStatus{}}
}

// Apply makes routes the served ones and returns those whose port cannot be bound. A port no
// route uses any more closes with its flows.
func (u *UDPRoutes) Apply(routes []UDPRoute) []*agentv1.ResourceStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	want := map[uint16]UDPRoute{}
	for _, r := range routes {
		want[r.Port] = r
	}
	u.status = map[string]*agentv1.ResourceStatus{}
	for port, p := range u.ports {
		if r, ok := want[port]; ok {
			p.route.Store(&r)
			continue
		}
		delete(u.ports, port)
		_ = p.conn.Close()
	}
	for port, r := range want {
		if u.ports[port] != nil {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(u.o.Host, strconv.Itoa(int(port))))
		var conn *net.UDPConn
		if err == nil {
			conn, err = net.ListenUDP("udp", addr)
		}
		if err != nil {
			reason := agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT
			if errors.Is(err, syscall.EADDRINUSE) {
				reason = agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE
			}
			u.status[r.ID] = &agentv1.ResourceStatus{ResourceId: r.ID, Reason: reason, Detail: "udp port " + strconv.Itoa(int(port)) + ": " + err.Error()}
			continue
		}
		p := &udpPort{conn: conn, flows: map[netip.AddrPort]*flow{}}
		p.route.Store(&r)
		u.ports[port] = p
		u.wg.Go(func() { u.read(p) })
		u.wg.Go(func() { u.expire(p) })
	}
	var out []*agentv1.ResourceStatus
	for _, st := range u.status {
		out = append(out, st)
	}
	return out
}

// Close stops every socket and flow.
func (u *UDPRoutes) Close() {
	u.cancel()
	u.mu.Lock()
	u.closed = true
	for port, p := range u.ports {
		_ = p.conn.Close()
		delete(u.ports, port)
	}
	u.mu.Unlock()
	u.wg.Wait()
}

// Flows returns the number of open flows.
func (u *UDPRoutes) Flows() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, p := range u.ports {
		p.mu.Lock()
		n += len(p.flows)
		p.mu.Unlock()
	}
	return n
}

// read takes the port's datagrams and hands each to its flow, opening flows as clients appear;
// it never blocks on a flow.
func (u *UDPRoutes) read(p *udpPort) {
	defer func() {
		p.mu.Lock()
		for _, f := range p.flows {
			f.close()
		}
		p.mu.Unlock()
	}()
	buf := make([]byte, tunnel.MaxUDPPayload)
	for {
		n, client, err := p.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		payload := append([]byte(nil), buf[:n]...)
		p.mu.Lock()
		f := p.flows[client]
		if f == nil && len(p.flows) >= maxFlows {
			p.mu.Unlock()
			u.o.Metrics.Dropped.WithLabelValues(p.route.Load().ID, "flow_limit").Inc()
			continue
		}
		if f == nil {
			f = &flow{client: client, queue: make(chan []byte, flowQueue), done: make(chan struct{})}
			f.touch()
			p.flows[client] = f
			r := p.route.Load()
			u.wg.Go(func() { u.run(p, f, r) })
		}
		p.mu.Unlock()
		f.touch()
		select {
		case f.queue <- payload:
		default:
			u.o.Metrics.Dropped.WithLabelValues(p.route.Load().ID, "queue_full").Inc()
		}
	}
}

// expire ends flows idle for longer than the route's flow idle timeout.
func (u *UDPRoutes) expire(p *udpPort) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-t.C:
		}
		idle := p.route.Load().FlowIdle
		p.mu.Lock()
		for k, f := range p.flows {
			select {
			case <-f.done:
				delete(p.flows, k)
				continue
			default:
			}
			if idle > 0 && f.idle() > idle {
				f.close()
				delete(p.flows, k)
			}
		}
		closed := false
		select {
		case <-u.ctx.Done():
			closed = true
		default:
		}
		p.mu.Unlock()
		if closed {
			return
		}
		if !u.serving(p) {
			return
		}
	}
}

func (u *UDPRoutes) serving(p *udpPort) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, q := range u.ports {
		if q == p {
			return true
		}
	}
	return false
}

// run carries one flow: it opens the UDP_FLOW stream, sends the client's payloads as datagrams
// or frames, and returns the connector's to the client, until the flow ends.
func (u *UDPRoutes) run(p *udpPort, f *flow, r *UDPRoute) {
	defer func() {
		f.close()
		p.mu.Lock()
		if p.flows[f.client] == f {
			delete(p.flows, f.client)
		}
		p.mu.Unlock()
	}()
	open := &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_UDP_FLOW, RouteId: r.ID,
		SrcIp: f.client.Addr().AsSlice(), SrcPort: uint32(f.client.Port())}
	if a, ok := p.conn.LocalAddr().(*net.UDPAddr); ok {
		ap := a.AddrPort()
		open.DstIp, open.DstPort = ap.Addr().Unmap().AsSlice(), uint32(ap.Port())
	}
	if u.o.Revision != nil {
		open.SnapshotRev = u.o.Revision()
	}
	st, err := u.o.Sessions.Open(u.ctx, open)
	if err != nil {
		u.o.Logger.Debug("no stream for a udp flow", "route", r.ID, "error", err)
		return
	}
	defer func() { _ = st.Close() }()
	stop := context.AfterFunc(u.ctx, st.Abort)
	defer stop()
	dg := u.o.Sessions.Datagrams(st)
	id, hasID := tunnel.StreamID(st)
	if !hasID {
		dg = nil
	}
	reply := func(b []byte) {
		f.touch()
		_, _ = p.conn.WriteToUDPAddrPort(b, f.client)
	}
	if dg != nil {
		defer dg.Register(id, reply)()
	}
	// The connector's answer and its frames come on the stream.
	go func() {
		defer f.close()
		res := &tunnelv1.StreamResult{}
		if err := tunnel.ReadMessage(st, res); err != nil || res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
			u.o.Logger.Debug("udp flow refused", "route", r.ID, "code", res.GetCode(), "error", err)
			return
		}
		for {
			b, err := tunnel.ReadFrame(st)
			if err != nil {
				return
			}
			reply(b)
		}
	}()
	// The client's payloads, sent without waiting for the answer: the connector keeps early
	// datagrams of a flow it does not know yet.
	for {
		select {
		case <-f.done:
			return
		case b := <-f.queue:
			if dg != nil && dg.Fits(id, len(b)) {
				if !dg.Send(id, b) {
					u.o.Metrics.Dropped.WithLabelValues(r.ID, "queue_full").Inc()
				}
				continue
			}
			if dg != nil {
				u.o.Metrics.Oversize.WithLabelValues(r.ID).Inc()
			}
			if err := tunnel.WriteFrame(st, b); err != nil {
				return
			}
		}
	}
}
