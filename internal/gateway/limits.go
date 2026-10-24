// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/ratelimit"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// The byte buckets of a route's bandwidth limit (docs/03-connections.md, "Route limits"): each
// holds a tenth of a second of the rate, but at least the largest UDP payload, so that a datagram
// can pass at any limit; reads and writes wait in steps of at most a tenth of a second of the rate,
// and at least bandwidthStep bytes, so that a low limit slows a connection down without stalling it.
const (
	bandwidthBurst = 100 * time.Millisecond
	bandwidthStep  = 512
	// maxBucket caps a bucket and a step, so that a tenth of a second of the largest rate fits an
	// int on 32-bit platforms too.
	maxBucket = 1 << 30
)

// tenth is a tenth of a second of perSecond bytes, at most maxBucket.
func tenth(perSecond float64) int {
	return int(min(perSecond*bandwidthBurst.Seconds(), maxBucket))
}

// clientKeys is how many client addresses a per-client rate_limit rule of a route keeps on a
// gateway (docs/03-connections.md, "Timeouts, keepalive and backoff"); when they are taken, new
// addresses are refused rather than ones being limited forgotten. A variable for tests.
var clientKeys = 65_536

// RouteLimits are this gateway's share of a route's limits, from its snapshot; 0 is no limit.
type RouteLimits struct {
	MaxConnections          uint32
	RequestsPerSecond       uint32
	BandwidthBytesPerSecond uint64
	// Clients are the route's per-client rate_limit rules; each applies.
	Clients []ClientRate
}

// ClientRate is a rate_limit rule of an access policy: each client, an IPv4 address or an IPv6
// /64, may make PerSecond requests, connections or flows a second, Burst of them at once.
type ClientRate struct {
	Policy           string
	PerSecond, Burst uint32
}

// routeLimitsOf reads a snapshot's limits and the rate_limit rules of its access.
func routeLimitsOf(l *agentv1.RouteLimits, rules []*agentv1.RateLimitRule) RouteLimits {
	out := RouteLimits{MaxConnections: l.GetMaxConnections(), RequestsPerSecond: l.GetRequestsPerSecond(),
		BandwidthBytesPerSecond: l.GetBandwidthBytesPerSecond()}
	for _, r := range rules {
		out.Clients = append(out.Clients, ClientRate{Policy: r.GetPolicyId(), PerSecond: r.GetPerSecond(), Burst: max(r.GetBurst(), 1)})
	}
	return out
}

// Limits keeps the limit state of each route by ID, so that a route's open connections and byte
// buckets carry over from one snapshot to the next.
type Limits struct {
	mu     sync.Mutex
	routes map[string]*RouteLimit
}

// Set makes l the limits of route id and returns the route's state, the same one for the same ID
// until Retain drops it.
func (ls *Limits) Set(id string, l RouteLimits) *RouteLimit {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.routes == nil {
		ls.routes = map[string]*RouteLimit{}
	}
	r := ls.routes[id]
	if r == nil {
		r = &RouteLimit{}
		r.clients.Store(&[]clientTable{})
		ls.routes[id] = r
	}
	r.set(l)
	return r
}

// Retain forgets the routes not in keep once they have no connection open: a removed route's
// connections drain for a while, and a route that comes back meanwhile must count them, or it
// would admit up to twice its limit.
func (ls *Limits) Retain(keep map[string]bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for id, r := range ls.routes {
		if !keep[id] && r.Open() == 0 {
			delete(ls.routes, id)
		}
	}
}

// RouteLimit is the limit state of one route on this gateway: its open connections, flows or
// requests, and a byte bucket for each direction shared by all of them. A nil RouteLimit limits
// nothing.
type RouteLimit struct {
	max       atomic.Int64 // 0 is no limit
	conns     atomic.Int64
	perSecond atomic.Uint32                // the route's requests per second, 0 is no limit
	requests  atomic.Pointer[rate.Limiter] // nil is no limit
	clients   atomic.Pointer[[]clientTable]
	bandwidth atomic.Uint64                // bytes per second, 0 is no limit
	in, out   atomic.Pointer[rate.Limiter] // bytes from and to clients; nil is no limit
}

// clientTable is a rate_limit rule with its clients.
type clientTable struct {
	rule  ClientRate
	table *ratelimit.Limiter
}

func (r *RouteLimit) set(l RouteLimits) {
	r.max.Store(int64(l.MaxConnections))
	if r.perSecond.Swap(l.RequestsPerSecond) != l.RequestsPerSecond {
		var b *rate.Limiter
		if l.RequestsPerSecond > 0 {
			b = rate.NewLimiter(rate.Limit(l.RequestsPerSecond), int(l.RequestsPerSecond))
		}
		r.requests.Store(b)
	}
	// A rule that stays keeps its clients' buckets.
	var old []clientTable
	if p := r.clients.Load(); p != nil {
		old = *p
	}
	next := make([]clientTable, 0, len(l.Clients))
	for _, c := range l.Clients {
		if i := slices.IndexFunc(old, func(t clientTable) bool { return t.rule == c }); i >= 0 {
			next = append(next, old[i])
			continue
		}
		next = append(next, clientTable{rule: c, table: ratelimit.NewSized(time.Second/time.Duration(max(c.PerSecond, 1)), int(c.Burst), clientKeys, nil)})
	}
	r.clients.Store(&next)
	r.setBandwidth(l.BandwidthBytesPerSecond)
}

// Admit checks a new request, connection or flow of client against the route's rates: each
// per-client rule, then the route's total. When it refuses, retry is how long until it may come
// again, and perClient says whether a per-client rule refused it.
func (r *RouteLimit) Admit(client netip.Addr) (ok bool, retry time.Duration, perClient bool) {
	if r == nil {
		return true, 0, false
	}
	if rules := *r.clients.Load(); len(rules) > 0 {
		key := clientKey(client)
		for _, c := range rules {
			if ok, wait := c.table.Take(key); !ok {
				return false, wait, true
			}
		}
	}
	if b := r.requests.Load(); b != nil {
		now := time.Now()
		res := b.ReserveN(now, 1)
		if d := res.DelayFrom(now); d > 0 {
			res.CancelAt(now)
			return false, d, false
		}
	}
	return true, 0, false
}

// clientKey is a client's key in the per-client tables: its IPv4 address, or its IPv6 /64, so that
// a host cannot escape by using many addresses of its own prefix.
func clientKey(ip netip.Addr) string {
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ip.String()
}

// retryAfter is a wait in whole seconds for Retry-After, at least 1.
func retryAfter(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

func (r *RouteLimit) setBandwidth(perSecond uint64) {
	if r.bandwidth.Swap(perSecond) == perSecond {
		return // the buckets keep their tokens
	}
	for _, b := range []*atomic.Pointer[rate.Limiter]{&r.in, &r.out} {
		if perSecond == 0 {
			b.Store(nil)
			continue
		}
		bytes := float64(perSecond)
		b.Store(rate.NewLimiter(rate.Limit(bytes), max(tenth(bytes), tunnel.MaxUDPPayload)))
	}
}

// Acquire takes one of the route's connection slots and returns its release, which may be called
// more than once; ok is false when every slot is taken.
func (r *RouteLimit) Acquire() (release func(), ok bool) {
	if r == nil {
		return func() {}, true
	}
	n := r.conns.Add(1)
	if m := r.max.Load(); m > 0 && n > m {
		r.conns.Add(-1)
		return func() {}, false
	}
	var once sync.Once
	return func() { once.Do(func() { r.conns.Add(-1) }) }, true
}

// Open is the number of slots taken.
func (r *RouteLimit) Open() int64 {
	if r == nil {
		return 0
	}
	return r.conns.Load()
}

// AllowDatagram reports whether a datagram of n bytes fits the route's bandwidth now, towards the
// client if out; one that does not is dropped.
func (r *RouteLimit) AllowDatagram(out bool, n int) bool {
	if r == nil {
		return true
	}
	b := r.in.Load()
	if out {
		b = r.out.Load()
	}
	return b == nil || b.AllowN(time.Now(), n)
}

// Conn returns a client's connection c with the route's bandwidth limit on what it reads (bytes
// from the client) and what it writes (bytes to the client); the limit in force is read at every
// step, so a change reaches open connections.
func (r *RouteLimit) Conn(c net.Conn) net.Conn {
	if r == nil {
		return c
	}
	return newLimitedConn(c, &r.in, &r.out)
}

// UpstreamConn is Conn for a connection towards the route's upstream, as HTTP routes pool them:
// what it reads goes to clients, what it writes comes from them.
func (r *RouteLimit) UpstreamConn(c net.Conn) net.Conn {
	if r == nil {
		return c
	}
	return newLimitedConn(c, &r.out, &r.in)
}

func newLimitedConn(c net.Conn, reads, writes *atomic.Pointer[rate.Limiter]) *limitedConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &limitedConn{Conn: c, reads: reads, writes: writes, ctx: ctx, cancel: cancel}
}

// limitedConn waits for the route's byte buckets: reads for what it reads, writes for what it
// writes.
type limitedConn struct {
	net.Conn
	reads, writes *atomic.Pointer[rate.Limiter]
	ctx           context.Context
	cancel        context.CancelFunc
}

// step is how many bytes one read or write moves under the bucket b: all of n without a limit.
func step(b *rate.Limiter, n int) int {
	if b == nil {
		return n
	}
	return min(n, b.Burst(), max(tenth(float64(b.Limit())), bandwidthStep))
}

func (c *limitedConn) Read(p []byte) (int, error) {
	b := c.reads.Load()
	if len(p) == 0 || b == nil {
		return c.Conn.Read(p)
	}
	n, err := c.Conn.Read(p[:step(b, len(p))])
	if n > 0 {
		if werr := b.WaitN(c.ctx, n); werr != nil && err == nil {
			err = net.ErrClosed
		}
	}
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		b := c.writes.Load()
		k := step(b, len(p)-written)
		if b != nil {
			if err := b.WaitN(c.ctx, k); err != nil {
				return written, net.ErrClosed
			}
		}
		n, err := c.Conn.Write(p[written : written+k])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// CloseWrite half-closes the connection, as Relay needs.
func (c *limitedConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

// SetLinger lets Relay reset the connection.
func (c *limitedConn) SetLinger(sec int) error {
	if l, ok := c.Conn.(lingerer); ok {
		return l.SetLinger(sec)
	}
	return nil
}

func (c *limitedConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}
