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

// Limits keeps the limit state of each route by ID, so that a route's open connections and
// buckets carry over from one snapshot to the next, and the client tables of each rate_limit rule:
// one that every route whose policies carry the rule shares, and one for its udp flows, whose
// sources can be forged, so that a flood of them never fills the table of the other routes (D137).
type Limits struct {
	// Now, if set before the Limits is used, is the clock of the client tables (tests).
	Now func() time.Time

	mu      sync.Mutex
	routes  map[string]*RouteLimit
	clients map[tableKey]*clientTable
	budget  atomic.Int64 // the client entries of all tables
}

// tableKey names a client table: a rule, for udp flows or for the rest.
type tableKey struct {
	rule ClientRate
	udp  bool
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
		ls.routes[id] = r
	}
	r.set(l)
	r.clients.Store(ls.tables(l.Clients, false))
	r.udpClients.Store(ls.tables(l.Clients, true))
	return r
}

// tables returns the client tables of rules, each once, however often a route names it. Under
// ls.mu.
func (ls *Limits) tables(rules []ClientRate, udp bool) *[]*clientTable {
	out := make([]*clientTable, 0, len(rules))
	for _, c := range rules {
		if ls.clients == nil {
			ls.clients = map[tableKey]*clientTable{}
		}
		k := tableKey{rule: c, udp: udp}
		t := ls.clients[k]
		if t == nil {
			t = newClientTable(c, ls.Now, &ls.budget)
			ls.clients[k] = t
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return &out
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
	used := map[*clientTable]bool{}
	for _, r := range ls.routes {
		for _, p := range []*[]*clientTable{r.clients.Load(), r.udpClients.Load()} {
			if p != nil {
				for _, t := range *p {
					used[t] = true
				}
			}
		}
	}
	for k, t := range ls.clients {
		if !used[t] {
			t.drop()
			delete(ls.clients, k)
		}
	}
}

// RouteLimit is the limit state of one route on this gateway: its open connections, flows or
// requests, and a byte bucket for each direction shared by all of them. A nil RouteLimit limits
// nothing.
type RouteLimit struct {
	max        atomic.Int64 // 0 is no limit
	conns      atomic.Int64
	perSecond  atomic.Uint32                  // the route's requests a second, 0 is no limit
	requests   atomic.Pointer[rate.Limiter]   // nil is no limit
	clients    atomic.Pointer[[]*clientTable] // for requests, connections and passthrough
	udpClients atomic.Pointer[[]*clientTable] // for udp flows
	bandwidth  atomic.Uint64                  // bytes per second, 0 is no limit
	in, out    atomic.Pointer[rate.Limiter]   // bytes from and to clients; nil is no limit
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
	if r.bandwidth.Swap(l.BandwidthBytesPerSecond) == l.BandwidthBytesPerSecond {
		return // the buckets keep their tokens
	}
	for _, b := range []*atomic.Pointer[rate.Limiter]{&r.in, &r.out} {
		if l.BandwidthBytesPerSecond == 0 {
			b.Store(nil)
			continue
		}
		perSecond := float64(l.BandwidthBytesPerSecond)
		b.Store(rate.NewLimiter(rate.Limit(perSecond), max(tenth(perSecond), tunnel.MaxUDPPayload)))
	}
}

// Admit checks a new request, connection or flow of client against the route's rates: each
// per-client rule, of udp flows if udp, then the route's total. It takes a client's tokens first
// and gives them back when a later rule or the total refuses, so a client over its rate does not
// use up the route's total, nor a refusal of the total the client's buckets. When it refuses, retry
// is how long until it may come again, and perClient says whether a per-client rule refused it.
func (r *RouteLimit) Admit(client netip.Addr, udp bool) (ok bool, retry time.Duration, perClient bool) {
	if r == nil {
		return true, 0, false
	}
	p := r.clients.Load()
	if udp {
		p = r.udpClients.Load()
	}
	var tables []*clientTable
	if p != nil {
		tables = *p
	}
	key := clientKey(client)
	for i, t := range tables {
		if ok, wait := t.take(key); !ok {
			for _, taken := range tables[:i] {
				taken.refund(key)
			}
			return false, wait, true
		}
	}
	if b := r.requests.Load(); b != nil {
		now := time.Now()
		res := b.ReserveN(now, 1)
		if d := res.DelayFrom(now); d > 0 {
			res.CancelAt(now)
			for _, t := range tables {
				t.refund(key)
			}
			return false, d, false
		}
	}
	return true, 0, false
}

// retryAfter is a wait in whole seconds for Retry-After, at least 1.
func retryAfter(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
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
