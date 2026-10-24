// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
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
)

// RouteLimits are this gateway's share of a route's limits, from its snapshot; 0 is no limit.
type RouteLimits struct {
	MaxConnections          uint32
	RequestsPerSecond       uint32
	BandwidthBytesPerSecond uint64
}

// routeLimitsOf reads a snapshot's limits.
func routeLimitsOf(l *agentv1.RouteLimits) RouteLimits {
	return RouteLimits{MaxConnections: l.GetMaxConnections(), RequestsPerSecond: l.GetRequestsPerSecond(),
		BandwidthBytesPerSecond: l.GetBandwidthBytesPerSecond()}
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
		ls.routes[id] = r
	}
	r.set(l)
	return r
}

// Retain forgets the routes not in keep; their connections keep the slots they hold.
func (ls *Limits) Retain(keep map[string]bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for id := range ls.routes {
		if !keep[id] {
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
	bandwidth atomic.Uint64                // bytes per second, 0 is no limit
	in, out   atomic.Pointer[rate.Limiter] // bytes from and to clients; nil is no limit
}

func (r *RouteLimit) set(l RouteLimits) {
	r.max.Store(int64(l.MaxConnections))
	if r.bandwidth.Swap(l.BandwidthBytesPerSecond) == l.BandwidthBytesPerSecond {
		return // the buckets keep their tokens
	}
	for _, b := range []*atomic.Pointer[rate.Limiter]{&r.in, &r.out} {
		if l.BandwidthBytesPerSecond == 0 {
			b.Store(nil)
			continue
		}
		perSecond := float64(l.BandwidthBytesPerSecond)
		b.Store(rate.NewLimiter(rate.Limit(perSecond), max(int(perSecond*bandwidthBurst.Seconds()), tunnel.MaxUDPPayload)))
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

// Conn returns c with the route's bandwidth limit on what it reads (from the client) and what it
// writes (to the client); the limit in force is read at every step, so a change reaches open
// connections.
func (r *RouteLimit) Conn(c net.Conn) net.Conn {
	if r == nil {
		return c
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &limitedConn{Conn: c, r: r, ctx: ctx, cancel: cancel}
}

// limitedConn waits for the route's byte buckets.
type limitedConn struct {
	net.Conn
	r      *RouteLimit
	ctx    context.Context
	cancel context.CancelFunc
}

// step is how many bytes one read or write moves under the bucket b: all of n without a limit.
func step(b *rate.Limiter, n int) int {
	if b == nil {
		return n
	}
	return min(n, b.Burst(), max(int(float64(b.Limit())*bandwidthBurst.Seconds()), bandwidthStep))
}

func (c *limitedConn) Read(p []byte) (int, error) {
	b := c.r.in.Load()
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
		b := c.r.out.Load()
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
