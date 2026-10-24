// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"sync/atomic"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
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

// Limits keeps the limit state of each route by ID, so that a route's open connections carry over
// from one snapshot to the next.
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
// requests. A nil RouteLimit limits nothing.
type RouteLimit struct {
	max   atomic.Int64 // 0 is no limit
	conns atomic.Int64
}

func (r *RouteLimit) set(l RouteLimits) {
	r.max.Store(int64(l.MaxConnections))
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
