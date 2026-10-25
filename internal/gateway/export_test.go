// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"
)

// SetTimeouts shortens the SessionHello and StreamResult timeouts for one test, which must not run
// in parallel with others.
func SetTimeouts(t testing.TB, hello, result time.Duration) {
	oldHello, oldResult := helloTimeout, resultTimeout
	helloTimeout, resultTimeout = hello, result
	t.Cleanup(func() { helloTimeout, resultTimeout = oldHello, oldResult })
}

// SetRouteTimers shortens the route drain period and the rebind interval for one test, which must
// not run in parallel with others.
func SetRouteTimers(t testing.TB, drain, rebind time.Duration) {
	oldDrain, oldRebind := routeDrain, rebindEvery
	routeDrain, rebindEvery = drain, rebind
	t.Cleanup(func() { routeDrain, rebindEvery = oldDrain, oldRebind })
}

// SetUnassignedDrain shortens how long the sessions of a dropped connector keep their streams, for
// one test that must not run in parallel with others.
func SetUnassignedDrain(t testing.TB, d time.Duration) {
	old := unassignedDrain
	unassignedDrain = d
	t.Cleanup(func() { unassignedDrain = old })
}

// SetMaxFlows lowers how many flows a UDP route port keeps, for one test that must not run in
// parallel with others.
func SetMaxFlows(t testing.TB, n int) {
	old := maxFlows
	maxFlows = n
	t.Cleanup(func() { maxFlows = old })
}

// SetHTTPTimers shortens the request-header and upstream-header timeouts for one test, which must
// not run in parallel with others.
func SetHTTPTimers(t testing.TB, readHeader, upstreamHeader time.Duration) {
	oldRead, oldUp := httpReadHeader, httpUpstreamHeader
	httpReadHeader, httpUpstreamHeader = readHeader, upstreamHeader
	t.Cleanup(func() { httpReadHeader, httpUpstreamHeader = oldRead, oldUp })
}

// RouteFor returns the ID of the http route that serves host and path, with the request headers
// header if given, or "".
func RouteFor(h *HTTPRoutes, host, path string, header ...http.Header) string {
	var hdr http.Header
	if len(header) > 0 {
		hdr = header[0]
	}
	if rt := h.routeFor(host, path, hdr); rt != nil {
		return rt.route.Load().ID
	}
	return ""
}

// SetBasicAuthTTL shortens how long basic-auth verifications are cached, for one test that must
// not run in parallel with others.
func SetBasicAuthTTL(t testing.TB, d time.Duration) {
	old := basicAuthTTL
	basicAuthTTL = d
	t.Cleanup(func() { basicAuthTTL = old })
}

// BasicAuthBusy returns how many basic-auth verifications run now.
func (h *HTTPRoutes) BasicAuthBusy() int64 { return int64(h.basic.busy.Load()) }

// RouteTimeouts returns the upstream timeouts in force for http route id.
func RouteTimeouts(h *HTTPRoutes, id string) (header, idle time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rt := h.transports[id]
	return rt.tr.ResponseHeaderTimeout, rt.tr.IdleConnTimeout
}

// LimitOf returns the limit state the applier keeps for a route, nil if none.
func LimitOf(a *Applier, id string) *RouteLimit {
	a.limits.mu.Lock()
	defer a.limits.mu.Unlock()
	return a.limits.routes[id]
}

// SetClientKeys sets how many client addresses a per-client rate_limit rule keeps, for one test.
func SetClientKeys(t testing.TB, n int) {
	old := clientKeys
	clientKeys = n
	t.Cleanup(func() { clientKeys = old })
}

// ClientTables is the number of client tables ls keeps, and the clients of each.
func ClientTables(ls *Limits) []int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	var out []int
	for _, t := range ls.clients {
		out = append(out, t.size())
	}
	return out
}

// SetClientBudget sets how many client entries all tables of a gateway hold, for one test.
func SetClientBudget(t testing.TB, n int) {
	old := clientBudget
	clientBudget = n
	t.Cleanup(func() { clientBudget = old })
}

// AssignedRoutes returns the IDs the applier's assignment holds routes for, sorted.
func AssignedRoutes(a Assignment) []string {
	s := a.(*assignment).cur.Load()
	if s == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(s.routes))
}
