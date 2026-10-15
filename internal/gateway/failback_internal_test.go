// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net"
	"testing"
)

// TestFailBack: an idle upstream connection closes once the route has a ready session at a better
// priority than when it was dialled, or once its entry left the route; not while the best
// priority's target merely fails with its connector ready, not while a request is in progress, and
// without looking up the best priority for a connection dialled at the best there is (D90).
func TestFailBack(t *testing.T) {
	var (
		best              uint32
		bestOK            = true
		bestCalls, closes int
		entries           = map[string]bool{"con_a/0": true, "con_a/5": true, "con_a/7": true, "con_b/0": true}
	)
	rt := &routeTransport{pooled: map[net.Conn]*pooledConn{},
		best:      func() (uint32, bool) { bestCalls++; return best, bestOK },
		entry:     func(c string, p uint32) bool { return entries[fmt.Sprintf("%s/%d", c, p)] },
		closeIdle: func() { closes++ }}
	dial := func(con string, priority, bestNow uint32) *streamConn {
		t.Helper()
		best = bestNow
		sc := &streamConn{Stream: &trackedStream{Stream: &blockingStream{}, d: &dataSession{connector: con},
			tier: RouteConnector{ID: con, Priority: priority, Ranked: true}}}
		if c, err := rt.pool(sc, sc, nil); err != nil || c != sc {
			t.Fatalf("pool: %v %v", c, err)
		}
		return sc
	}
	check := func(what string, wantCloses int) {
		t.Helper()
		closes = 0
		rt.failBack()
		if closes != wantCloses {
			t.Fatalf("%s: %d closes of the idle connections, want %d", what, closes, wantCloses)
		}
	}

	// con_a's priority 0 refuses, its connector ready, so the best priority stays 0: the fallback's
	// connection at priority 5 is kept alive, and the best is not even looked up.
	outage := dial("con_a", 5, 0)
	bestCalls = 0
	check("priority 0 failing, its connector ready", 0)
	if bestCalls != 0 {
		t.Fatalf("%d lookups of the best priority for a connection dialled at the best", bestCalls)
	}
	_ = outage.Close()
	if len(rt.pooled) != 0 {
		t.Fatalf("%d connections recorded after Close", len(rt.pooled))
	}

	// Dialled at priority 5 while priority 5 was the best ready one: once priority 0 is ready again
	// the connection closes, but not while a request is in progress on it.
	back := dial("con_a", 5, 5)
	best = 5
	check("nothing better ready yet", 0)
	best = 0
	rt.use(back, 1)
	check("a request in progress", 0)
	rt.use(back, -1)
	check("priority 0 ready again", 1)
	bestOK = false
	check("no ready session at all", 0)
	bestOK = true
	_ = back.Close()

	// Dialled at priority 7 after priority 5's target failed, priority 5 the best ready one: kept
	// while the best is still 5, closed once priority 0 is ready.
	deeper := dial("con_a", 7, 5)
	check("priority 5 failing, its connector ready", 0)
	best = 0
	check("priority 0 ready", 1)
	_ = deeper.Close()

	// A connection whose entry left the route closes, whatever the priorities.
	gone := dial("con_b", 0, 0)
	delete(entries, "con_b/0")
	check("its entry left the route", 1)
	_ = gone.Close()

	// An unranked stream, from a controller before D90, is not recorded.
	plain := &streamConn{Stream: &trackedStream{Stream: &blockingStream{}, d: &dataSession{connector: "con_a"}}}
	if _, err := rt.pool(plain, plain, nil); err != nil || len(rt.pooled) != 0 {
		t.Fatalf("an unranked stream: %v, %d recorded", err, len(rt.pooled))
	}
	if c, err := rt.pool(nil, nil, net.ErrClosed); c != nil || err == nil {
		t.Fatalf("a failed dial: %v %v", c, err)
	}
}
