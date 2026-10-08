// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
