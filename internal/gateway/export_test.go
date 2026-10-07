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
