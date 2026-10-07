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
