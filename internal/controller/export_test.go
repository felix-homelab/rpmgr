// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"
	"time"
)

// SetRunTimers shortens the drain wait and the certificate reload interval of Run for one test,
// which must not run in parallel with others.
func SetRunTimers(t testing.TB, drain, reload time.Duration) {
	oldDrain, oldReload := drainWait, webCertReload
	drainWait, webCertReload = drain, reload
	t.Cleanup(func() { drainWait, webCertReload = oldDrain, oldReload })
}
