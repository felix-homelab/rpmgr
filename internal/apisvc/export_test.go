// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"testing"
	"time"
)

// SetSent sets the hook called after each attempt to e-mail a reset link, so a test knows when
// the background work is done.
func SetSent(a *Auth, f func(error)) { a.sent = f }

// SetStatusWindow lowers how many revisions a route status reads, for one test that must not run
// in parallel with others.
func SetStatusWindow(t testing.TB, n int) {
	old := statusWindow
	statusWindow = n
	t.Cleanup(func() { statusWindow = old })
}

// SetProbeWait shortens how long ProbeTargetCertificate waits for a connector, for one test.
func SetProbeWait(t testing.TB, d time.Duration) {
	old := probeWait
	probeWait = d
	t.Cleanup(func() { probeWait = old })
}

// CapabilityMissingFor is the route status entry of an agent that lacks caps.
var CapabilityMissingFor = capabilityMissing

// SetLogHeartbeat shortens the heartbeat of live-log streams for one test, which must not run in
// parallel with others.
func SetLogHeartbeat(t testing.TB, d time.Duration) {
	old := logHeartbeat
	logHeartbeat = d
	t.Cleanup(func() { logHeartbeat = old })
}

// SetLogRecheck shortens how often live-log streams admit their caller again, for one test, which
// must not run in parallel with others.
func SetLogRecheck(t testing.TB, d time.Duration) {
	old := logRecheck
	logRecheck = d
	t.Cleanup(func() { logRecheck = old })
}
