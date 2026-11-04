// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"testing"
	"time"
)

// RetryWait is retryWait, for a test of the waits after failures.
var RetryWait = retryWait

// SetLockPoll shortens how often Lock tries again, for one test that must not run in parallel
// with others.
func SetLockPoll(t testing.TB, d time.Duration) {
	old := lockPoll
	lockPoll = d
	t.Cleanup(func() { lockPoll = old })
}

// SetPushTimeout shortens how long gateways have to acknowledge a challenge, for one test that
// must not run in parallel with others.
func SetPushTimeout(t testing.TB, d time.Duration) {
	old := pushTimeout
	pushTimeout = d
	t.Cleanup(func() { pushTimeout = old })
}

// SetOwnRenewCheck shortens how often an Own checks for renewal, for one test that must not run in
// parallel with others.
func SetOwnRenewCheck(t testing.TB, d time.Duration) {
	old := ownRenewCheck
	ownRenewCheck = d
	t.Cleanup(func() { ownRenewCheck = old })
}

// SetOwnHTTP01Only leaves TLS-ALPN-01 out of the Owns created afterwards, or puts it back, for one
// test that must not run in parallel with others.
func SetOwnHTTP01Only(t testing.TB, on bool) {
	ownNoTLSALPN01 = on
	t.Cleanup(func() { ownNoTLSALPN01 = false })
}

// OwnDNS01 reports whether the controller's own certificate has a DNS-01 solver, which it must
// never have (D166).
func OwnDNS01(o *Own) bool { return o.issuer.DNS01Solver != nil }
