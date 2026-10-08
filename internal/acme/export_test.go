// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"testing"
	"time"
)

// SetLockPoll shortens how often Lock tries again, for one test that must not run in parallel
// with others.
func SetLockPoll(t testing.TB, d time.Duration) {
	old := lockPoll
	lockPoll = d
	t.Cleanup(func() { lockPoll = old })
}
