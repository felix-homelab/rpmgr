// SPDX-License-Identifier: Apache-2.0

package allinone

import "testing"

// SetStarted makes Run call f once it has taken SIGHUP over, until the test ends.
func SetStarted(t testing.TB, f func()) {
	old := started
	started = f
	t.Cleanup(func() { started = old })
}
