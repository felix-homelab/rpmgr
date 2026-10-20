// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update

import "testing"

// OnOpen runs f after each staged file is opened, until the test ends.
func OnOpen(t testing.TB, f func(name string)) {
	t.Helper()
	afterOpen = f
	t.Cleanup(func() { afterOpen = nil })
}
