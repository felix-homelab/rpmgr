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

// AfterCopy runs f after the artifact is copied and before the copy is verified, until the test
// ends.
func AfterCopy(t testing.TB, f func()) {
	t.Helper()
	afterCopy = f
	t.Cleanup(func() { afterCopy = nil })
}
