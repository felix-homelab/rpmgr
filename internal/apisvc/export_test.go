// SPDX-License-Identifier: Apache-2.0

package apisvc

import "testing"

// SetSent sets the hook called after each attempt to e-mail a reset link, so a test knows when
// the background work is done.
func SetSent(a *Auth, f func(error)) { a.sent = f }

// ShellQuote is shellQuote, for a test that runs a shell on its output.
var ShellQuote = shellQuote

// SetStatusWindow lowers how many revisions a route status reads, for one test that must not run
// in parallel with others.
func SetStatusWindow(t testing.TB, n int) {
	old := statusWindow
	statusWindow = n
	t.Cleanup(func() { statusWindow = old })
}
