// SPDX-License-Identifier: Apache-2.0

package apisvc

// SetSent sets the hook called after each attempt to e-mail a reset link, so a test knows when
// the background work is done.
func SetSent(a *Auth, f func(error)) { a.sent = f }
