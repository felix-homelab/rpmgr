// SPDX-License-Identifier: Apache-2.0

package password

import "testing"

// SetIDKey replaces argon2id for one test, which must not run in parallel with others.
func SetIDKey(t testing.TB, f func(pw, salt []byte, time, memory uint32, threads uint8, n uint32) []byte) {
	old := idKey
	idKey = f
	t.Cleanup(func() { idKey = old })
}
