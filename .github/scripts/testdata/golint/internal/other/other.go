// Package other is outside every allow-list.
package other

import "math/rand"

// Jitter may use math/rand: this package handles no keys, tokens or nonces.
func Jitter() int { return rand.Intn(10) } //nolint:gosec // G404 is not the subject of this test
