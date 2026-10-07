// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/rand"
	"math/big"
	"time"
)

// Backoff is the reconnect backoff of docs/03-connections.md ("Timeouts, keepalive and backoff"):
// full jitter, base 0.5 s, factor 2, capped, and reset after a connection stayed healthy.
type Backoff struct {
	Base, Cap, ResetAfter time.Duration
	attempt               int
}

// ControlBackoff is the backoff of the control session.
func ControlBackoff() *Backoff {
	return &Backoff{Base: 500 * time.Millisecond, Cap: 30 * time.Second, ResetAfter: time.Minute}
}

// Next returns how long to wait before the next attempt: a uniformly random duration up to
// min(Cap, Base·2^attempt), and at least floor (a Goodbye's retry_after).
func (b *Backoff) Next(floor time.Duration) time.Duration {
	ceiling := b.Cap
	if b.attempt < 30 {
		ceiling = min(b.Cap, b.Base<<b.attempt)
	}
	b.attempt++
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling)+1))
	d := ceiling
	if err == nil {
		d = time.Duration(n.Int64())
	}
	return max(d, floor)
}

// Healthy reports that a connection lasted lasted; after ResetAfter the backoff starts over.
func (b *Backoff) Healthy(lasted time.Duration) {
	if lasted >= b.ResetAfter {
		b.attempt = 0
	}
}
