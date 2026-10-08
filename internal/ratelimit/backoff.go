// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"sync"
	"time"
)

// Backoff delays a key, such as an account, after failures in a row (docs/04-security.md, "Human
// authentication and sessions"): after the free-th failure each further attempt must wait, first
// one interval, doubling with every failure up to the maximum; a success forgets the key. It
// delays instead of locking out, so an attacker cannot lock an administrator out for longer than
// the maximum.
type Backoff struct {
	free       int
	first, max time.Duration
	now        func() time.Time

	mu   sync.Mutex
	keys map[string]*failures
}

type failures struct {
	n     int
	until time.Time
}

// NewBackoff returns a Backoff; now may be nil.
func NewBackoff(free int, first, max time.Duration, now func() time.Time) *Backoff {
	if now == nil {
		now = time.Now
	}
	return &Backoff{free: free, first: first, max: max, now: now, keys: map[string]*failures{}}
}

// Wait returns how long key must wait before its next attempt; 0 when it may go ahead.
func (b *Backoff) Wait(key string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f, ok := b.keys[key]; ok {
		if d := f.until.Sub(b.now()); d > 0 {
			return d
		}
	}
	return 0
}

// Fail records a failed attempt of key.
func (b *Backoff) Fail(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.keys[key]
	if !ok {
		if len(b.keys) >= maxKeys {
			b.sweep()
		}
		if len(b.keys) >= maxKeys {
			return // full of keys that wait: the per-address limit still applies
		}
		f = &failures{}
		b.keys[key] = f
	}
	f.n++
	if f.n < b.free {
		return
	}
	d := b.first
	for i := b.free; i < f.n && d < b.max; i++ {
		d *= 2
	}
	f.until = b.now().Add(min(d, b.max))
}

// Succeed forgets key after a successful attempt.
func (b *Backoff) Succeed(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.keys, key)
}

// sweep drops the keys that do not wait now. Those above the free failures start counting again,
// which happens only when maxKeys keys fail at once.
func (b *Backoff) sweep() {
	now := b.now()
	for k, f := range b.keys {
		if f.n < b.free || !now.Before(f.until) {
			delete(b.keys, k)
		}
	}
}
