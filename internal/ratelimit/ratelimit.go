// SPDX-License-Identifier: Apache-2.0

// Package ratelimit keeps one token bucket per key, such as a client IP (docs/04-security.md,
// "Human authentication and sessions", rate limiting).
package ratelimit

import (
	"sync"
	"time"
)

// maxKeys bounds the memory of a Limiter. When it is reached, buckets that are full again are
// dropped, at most once per refill interval so a flood of keys costs no more than one scan per
// interval; if none is, new keys are refused until some are. Keys that are being limited are never
// dropped, so a flood of other keys cannot reset them.
const maxKeys = 100_000

// Limiter allows Burst events at once per key and refills one every Every.
type Limiter struct {
	every time.Duration
	burst float64
	now   func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a Limiter of burst events per key, refilled at one per every. now may be nil.
func New(every time.Duration, burst int, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{every: every, burst: float64(burst), now: now, buckets: map[string]*bucket{}}
}

// Allow takes one token of key's bucket and reports whether there was one.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxKeys && now.Sub(l.lastSweep) >= l.every {
			l.sweep(now)
		}
		if len(l.buckets) >= maxKeys {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+float64(now.Sub(b.last))/float64(l.every))
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops the buckets that are full again: forgetting them changes nothing.
func (l *Limiter) sweep(now time.Time) {
	l.lastSweep = now
	for k, b := range l.buckets {
		if b.tokens+float64(now.Sub(b.last))/float64(l.every) >= l.burst {
			delete(l.buckets, k)
		}
	}
}
