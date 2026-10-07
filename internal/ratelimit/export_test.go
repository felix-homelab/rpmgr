// SPDX-License-Identifier: Apache-2.0

package ratelimit

// Keys returns the number of buckets a Limiter keeps.
func Keys(l *Limiter) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
