// SPDX-License-Identifier: Apache-2.0

package webhook

import "time"

// The schedule of deliveries (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	RetryFirst    = 10 * time.Second
	RetryMax      = time.Hour
	GiveUp        = 24 * time.Hour      // after the event
	PerEndpoint   = 4                   // deliveries at once
	DisableAfter  = 3 * 24 * time.Hour  // without a success while deliveries failed
	PreviousSigns = 24 * time.Hour      // after a secret rotation
	KeepFor       = 30 * 24 * time.Hour // deliveries
	KeepAtMost    = 1000                // deliveries per endpoint
)

// Next is when the attempt after a failed attempt n at sent, of an event of at, is due: 10 s after
// the first, doubling to 1 h; ok is false once that is past GiveUp after the event.
func Next(n int, sent, at time.Time) (time.Time, bool) {
	d := RetryFirst
	for i := 1; i < n && d < RetryMax; i++ {
		d *= 2
	}
	next := sent.Add(min(d, RetryMax))
	return next, !next.After(at.Add(GiveUp))
}
