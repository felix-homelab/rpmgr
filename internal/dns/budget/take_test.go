// SPDX-License-Identifier: Apache-2.0

package budget

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// drain takes requests of kind until one is refused and returns how many it got.
func drain(s *state, now time.Time, kind Kind) int {
	n := 0
	for {
		next, _, ok := take(*s, now, kind)
		if !ok {
			return n
		}
		*s = next
		n++
	}
}

func TestTake_WindowAndDNS01Half(t *testing.T) {
	var s state
	if n := drain(&s, t0, DNS01); n != Dns01Limit {
		t.Fatalf("DNS-01 got %d, want the half, %d", n, Dns01Limit)
	}
	// The job gets the rest, and not a request more: the half is shared, not extra.
	if n := drain(&s, t0.Add(time.Second), Job); n != Limit-Dns01Limit {
		t.Fatalf("the job got %d after DNS-01, want %d", n, Limit-Dns01Limit)
	}
	if _, until, ok := take(s, t0.Add(time.Minute), Job); ok || !until.Equal(t0.Add(Window)) {
		t.Fatalf("spent window: ok %v, retry at %v, want %v", ok, until, t0.Add(Window))
	}
	// DNS-01 never starves the job: the job alone may take the whole window.
	var j state
	if n := drain(&j, t0, Job); n != Limit {
		t.Fatalf("the job alone got %d, want %d", n, Limit)
	}
	// A window after the last one starts afresh, at its first request.
	next, _, ok := take(s, t0.Add(Window), DNS01)
	if !ok || next.used != 1 || next.dns01 != 1 || !next.start.Equal(t0.Add(Window)) {
		t.Fatalf("new window: %+v, %v", next, ok)
	}
	// One nanosecond short of the end, it is the old window.
	if _, _, ok := take(s, t0.Add(Window-time.Nanosecond), Job); ok {
		t.Fatal("the window ended early")
	}
}

func TestTake_RetryAfterBlock(t *testing.T) {
	until := t0.Add(2 * time.Minute)
	s := state{start: t0, blocked: &until}
	if _, u, ok := take(s, t0.Add(time.Minute), Job); ok || !u.Equal(until) {
		t.Fatalf("during the block: %v, %v", u, ok)
	}
	// At the end of the block it lifts, and the window it was in goes on.
	s.used = 7
	next, _, ok := take(s, until, Job)
	if !ok || next.blocked != nil || next.used != 8 {
		t.Fatalf("after the block: %+v, %v", next, ok)
	}
}

// A replica whose clock is ahead writes times the others read in their own past or future. The
// budget errs towards fewer requests, and never locks up.
func TestTake_ClockSkew(t *testing.T) {
	// Another replica's clock is two minutes ahead and started the window: for this one it ends
	// five minutes plus the skew from now, never earlier.
	ahead := t0.Add(2 * time.Minute)
	s := state{start: ahead, used: Limit}
	if _, u, ok := take(s, t0, Job); ok || !u.Equal(ahead.Add(Window)) {
		t.Fatalf("window of a fast replica: %v, %v", u, ok)
	}
	// A window that starts further ahead than a window is long is not honoured: the skew would
	// keep the budget closed for as long as it lasts.
	far := t0.Add(Window + time.Second)
	if _, _, ok := take(state{start: far, used: Limit}, t0, Job); !ok {
		t.Fatal("a window from the far future locked the budget")
	}
	// A replica that is behind reads a window that already ended.
	if _, _, ok := take(state{start: t0.Add(-Window), used: Limit}, t0, Job); !ok {
		t.Fatal("an old window stayed")
	}
	// A block that a replica two minutes ahead wrote ends, for this one, two minutes later than it
	// meant: it waits the skew longer and never less.
	blocked := t0.Add(5*time.Minute + 2*time.Minute)
	if _, u, ok := take(state{start: t0, blocked: &blocked}, t0.Add(5*time.Minute), Job); ok || !u.Equal(blocked) {
		t.Fatalf("a block of a fast replica: %v, %v", u, ok)
	}
	if _, _, ok := take(state{start: t0, blocked: &blocked}, blocked, Job); !ok {
		t.Fatal("the block never lifted")
	}
}
