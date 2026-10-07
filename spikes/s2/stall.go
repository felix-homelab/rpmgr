// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"sort"
	"sync"
	"time"
)

// StallDetector prototypes the receiver-side rule of docs/03-connections.md ("Stalled stream"):
// backpressure is allowed indefinitely, but when the unread bytes held by streams without read
// progress for at least Age exceed half of the connection window, those streams are reset,
// oldest first, until the total is below the threshold.
//
// net/http's HTTP/2 does not expose how many bytes a stream has buffered but not yet handed to
// the reader, so a stalled stream is counted at its full receive window, the upper bound of what
// it can hold. This makes the rule trigger at most early, never late.
type StallDetector struct {
	Age          time.Duration
	StreamWindow int
	ConnWindow   int

	mu      sync.Mutex
	streams map[*Tracked]struct{}
	resets  int
}

// Tracked is one receiving stream under the detector.
type Tracked struct {
	d        *StallDetector
	opened   time.Time
	progress time.Time
	ended    bool
	reset    func()
}

// Track registers a receiving stream; reset is called if the detector resets it.
func (d *StallDetector) Track(reset func()) *Tracked {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.streams == nil {
		d.streams = map[*Tracked]struct{}{}
	}
	now := time.Now()
	t := &Tracked{d: d, opened: now, progress: now, reset: reset}
	d.streams[t] = struct{}{}
	return t
}

// Progress records that the reader consumed bytes.
func (t *Tracked) Progress() {
	t.d.mu.Lock()
	t.progress = time.Now()
	t.d.mu.Unlock()
}

// End removes the stream (EOF, error or reset).
func (t *Tracked) End() {
	t.d.mu.Lock()
	t.ended = true
	delete(t.d.streams, t)
	t.d.mu.Unlock()
}

// Resets is the number of streams the detector has reset.
func (d *StallDetector) Resets() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.resets
}

// Check applies the rule once and returns the number of streams it reset.
func (d *StallDetector) Check(now time.Time) int {
	d.mu.Lock()
	var stalled []*Tracked
	for t := range d.streams {
		if !t.ended && now.Sub(t.progress) >= d.Age {
			stalled = append(stalled, t)
		}
	}
	// Oldest first: the stream whose stall began earliest.
	sort.Slice(stalled, func(i, j int) bool { return stalled[i].progress.Before(stalled[j].progress) })
	held := len(stalled) * d.StreamWindow
	threshold := d.ConnWindow / 2
	var victims []*Tracked
	for _, t := range stalled {
		if held <= threshold {
			break
		}
		victims = append(victims, t)
		held -= d.StreamWindow
		t.ended = true
		delete(d.streams, t)
	}
	d.resets += len(victims)
	d.mu.Unlock()
	for _, t := range victims {
		t.reset()
	}
	return len(victims)
}

// Run checks every interval until stop is closed.
func (d *StallDetector) Run(interval time.Duration, stop <-chan struct{}) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			d.Check(now)
		}
	}
}
