// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"slices"
	"sync"
	"time"
)

// The stalled-stream rule (docs/03-connections.md, "Timeouts, keepalive and backoff"):
// backpressure is allowed indefinitely, but when the unread bytes held by streams without read
// progress for StallAge exceed half of the session's connection window, the receiver resets those
// streams, oldest first, until the rest is below that. Neither quic-go nor net/http's HTTP/2
// tells how many bytes a stream holds unread, so a stalled stream counts with its full receive
// window, the upper bound: the rule acts at most early, never late.
const (
	StallAge   = 30 * time.Second
	stallCheck = time.Second
)

// Stalls watches the receiving streams of one session.
type Stalls struct {
	age          time.Duration
	streamWindow int
	connWindow   int

	mu      sync.Mutex
	streams map[*stalling]struct{}
	resets  int
}

// NewStalls returns the watcher of a session with the given receive windows; age 0 is StallAge.
func NewStalls(streamWindow, connWindow int, age time.Duration) *Stalls {
	if age == 0 {
		age = StallAge
	}
	return &Stalls{age: age, streamWindow: streamWindow, connWindow: connWindow, streams: map[*stalling]struct{}{}}
}

// Watch wraps a stream whose received bytes this session holds. The stream stalls while its
// reader is not waiting in Read: a reader that waits holds nothing unread, whatever the peer does.
func (s *Stalls) Watch(st Stream) Stream {
	w := &stalling{Stream: st, s: s, since: time.Now()}
	s.mu.Lock()
	s.streams[w] = struct{}{}
	s.mu.Unlock()
	return w
}

// Resets returns how many streams the rule has reset.
func (s *Stalls) Resets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}

// Check applies the rule at now and returns how many streams it reset.
func (s *Stalls) Check(now time.Time) int {
	s.mu.Lock()
	var stalled []*stalling
	for w := range s.streams {
		if !w.reading && now.Sub(w.since) >= s.age {
			stalled = append(stalled, w)
		}
	}
	slices.SortFunc(stalled, func(a, b *stalling) int { return a.since.Compare(b.since) }) // oldest first
	held := len(stalled) * s.streamWindow
	var victims []*stalling
	for _, w := range stalled {
		if held <= s.connWindow/2 {
			break
		}
		victims = append(victims, w)
		held -= s.streamWindow
		delete(s.streams, w)
	}
	s.resets += len(victims)
	s.mu.Unlock()
	for _, w := range victims {
		w.Stream.Abort()
	}
	return len(victims)
}

// Run checks every second until ctx ends.
func (s *Stalls) Run(ctx context.Context) {
	t := time.NewTicker(stallCheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.Check(now)
		}
	}
}

// stalling tracks one stream's reader.
type stalling struct {
	Stream
	s       *Stalls
	reading bool      // the reader waits in Read; guarded by s.mu
	since   time.Time // when the last Read returned; guarded by s.mu
}

func (w *stalling) Read(p []byte) (int, error) {
	w.s.mu.Lock()
	w.reading = true
	w.s.mu.Unlock()
	n, err := w.Stream.Read(p)
	w.s.mu.Lock()
	w.reading, w.since = false, time.Now()
	if err != nil {
		delete(w.s.streams, w) // the receive direction ended
	}
	w.s.mu.Unlock()
	return n, err
}

func (w *stalling) forget() {
	w.s.mu.Lock()
	delete(w.s.streams, w)
	w.s.mu.Unlock()
}

func (w *stalling) Abort() {
	w.forget()
	w.Stream.Abort()
}

func (w *stalling) Close() error {
	w.forget()
	return w.Stream.Close()
}
