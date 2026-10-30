// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"sync/atomic"
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

	base time.Time // the monotonic origin of every stream's since

	mu      sync.Mutex // guards streams and resets; the per-Read state is atomic, off this lock
	streams map[*stalling]struct{}
	resets  int
}

// NewStalls returns the watcher of a session with the given receive windows; age 0 is StallAge.
func NewStalls(streamWindow, connWindow int, age time.Duration) *Stalls {
	if age == 0 {
		age = StallAge
	}
	return &Stalls{age: age, streamWindow: streamWindow, connWindow: connWindow, streams: map[*stalling]struct{}{}, base: time.Now()}
}

// Watch wraps a stream whose received bytes this session holds. The stream stalls while its
// reader is not waiting in Read: a reader that waits holds nothing unread, whatever the peer does.
func (s *Stalls) Watch(st Stream) Stream {
	w := &stalling{Stream: st, s: s}
	w.since.Store(int64(time.Since(s.base)))
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
	at := int64(now.Sub(s.base))
	s.mu.Lock()
	var stalled []*stalling
	for w := range s.streams {
		// since is stored before reading is cleared, so a Read that just returned never looks old.
		if !w.reading.Load() && time.Duration(at-w.since.Load()) >= s.age {
			stalled = append(stalled, w)
		}
	}
	slices.SortFunc(stalled, func(a, b *stalling) int { return cmp.Compare(a.since.Load(), b.since.Load()) }) // oldest first
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
		w.reset.Store(true)
		w.Stream.Abort()
		if f := w.onReset.Load(); f != nil {
			(*f)()
		}
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

// stalling tracks one stream's reader. Read takes no lock: a hot stream must not contend with the
// session's other streams on the watcher's mutex.
type stalling struct {
	Stream
	s       *Stalls
	reading atomic.Bool  // the reader waits in Read
	since   atomic.Int64 // when the last Read returned, as time since s.base

	reset   atomic.Bool            // the rule reset the stream
	onReset atomic.Pointer[func()] // called after the rule's reset; see OnReset
}

// resetNotifier is a stream that tells when the stalled-stream rule resets it.
type resetNotifier interface {
	OnReset(f func()) (stop func())
}

// OnReset registers f, which runs, in the goroutine of the rule, once the rule has reset the
// stream, and at once if it already has. The relay needs it: it may be blocked writing to a target
// that does not read, which a reset of the stream alone does not wake. stop unregisters f.
func (w *stalling) OnReset(f func()) (stop func()) {
	w.onReset.Store(&f)
	if w.reset.Load() {
		f()
	}
	return func() { w.onReset.Store(nil) }
}

// Unwrap lets Conn find the deadlines of the stream below.
func (w *stalling) Unwrap() Stream { return w.Stream }

func (w *stalling) Read(p []byte) (int, error) {
	w.reading.Store(true)
	n, err := w.Stream.Read(p)
	w.since.Store(int64(time.Since(w.s.base)))
	w.reading.Store(false)
	if err != nil {
		w.forget() // the receive direction ended
	}
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

// onReset finds the reset notification of st or of a stream it wraps.
func onReset(st Stream) (resetNotifier, bool) {
	for {
		switch s := st.(type) {
		case resetNotifier:
			return s, true
		case interface{ Unwrap() Stream }:
			st = s.Unwrap()
		default:
			return nil, false
		}
	}
}
