// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// TestPick: of two sessions, the one with the lower score wins, and a session whose writes are
// blocked loses against one whose are not, whatever their scores [V VB-18, unit level].
func TestPick(t *testing.T) {
	now := time.Now()
	idle, busy := &dataSession{}, &dataSession{}
	busy.inflight.Store(10)
	for range 50 {
		if got := pick([]*dataSession{idle, busy}, now); got != idle {
			t.Fatal("the busier session was picked")
		}
	}
	blocked := &dataSession{}
	blocked.writing.Store(now.Add(-time.Second).UnixNano())
	for range 50 {
		if got := pick([]*dataSession{blocked, busy}, now); got != busy {
			t.Fatal("a blocked session was picked over an unblocked one")
		}
	}
	young := &dataSession{}
	young.writing.Store(now.Add(-100 * time.Millisecond).UnixNano())
	if young.blocked(now) || !blocked.blocked(now) {
		t.Fatal("blocked after 200 ms, not before")
	}
	if pick([]*dataSession{idle}, now) != idle {
		t.Fatal("a single session")
	}
	// With many sessions every one is picked sometimes: the two are sampled at random.
	sessions := []*dataSession{{}, {}, {}, {}}
	seen := map[*dataSession]bool{}
	for range 200 {
		seen[pick(sessions, now)] = true
	}
	if len(seen) != 4 {
		t.Fatalf("%d of 4 sessions picked", len(seen))
	}
}

// blockingStream's writes wait for release.
type blockingStream struct {
	tunnel.Stream
	release chan struct{}
}

func (b *blockingStream) Write(p []byte) (int, error) { <-b.release; return len(p), nil }
func (b *blockingStream) Abort()                      {}
func (b *blockingStream) Close() error                { return nil }

// TestTrackedStream: a write in progress marks its session blocked after 200 ms and unmarks it when
// it returns; Close and Abort together end the stream's count once.
func TestTrackedStream(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	d := &dataSession{now: func() time.Time { return now }}
	d.inflight.Store(1)
	ts := &trackedStream{Stream: &blockingStream{release: make(chan struct{})}, d: d}
	done := make(chan struct{})
	go func() {
		_, _ = ts.Write([]byte("x"))
		close(done)
	}()
	for d.writing.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	if d.blocked(now.Add(blockedAfter)) || !d.blocked(now.Add(blockedAfter+time.Millisecond)) {
		t.Fatal("a write in progress counts as blocked only after 200 ms")
	}
	close(ts.Stream.(*blockingStream).release)
	<-done
	if d.blocked(now.Add(time.Hour)) {
		t.Fatal("blocked after the write returned")
	}
	_ = ts.Close()
	ts.Abort()
	if n := d.inflight.Load(); n != 0 {
		t.Fatalf("%d streams in flight after Close and Abort, want 0", n)
	}
}
