// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// TestFlowControl_StalledStreamsDoNotFreezeSession: four streams whose gateway-side reader stops
// fill the connection window, so the session freezes; the stall rule resets them oldest first
// until their held bytes are at most half the window, and other streams and the session control
// stream flow again.
func TestFlowControl_StalledStreamsDoNotFreezeSession(t *testing.T) {
	w := tunnel.H2Windows{Stream: 1 << 20, Conn: 3 << 20}
	gw, con, gc, cc := h2Session(t, w)
	stalls := tunnel.NewStalls(w.Stream, w.Conn, 200*time.Millisecond)
	var peers []tunnel.Stream
	for range 4 {
		g, c := h2Open(t, gw, con)
		stalls.Watch(g)
		peers = append(peers, c)
		// The four together fill the connection window, before the next stream writes; the
		// gateway never reads them.
		if _, err := c.Write(make([]byte, 768<<10)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond) // a distinct age for each
	}
	// Let the 3.6 MiB reach the 3 MiB connection window before the probe; on a loaded machine
	// the writers need more than the 80 ms above.
	time.Sleep(500 * time.Millisecond)
	g, c := h2Open(t, gw, con)
	wrote := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 256<<10)); wrote <- err }()
	select {
	case <-wrote:
		t.Fatal("the session did not freeze; the test proves nothing")
	case <-time.After(300 * time.Millisecond):
	}
	if n := stalls.Check(time.Now()); n != 3 {
		t.Fatalf("%d streams reset, want 3 (4 MiB held, at most 1.5 MiB may stay)", n)
	}
	// The three oldest were reset: their peers see an error.
	for i, p := range peers[:3] {
		if _, err := io.ReadAll(p); err == nil {
			t.Errorf("stalled stream %d was not reset", i)
		}
	}
	got := make(chan error, 1)
	go func() { _, err := io.ReadFull(g, make([]byte, 256<<10)); got <- err }()
	for name, ch := range map[string]chan error{"write": wrote, "read": got} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("%s after the resets: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the session stayed frozen (%s)", name)
		}
	}
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(gc, make([]byte, 4)); err != nil {
		t.Fatalf("control stream: %v", err)
	}
	if stalls.Resets() != 3 {
		t.Fatalf("%d resets counted", stalls.Resets())
	}
}

// TestFlowControl_PausedClientNotResetWithoutPressure: a paused reader holds data for longer than
// the stall age, but without window pressure it is not reset, and every byte arrives once it reads
// again; a reader waiting for data never counts as stalled.
func TestFlowControl_PausedClientNotResetWithoutPressure(t *testing.T) {
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	stalls := tunnel.NewStalls(16<<20, 256<<20, 100*time.Millisecond)
	paused, c := h2Open(t, gw, con)
	paused = stalls.Watch(paused)
	payload := make([]byte, 4<<20)
	go func() { _, _ = c.Write(payload); _ = c.CloseWrite() }()

	// Many idle streams wait in Read with nothing to read.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range 20 {
		idle, _ := h2Open(t, gw, con)
		idle = stalls.Watch(idle)
		go func() {
			<-ctx.Done()
			idle.Abort()
		}()
		go func() { _, _ = idle.Read(make([]byte, 1)) }()
	}
	time.Sleep(300 * time.Millisecond)
	if n := stalls.Check(time.Now()); n != 0 {
		t.Fatalf("%d streams reset without window pressure", n)
	}
	got, err := io.ReadAll(paused)
	if err != nil || len(got) != len(payload) {
		t.Fatalf("the paused reader got %d bytes: %v", len(got), err)
	}
}

// TestStalls_OldestFirst: of stalled streams, the oldest are reset first, and a stream that ended
// is not counted.
func TestStalls_OldestFirst(t *testing.T) {
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	stalls := tunnel.NewStalls(1<<20, 4<<20, time.Millisecond)
	var watched []tunnel.Stream
	var peers []tunnel.Stream
	for range 4 {
		g, c := h2Open(t, gw, con)
		watched = append(watched, stalls.Watch(g))
		peers = append(peers, c)
		time.Sleep(5 * time.Millisecond)
	}
	_ = watched[0].Close() // ended: not counted
	time.Sleep(10 * time.Millisecond)
	// Three stalled streams hold 3 MiB, the threshold is 2 MiB: one reset, the oldest one left.
	if n := stalls.Check(time.Now()); n != 1 {
		t.Fatalf("%d resets, want 1", n)
	}
	if _, err := io.ReadAll(peers[1]); err == nil {
		t.Fatal("the oldest stalled stream was not the one reset")
	}
}

// TestH2_AdmissionUnderBudget: h2 sessions are admitted against the window budget (03, "Memory
// bound"; D124): at most 64 MiB each, a sixteenth of the free budget once that is less, never
// less than 1 MiB, so about eighty fit in the default budget; the stream window is a sixteenth of
// the connection window; the reservations never exceed the budget; released ones are free again.
func TestH2_AdmissionUnderBudget(t *testing.T) {
	const mib = 1 << 20
	b := tunnel.NewBudget(tunnel.DefaultWindowBudget)
	full := tunnel.DefaultH2Windows()
	var releases []func()
	var windows []int
	for {
		w, release, err := b.AdmitH2(full)
		if errors.Is(err, tunnel.ErrBudget) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if w.Stream != w.Conn/16 || w.Conn < mib || w.Conn > 64*mib {
			t.Fatalf("session %d: %+v", len(windows)+1, w)
		}
		if n := len(windows); n > 0 && w.Conn > windows[n-1] {
			t.Fatalf("session %d got %d, more than the one before (%d)", n+1, w.Conn, windows[n-1])
		}
		if b.Used() > tunnel.DefaultWindowBudget {
			t.Fatalf("the reservations exceed the budget: %d", b.Used())
		}
		windows = append(windows, w.Conn)
		releases = append(releases, release)
		if len(windows) > 1000 {
			t.Fatal("no end to admission")
		}
	}
	// The first session gets the cap, 64 MiB with a 4 MiB stream window; the second a sixteenth
	// of the 960 MiB left; the tenth still more than 32 MiB (a stream window above 2 MiB).
	if windows[0] != 64*mib || windows[1] != 60*mib || windows[9] < 32*mib {
		t.Fatalf("first windows %v", windows[:10])
	}
	if n := len(windows); n < 75 || n > 85 {
		t.Fatalf("%d sessions admitted under the default budget, want about 80", n)
	}
	if last := windows[len(windows)-1]; last != mib {
		t.Fatalf("the last session got %d, want the 1 MiB floor", last)
	}
	if free := tunnel.DefaultWindowBudget - b.Used(); free >= mib {
		t.Fatalf("refused with %d bytes free", free)
	}
	releases[0]()
	releases[0]() // twice is harmless
	again, releaseAgain, err := b.AdmitH2(full)
	if err != nil || again.Conn < 4*mib || again.Conn >= 5*mib {
		t.Fatalf("after one release: %+v %v, want a sixteenth of the 64 MiB freed and the rest", again, err)
	}
	for _, release := range releases[1:] {
		release()
	}
	if b.Used() != uint64(again.Conn) { //nolint:gosec // G115: a window is positive
		t.Fatalf("after every other release: used %d", b.Used())
	}
	releaseAgain()
	if w, _, err := b.AdmitH2(full); err != nil || w != (tunnel.H2Windows{Stream: 4 * mib, Conn: 64 * mib}) {
		t.Fatalf("in an empty budget again: %+v %v", w, err)
	}
}

// TestH2_AdmissionSmallWants: a session that asks for less than the cap or the floor gets what it
// asks for; a budget below the floor admits nothing, and one of exactly the floor one session.
func TestH2_AdmissionSmallWants(t *testing.T) {
	const mib = 1 << 20
	small := tunnel.H2Windows{Stream: 32 << 10, Conn: 512 << 10}
	if w, _, err := tunnel.NewBudget(tunnel.DefaultWindowBudget).AdmitH2(small); err != nil || w != small {
		t.Fatalf("a small want: %+v %v", w, err)
	}
	if _, _, err := tunnel.NewBudget(mib - 1).AdmitH2(tunnel.DefaultH2Windows()); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("below the floor: %v", err)
	}
	b := tunnel.NewBudget(mib)
	if w, _, err := b.AdmitH2(tunnel.DefaultH2Windows()); err != nil || w.Conn != mib || w.Stream != mib/16 {
		t.Fatalf("a budget of exactly the floor: %+v %v", w, err)
	}
	if _, _, err := b.AdmitH2(tunnel.DefaultH2Windows()); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("a second session in a full budget: %v", err)
	}
}

// TestH2_StalledStreamsHoldAtMostTheAdmittedWindow: the memory a session can hold is its admitted
// connection window: streams whose reader stops take no more than that, however much the peer
// writes, so the budget bounds memory under stalled streams.
func TestH2_StalledStreamsHoldAtMostTheAdmittedWindow(t *testing.T) {
	b := tunnel.NewBudget(40 << 20)
	w, release, err := b.AdmitH2(tunnel.DefaultH2Windows())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if w.Conn != 2<<20+512<<10 { // a sixteenth of 40 MiB
		t.Fatalf("admitted %+v", w)
	}
	gw, con, _, _ := h2Session(t, w)
	var sent atomic.Int64
	for range 4 {
		_, c := h2Open(t, gw, con) // the gateway never reads these streams
		go func() {
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Write(buf)
				sent.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(time.Second)
	if got := sent.Load(); got > int64(w.Conn)+int64(4*w.Stream) {
		t.Fatalf("the peer wrote %d bytes into stalled streams, more than the %d MiB window allows", got, w.Conn>>20)
	}
}
