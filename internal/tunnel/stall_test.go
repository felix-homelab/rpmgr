// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"context"
	"errors"
	"io"
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

// TestH2_AdmissionUnderBudget: h2 sessions are admitted against the window budget, each with at
// most half of what is free: the first ones get full windows, later ones smaller ones (the stream
// window a sixteenth of the connection window), and a session that would get less than 4 MiB is
// refused; released reservations are free again. Two links of two sessions each to four gateways
// fit in the default budget.
func TestH2_AdmissionUnderBudget(t *testing.T) {
	b := tunnel.NewBudget(tunnel.DefaultWindowBudget)
	full := tunnel.DefaultH2Windows()
	var releases []func()
	for i, want := range []int{256, 256, 256, 128, 64, 32, 16, 8, 4} {
		w, release, err := b.AdmitH2(full)
		if err != nil || w.Conn != want<<20 || w.Stream != min(full.Stream, (want<<20)/16) {
			t.Fatalf("session %d: %+v %v, want a %d MiB window", i+1, w, err, want)
		}
		releases = append(releases, release)
	}
	if _, _, err := b.AdmitH2(full); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("a tenth session with less than 4 MiB free: %v", err)
	}
	if b.Used() != 1020<<20 {
		t.Fatalf("used %d", b.Used())
	}
	releases[0]()
	releases[0]() // twice is harmless
	for _, release := range releases[1:4] {
		release()
	}
	if b.Used() != (1020-3*256-128)<<20 {
		t.Fatalf("after four releases: used %d", b.Used())
	}
	if w, _, err := b.AdmitH2(full); err != nil || w != full {
		t.Fatalf("after the releases: %+v %v", w, err)
	}
}
