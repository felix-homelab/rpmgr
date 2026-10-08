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

// TestH2_AdmissionUnderBudget: reverse-HTTP/2 sessions are admitted against the process-wide window
// budget, which QUIC sessions share; when it is tight a new session gets smaller windows, and when
// not even 4 MiB fit, none. (The h3 share is Phase 3.)
func TestH2_AdmissionUnderBudget(t *testing.T) {
	b := tunnel.NewBudget(600 << 20)
	full := tunnel.DefaultH2Windows()
	w1, release1, err := b.AdmitH2(full)
	if err != nil || w1 != full {
		t.Fatalf("first session: %+v %v", w1, err)
	}
	if _, _, err := b.AdmitH2(full); err != nil {
		t.Fatal(err)
	}
	w3, release3, err := b.AdmitH2(full)
	if err != nil || w3.Conn != 88<<20 || w3.Stream != (88<<20)/16 {
		t.Fatalf("third session: %+v %v", w3, err)
	}
	if _, _, err := b.AdmitH2(full); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("a fourth session with the budget exhausted: %v", err)
	}
	if b.Used() != 600<<20 {
		t.Fatalf("used %d", b.Used())
	}
	release1()
	release1() // twice is harmless
	release3()
	if b.Used() != 256<<20 {
		t.Fatalf("after two releases: used %d", b.Used())
	}
	if w, _, err := b.AdmitH2(full); err != nil || w != full {
		t.Fatalf("after the releases: %+v %v", w, err)
	}
}
