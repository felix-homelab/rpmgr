// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// flowPair opens a stream from the gateway and returns both ends' datagram multiplexers and the
// stream ID, the same on both ends.
func flowPair(t *testing.T) (*tunnel.Datagrams, *tunnel.Datagrams, uint64) {
	t.Helper()
	gw, con, _ := connect(t)
	st, err := gw.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	in := accept(t, con)
	id, ok := tunnel.StreamID(st)
	inID, inOK := tunnel.StreamID(in)
	if !ok || !inOK || id != inID {
		t.Fatalf("stream IDs %d/%v and %d/%v", id, ok, inID, inOK)
	}
	return gw.Datagrams(), con.Datagrams(), id
}

func receiveOne(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram")
		return nil
	}
}

// TestDatagrams_RoundTrip: a flow's payloads travel as datagrams both ways, to the flow registered
// for the stream ID; an unregistered flow gets nothing after it unregisters.
func TestDatagrams_RoundTrip(t *testing.T) {
	g, c, id := flowPair(t)
	atCon, atGw := make(chan []byte, 16), make(chan []byte, 16)
	unreg := c.Register(id, func(p []byte) { atCon <- p })
	g.Register(id, func(p []byte) { atGw <- p })
	if !g.Fits(id, 1000) || g.Fits(id, 2000) {
		t.Fatal("Fits: 1000 bytes fit, 2000 do not")
	}
	if !g.Send(id, []byte("query")) || !bytes.Equal(receiveOne(t, atCon), []byte("query")) {
		t.Fatal("gateway to connector")
	}
	if !c.Send(id, []byte("answer")) || !bytes.Equal(receiveOne(t, atGw), []byte("answer")) {
		t.Fatal("connector to gateway")
	}
	if !g.Send(id, nil) || len(receiveOne(t, atCon)) != 0 {
		t.Fatal("an empty datagram")
	}
	unreg()
	g.Send(id, []byte("late"))
	select {
	case p := <-atCon:
		t.Fatalf("delivered after unregistering: %q", p)
	case <-time.After(300 * time.Millisecond):
	}
	if s := g.Stats(); s.Sent < 3 {
		t.Fatalf("stats %v", s)
	}
}

// TestDatagrams_PendingFlow: datagrams of a flow not registered yet are kept, at most 8, and
// delivered when it registers within a second; later they are gone.
func TestDatagrams_PendingFlow(t *testing.T) {
	g, c, id := flowPair(t)
	for i := range 10 {
		g.Send(id, []byte{byte(i)})
	}
	waitFor := func(cond func() bool) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			if cond() {
				return
			}
		}
		t.Fatal("timed out")
	}
	waitFor(func() bool { return c.Pending() == 1 })
	time.Sleep(100 * time.Millisecond)
	got := make(chan []byte, 16)
	c.Register(id, func(p []byte) { got <- p })
	if n := len(got); n != 8 {
		t.Fatalf("%d kept datagrams delivered, want 8", n)
	}

	// Another flow, registered too late.
	other := id + 4
	g.Send(other, []byte("early"))
	waitFor(func() bool { return c.Pending() == 1 })
	time.Sleep(1100 * time.Millisecond)
	g.Send(other+4, []byte("prunes the old one"))
	waitFor(func() bool { return c.Pending() == 1 })
	late := make(chan []byte, 1)
	c.Register(other, func(p []byte) { late <- p })
	if len(late) != 0 {
		t.Fatal("a datagram older than a second was delivered")
	}

	// Unknown flows are kept up to a limit; the datagrams of more are dropped.
	dropped := c.Stats().Dropped
	for i := range uint64(tunnel.PendingFlows + 10) {
		g.Send(other+8+4*i, []byte("x"))
	}
	waitFor(func() bool { return c.Pending() == tunnel.PendingFlows && c.Stats().Dropped >= dropped+10 })
}

// TestDatagrams_NeverBlock: sending far more than the queue holds returns at once and drops the
// rest, as UDP does.
func TestDatagrams_NeverBlock(t *testing.T) {
	g, _, id := flowPair(t)
	payload := make([]byte, 1000)
	begin := time.Now()
	queued := 0
	for range 20000 {
		if g.Send(id, payload) {
			queued++
		}
	}
	if d := time.Since(begin); d > 2*time.Second {
		t.Fatalf("20000 sends took %s", d)
	}
	if queued == 20000 || g.Stats().Dropped == 0 {
		t.Fatalf("%d of 20000 queued, %v: a full queue must drop", queued, g.Stats())
	}
}

// TestDatagrams_TooLarge: a datagram the path cannot carry is lost and lowers the size that fits,
// so the next ones of that size go as frames.
func TestDatagrams_TooLarge(t *testing.T) {
	g, _, id := flowPair(t)
	if !g.Fits(id, 1400) {
		t.Fatal("1400 bytes are within the ceiling before quic-go reports a limit")
	}
	g.Send(id, make([]byte, 1400))
	for end := time.Now().Add(5 * time.Second); g.Stats().TooLarge == 0 && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if g.Stats().TooLarge != 1 || g.Fits(id, 1400) || !g.Fits(id, 1000) {
		t.Fatalf("after a too-large datagram: %v, fits 1400 %v", g.Stats(), g.Fits(id, 1400))
	}
}

// TestFrames: UDP payloads as frames on a stream, and the frames that are refused.
func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	for _, p := range [][]byte{[]byte("x"), {}, make([]byte, tunnel.MaxUDPPayload)} {
		if err := tunnel.WriteFrame(&buf, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []int{1, 0, tunnel.MaxUDPPayload} {
		p, err := tunnel.ReadFrame(&buf)
		if err != nil || len(p) != want {
			t.Fatalf("frame of %d: %d %v", want, len(p), err)
		}
	}
	if _, err := tunnel.ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("the end before a frame: %v", err)
	}
	if err := tunnel.WriteFrame(&buf, make([]byte, tunnel.MaxUDPPayload+1)); !errors.Is(err, tunnel.ErrFrameTooLarge) {
		t.Fatalf("writing a frame too large: %v", err)
	}
	big := binary.AppendUvarint(nil, tunnel.MaxUDPPayload+1)
	if _, err := tunnel.ReadFrame(bytes.NewReader(big)); !errors.Is(err, tunnel.ErrFrameTooLarge) {
		t.Fatalf("a length too large: %v", err)
	}
	cut := append(binary.AppendUvarint(nil, 10), "short"...)
	if _, err := tunnel.ReadFrame(bytes.NewReader(cut)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a cut frame: %v", err)
	}
}

// TestStreamID_H2: streams of the TCP transport have no ID; their payloads always go as frames.
func TestStreamID_H2(t *testing.T) {
	gw, con := h2Pair(t, tunnel.DefaultH2Windows())
	if _, err := gw.Control(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, err := gw.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tunnel.StreamID(st); ok {
		t.Fatal("an h2 stream has a QUIC stream ID")
	}
	_ = con
}
