// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// h2Pair is a gateway and a connector on one loopback TCP connection; the transport does not care
// whether TLS is below it.
func h2Pair(t *testing.T, w tunnel.H2Windows) (*tunnel.H2Gateway, *tunnel.H2Connector) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	dialled, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	con := tunnel.ServeH2Connector(dialled, w)
	gw, err := tunnel.NewH2Gateway(<-accepted, w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close(); _ = con.Close() })
	return gw, con
}

// h2Session opens the control stream on both sides and returns them.
func h2Session(t *testing.T, w tunnel.H2Windows) (gw *tunnel.H2Gateway, con *tunnel.H2Connector, gc, cc tunnel.Stream) {
	t.Helper()
	gw, con = h2Pair(t, w)
	gc, err := gw.Control(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gc.Write([]byte("hello")); err != nil { // the request reaches the connector with data
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if cc, err = con.Control(ctx); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(cc, buf); err != nil {
		t.Fatal(err)
	}
	return gw, con, gc, cc
}

func h2Open(t *testing.T, gw *tunnel.H2Gateway, con *tunnel.H2Connector) (g, c tunnel.Stream) {
	t.Helper()
	g, err := gw.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err = con.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return g, c
}

// TestH2_ConnectorFINKeepsClientDirection: after the connector's in-band FIN the gateway reads
// EOF, not a reset, and every byte the client still sends reaches the service; the response ends
// only after both directions ended.
func TestH2_ConnectorFINKeepsClientDirection(t *testing.T) {
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	g, c := h2Open(t, gw, con)
	if _, err := c.Write([]byte("service bytes")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(g)
	if err != nil || string(got) != "service bytes" {
		t.Fatalf("gateway read %q, %v; want the bytes and EOF", got, err)
	}
	// The client keeps sending after the service's FIN.
	payload := bytes.Repeat([]byte("client after FIN "), 256<<10) // 4.25 MiB
	sent := make(chan error, 1)
	go func() {
		_, err := g.Write(payload)
		if err == nil {
			err = g.CloseWrite()
		}
		sent <- err
	}()
	rest, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(rest, payload) {
		t.Fatalf("connector read %d of %d bytes after its FIN: %v", len(rest), len(payload), err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	_ = g.Close()
	_ = c.Close()
}

// TestH2_Duplex moves 1 GiB in each direction at once (64 MiB under the race detector) and checks
// both with SHA-256.
func TestH2_Duplex(t *testing.T) {
	size := int64(1 << 30)
	if raceEnabled || testing.Short() {
		size = 64 << 20
	}
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	g, c := h2Open(t, gw, con)
	type result struct {
		n   int64
		sum [32]byte
		err error
	}
	recv := func(r io.Reader, out chan<- result) {
		h := sha256.New()
		n, err := io.Copy(h, r)
		var res result
		res.n, res.err = n, err
		copy(res.sum[:], h.Sum(nil))
		out <- res
	}
	send := func(w tunnel.Stream, seed byte) {
		go func() {
			_, _ = io.Copy(w, io.LimitReader(pattern(seed), size))
			_ = w.CloseWrite()
		}()
	}
	gotC, gotG := make(chan result, 1), make(chan result, 1)
	go recv(c, gotC)
	go recv(g, gotG)
	send(g, 1)
	send(c, 2)
	want := func(seed byte) [32]byte {
		h := sha256.New()
		_, _ = io.Copy(h, io.LimitReader(pattern(seed), size))
		var s [32]byte
		copy(s[:], h.Sum(nil))
		return s
	}
	for name, tc := range map[string]struct {
		ch   chan result
		seed byte
	}{"gateway → connector": {gotC, 1}, "connector → gateway": {gotG, 2}} {
		r := <-tc.ch
		if r.err != nil || r.n != size || r.sum != want(tc.seed) {
			t.Fatalf("%s: %d bytes, %v, checksum match %v", name, r.n, r.err, r.sum == want(tc.seed))
		}
	}
}

// pattern is an endless, seeded byte stream.
func pattern(seed byte) io.Reader { return &patternReader{b: seed} }

type patternReader struct{ b byte }

func (p *patternReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = p.b
		p.b = p.b*31 + 7
	}
	return len(buf), nil
}

// TestH2_Abort: an abort on either side is an error at the other end, never a clean EOF.
func TestH2_Abort(t *testing.T) {
	for _, who := range []string{"gateway", "connector"} {
		t.Run(who, func(t *testing.T) {
			gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
			g, c := h2Open(t, gw, con)
			if _, err := c.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			if _, err := g.Write([]byte("y")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1)
			if _, err := io.ReadFull(g, buf); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatal(err)
			}
			peer := c
			if who == "gateway" {
				g.Abort()
			} else {
				c.Abort()
				peer = g
			}
			done := make(chan error, 1)
			go func() { _, err := io.ReadAll(peer); done <- err }()
			select {
			case err := <-done:
				if err == nil || errors.Is(err, io.EOF) {
					t.Fatalf("after the %s's abort the peer read %v, want an error", who, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("the peer did not notice the %s's abort", who)
			}
		})
	}
}

// TestH2_ResetReturnsConnectionWindow: stalled streams exhaust the connection window, so a new
// stream cannot deliver; resetting them on the gateway returns their unread bytes, and new streams
// and the control stream flow again.
func TestH2_ResetReturnsConnectionWindow(t *testing.T) {
	// Four streams of 900 KiB each, never read by the gateway, exceed its 3 MiB connection window.
	w := tunnel.H2Windows{Stream: 1 << 20, Conn: 3 << 20}
	gw, con, gc, cc := h2Session(t, w)
	var stalled []tunnel.Stream
	for range 4 {
		g, c := h2Open(t, gw, con)
		stalled = append(stalled, g)
		go func() { _, _ = c.Write(make([]byte, 900<<10)) }()
	}
	time.Sleep(300 * time.Millisecond)
	g, c := h2Open(t, gw, con)
	wrote := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 256<<10)); wrote <- err }()
	select {
	case <-wrote:
		t.Fatal("a new stream delivered with the connection window exhausted; the test proves nothing")
	case <-time.After(300 * time.Millisecond):
	}
	for _, s := range stalled {
		s.Abort()
	}
	got := make(chan error, 1)
	go func() { _, err := io.ReadFull(g, make([]byte, 256<<10)); got <- err }()
	for name, ch := range map[string]chan error{"write": wrote, "read": got} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("%s on a new stream after the resets: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the window did not come back (%s)", name)
		}
	}
	// The control stream flows too.
	if _, err := cc.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(gc, make([]byte, 4)); err != nil {
		t.Fatalf("control stream after the resets: %v", err)
	}
}

// TestH2_IdleStreamMemoryBounded: with 16 KiB frames, open idle streams use less than 100 KiB each,
// both ends together; 10 000 streams with the control stream, the connector's limit (1 000 under
// the race detector).
func TestH2_IdleStreamMemoryBounded(t *testing.T) {
	n := 10000 - 1
	if raceEnabled || testing.Short() {
		n = 1000
	}
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	before := heap()
	var streams []tunnel.Stream
	for range n {
		g, c := h2Open(t, gw, con)
		if _, err := g.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte{2}); err != nil {
			t.Fatal(err)
		}
		streams = append(streams, g, c)
	}
	time.Sleep(200 * time.Millisecond)
	per := (heap() - before) / uint64(n)
	t.Logf("%d idle streams: %d KiB per stream, both ends", n, per>>10)
	if per >= 100<<10 {
		t.Fatalf("%d KiB per idle stream, want less than 100 KiB", per>>10)
	}
	runtime.KeepAlive(streams)
}

func heap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse + m.StackInuse
}

// TestH2_StreamBeforeControlRefused: the connector refuses a stream that comes before the session
// control stream, and a second control stream; the gateway's own API refuses the same.
func TestH2_StreamBeforeControlRefused(t *testing.T) {
	gw, _ := h2Pair(t, tunnel.DefaultH2Windows())
	if _, err := gw.OpenStream(context.Background()); !errors.Is(err, tunnel.ErrControlFirst) {
		t.Fatalf("OpenStream before Control: %v", err)
	}

	// A raw HTTP/2 client that skips the control stream.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, err := ln.Accept(); err == nil {
			con := tunnel.ServeH2Connector(c, tunnel.DefaultH2Windows())
			t.Cleanup(func() { _ = con.Close() })
		}
	}()
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	client := &http.Client{Transport: &http.Transport{Protocols: &p}}
	status := func(path string) int {
		t.Helper()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+ln.Addr().String()+path, bytes.NewReader(nil))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := status("/stream"); code != http.StatusMisdirectedRequest {
		t.Fatalf("a stream before the control stream: %d", code)
	}
	if code := status("/stream"); code != http.StatusMisdirectedRequest {
		t.Fatalf("a stream after a refused first stream: %d", code)
	}
}

// TestH2_StreamLimitNeverBlocks: at the connector's stream limit OpenStream fails at once.
func TestH2_StreamLimitNeverBlocks(t *testing.T) {
	gw, con, _, _ := h2Session(t, tunnel.WithMaxStreams(tunnel.DefaultH2Windows(), 5))
	for range 4 { // the control stream is the fifth
		h2Open(t, gw, con)
	}
	start := time.Now()
	if _, err := gw.OpenStream(context.Background()); !errors.Is(err, tunnel.ErrStreamLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("OpenStream took %v at the limit", d)
	}
	if _, err := con.OpenStream(context.Background()); !errors.Is(err, tunnel.ErrNotSupported) {
		t.Fatalf("the connector opened a stream: %v", err)
	}
	if _, err := gw.AcceptStream(context.Background()); !errors.Is(err, tunnel.ErrNotSupported) {
		t.Fatalf("the gateway accepted a stream: %v", err)
	}
}

// TestH2_SessionEnd: closing either side ends the session on both.
func TestH2_SessionEnd(t *testing.T) {
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	_ = con.Close()
	for name, done := range map[string]<-chan struct{}{"connector": con.Done(), "gateway": gw.Done()} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("the %s did not see the session end", name)
		}
	}
	if gw.Transport() != "h2" || con.Transport() != "h2" {
		t.Fatal("transport name")
	}
}
