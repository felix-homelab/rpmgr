// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// TestConn_QUIC: a QUIC stream as a net.Conn carries both directions and half-closes; its
// deadlines are the stream's own, so a passed read deadline is a timeout the conn survives.
func TestConn_QUIC(t *testing.T) {
	gw, con, _ := connect(t)
	st, err := con.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := tunnel.Conn(st, tunnel.StreamAddr("connector"), tunnel.StreamAddr("gateway"))
	if _, err := c.Write([]byte("hi")); err != nil { // QUIC announces a stream with its first bytes
		t.Fatal(err)
	}
	peer := accept(t, gw)
	if c.LocalAddr().String() != "connector" || c.RemoteAddr().String() != "gateway" || c.RemoteAddr().Network() != "rpmgr-stream" {
		t.Fatalf("addresses %v %v", c.LocalAddr(), c.RemoteAddr())
	}
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var ne net.Error
	if _, err := c.Read(make([]byte, 1)); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("a passed read deadline: %v, want a timeout", err)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("back")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "back" {
		t.Fatalf("after the timeout: %q %v", b, err)
	}
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "hi" {
		t.Fatalf("the peer read %q %v, want hi and EOF", got, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestConn_H2: an HTTP/2 stream has no deadlines of its own, so a deadline that passes resets
// it; a cleared deadline never fires.
func TestConn_H2(t *testing.T) {
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	g, s := h2Open(t, gw, con)
	c := tunnel.Conn(s, tunnel.StreamAddr("connector"), tunnel.StreamAddr("gateway"))
	if err := c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := c.Write([]byte("ok")); err != nil {
		t.Fatalf("after a cleared deadline: %v", err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(g, b); err != nil || string(b) != "ok" {
		t.Fatalf("%q %v", b, err)
	}
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("a passed deadline on HTTP/2: %v, want the stream reset", err)
	}
	_ = c.Close()
}
