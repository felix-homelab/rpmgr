// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// relayed returns the gateway's end of a QUIC stream whose connector end Relay connects to a
// TCP connection that serve handles; done closes when Relay returns.
func relayed(t *testing.T, serve func(*net.TCPConn)) (st tunnel.Stream, done chan [2]int64) {
	t.Helper()
	gw, con, _ := connect(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			serve(c.(*net.TCPConn))
		}
	}()
	st, err = gw.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte{0}); err != nil { // QUIC announces a stream with its first byte
		t.Fatal(err)
	}
	in := accept(t, con)
	if _, err := io.ReadFull(in, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	done = make(chan [2]int64, 1)
	go func() {
		a, b := tunnel.Relay(in, c)
		done <- [2]int64{a, b}
	}()
	return st, done
}

func wait(t *testing.T, done chan [2]int64) [2]int64 {
	t.Helper()
	select {
	case n := <-done:
		return n
	case <-time.After(10 * time.Second):
		t.Fatal("Relay did not return")
		return [2]int64{}
	}
}

// TestRelay_HalfClose: the client's FIN reaches the service as a FIN, and the service's answer,
// written after it, still reaches the client.
func TestRelay_HalfClose(t *testing.T) {
	st, done := relayed(t, func(c *net.TCPConn) {
		req, _ := io.ReadAll(c) // up to the FIN
		_, _ = c.Write(append([]byte("answer to "), req...))
		_ = c.Close()
	})
	if _, err := st.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "answer to request" {
		t.Fatalf("%q %v", got, err)
	}
	if n := wait(t, done); n != [2]int64{7, 17} {
		t.Fatalf("relayed %v bytes, want 7 and 17", n)
	}
}

// TestRelay_Bulk: 4 MiB each way at the same time arrive intact.
func TestRelay_Bulk(t *testing.T) {
	const size = 4 << 20
	up, down := make([]byte, size), make([]byte, size)
	_, _ = rand.Read(up)
	_, _ = rand.Read(down)
	got := make(chan [32]byte, 1)
	st, done := relayed(t, func(c *net.TCPConn) {
		go func() {
			_, _ = c.Write(down)
			_ = c.CloseWrite()
		}()
		b, _ := io.ReadAll(c)
		got <- sha256.Sum256(b)
	})
	go func() {
		_, _ = st.Write(up)
		_ = st.CloseWrite()
	}()
	b, err := io.ReadAll(st)
	if err != nil || !bytes.Equal(b, down) {
		t.Fatalf("download: %d bytes, %v", len(b), err)
	}
	if <-got != sha256.Sum256(up) {
		t.Fatal("upload corrupted")
	}
	wait(t, done)
}

// TestRelay_ServiceReset: a reset from the service resets the client's stream; it is an error,
// not an end of data.
func TestRelay_ServiceReset(t *testing.T) {
	st, done := relayed(t, func(c *net.TCPConn) {
		_, _ = c.Read(make([]byte, 16))
		_ = c.SetLinger(0)
		_ = c.Close()
	})
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(st); err == nil {
		t.Fatal("the client saw a clean end after the service's reset")
	}
	wait(t, done)
}

// TestRelay_ClientReset: a reset stream closes the service's connection with SO_LINGER=0, so the
// service sees a reset.
func TestRelay_ClientReset(t *testing.T) {
	seen := make(chan error, 1)
	st, done := relayed(t, func(c *net.TCPConn) {
		_, _ = c.Read(make([]byte, 5))
		_, err := io.ReadAll(c)
		seen <- err
	})
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	st.Abort()
	select {
	case err := <-seen:
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("the service saw %v, want a reset", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the service's connection stayed open")
	}
	wait(t, done)
}
