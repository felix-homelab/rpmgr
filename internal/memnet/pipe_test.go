// SPDX-License-Identifier: Apache-2.0

package memnet_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/nettest"

	"github.com/felix-homelab/rpmgr/internal/memnet"
)

// TestPipe_Conformance: a Pipe end behaves as a net.Conn should, deadlines and concurrent use
// included.
func TestPipe_Conformance(t *testing.T) {
	nettest.TestConn(t, func() (net.Conn, net.Conn, func(), error) {
		a, b := memnet.Pipe()
		return a, b, func() { _, _ = a.Close(), b.Close() }, nil
	})
}

// TestPipe_WritesDoNotWaitForTheReader: both ends write and close while neither reads, as both
// ends of a TLS connection send close_notify at once; afterwards each reads what the other wrote,
// then io.EOF.
func TestPipe_WritesDoNotWaitForTheReader(t *testing.T) {
	a, b := memnet.Pipe()
	done := make(chan error, 2)
	for _, c := range []net.Conn{a, b} {
		go func() {
			_, err := c.Write(bytes.Repeat([]byte("x"), 4096))
			done <- err
		}()
	}
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a write waited for the reader")
		}
	}
	_ = a.Close()
	got, err := io.ReadAll(b)
	if err != nil || len(got) != 4096 {
		t.Fatalf("read %d bytes, %v; want 4096 and io.EOF", len(got), err)
	}
	if _, err := b.Write([]byte("y")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("a write to a closed peer: %v", err)
	}
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("a read after Close: %v", err)
	}
}

// TestPipe_FullBufferWaits: a write beyond the buffer waits for the reader, and its deadline ends
// the wait with the part that fitted written.
func TestPipe_FullBufferWaits(t *testing.T) {
	a, b := memnet.Pipe()
	defer func() { _, _ = a.Close(), b.Close() }()
	_ = a.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := a.Write(make([]byte, 3<<20))
	if !errors.Is(err, os.ErrDeadlineExceeded) || n != 1<<20 {
		t.Fatalf("wrote %d, %v; want 1 MiB and a timeout", n, err)
	}
	_ = a.SetWriteDeadline(time.Time{})
	go func() { _, _ = io.Copy(io.Discard, b) }()
	if n, err := a.Write(make([]byte, 3<<20)); err != nil || n != 3<<20 {
		t.Fatalf("with a reader: %d, %v", n, err)
	}
}

// TestPipe_WritesAreAtomic: writes larger than the buffer from two goroutines arrive one after
// the other, never interleaved.
func TestPipe_WritesAreAtomic(t *testing.T) {
	a, b := memnet.Pipe()
	defer func() { _, _ = a.Close(), b.Close() }()
	const size = 3 << 20
	errs := make(chan error, 2)
	for _, c := range []byte{'a', 'b'} {
		go func() {
			_, err := a.Write(bytes.Repeat([]byte{c}, size))
			errs <- err
		}()
	}
	// Both writers wait for room once the buffer is full; small reads then wake them many times.
	time.Sleep(100 * time.Millisecond)
	got := make([]byte, 0, 2*size)
	chunk := make([]byte, 16<<10)
	for len(got) < 2*size {
		n, err := b.Read(chunk)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, chunk[:n]...)
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	first, second := got[:size], got[size:]
	if bytes.Count(first, first[:1]) != size || bytes.Count(second, second[:1]) != size || first[0] == second[0] {
		t.Fatalf("the writes interleaved: %d of %q first, %d of %q second", bytes.Count(first, first[:1]), first[0],
			bytes.Count(second, second[:1]), second[0])
	}
}
