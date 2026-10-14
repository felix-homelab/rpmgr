// SPDX-License-Identifier: Apache-2.0

package memnet_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/memnet"
)

// TestListener_DialAndDeliver: a dialled pipe and a delivered connection both reach Accept, and
// bytes flow both ways.
func TestListener_DialAndDeliver(t *testing.T) {
	l := memnet.NewListener()
	defer func() { _ = l.Close() }()
	if l.Addr().Network() != "memory" || l.Addr().String() != "in-process" {
		t.Fatalf("Addr %s/%s", l.Addr().Network(), l.Addr().String())
	}
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	client, err := l.Dial(context.Background(), "ignored:1")
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	go func() { _, _ = server.Write([]byte("hello")) }()
	b := make([]byte, 5)
	if _, err := io.ReadFull(client, b); err != nil || string(b) != "hello" {
		t.Fatalf("read %q, %v", b, err)
	}
	a, b2 := net.Pipe()
	defer func() { _, _ = a.Close(), b2.Close() }()
	l.Deliver(a)
	if got := <-accepted; got != a {
		t.Fatal("Deliver did not hand over the connection")
	}
}

// TestListener_Closed: after Close, Accept and Dial fail with net.ErrClosed and Deliver closes the
// connection it gets.
func TestListener_Closed(t *testing.T) {
	l := memnet.NewListener()
	_ = l.Close()
	_ = l.Close() // twice is fine
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept: %v", err)
	}
	if _, err := l.Dial(context.Background(), ""); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Dial: %v", err)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	l.Deliver(a)
	if _, err := a.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("the delivered connection is open: %v", err)
	}
}

// TestListener_DialWaitsForAccept: Dial waits until a connection is accepted and gives up when
// its context ends.
func TestListener_DialWaitsForAccept(t *testing.T) {
	l := memnet.NewListener()
	defer func() { _ = l.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Dial(ctx, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial without Accept: %v", err)
	}
}
