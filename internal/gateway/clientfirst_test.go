// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	conn "github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// clientFirstTarget is a target that speaks second, as every TLS, database and mail server does: it
// reads 19 bytes and answers them, reads second bytes and answers them as well, then reads to the
// end. The answers are the bytes it read, so the visitor can check them. done gets nil once the
// visitor's half-close has reached it with nothing more written, else the error that ended it.
func clientFirstTarget(t *testing.T, second int, done chan<- error) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		for _, n := range []int{19, second} {
			b := make([]byte, n)
			if _, err := io.ReadFull(c, b); err != nil {
				done <- err
				return
			}
			if _, err := c.Write(b); err != nil {
				done <- err
				return
			}
		}
		// The visitor's half-close arrives as EOF, after which the target's answers are complete.
		rest, err := io.ReadAll(c)
		if err == nil && len(rest) != 0 {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	return ln.Addr().String()
}

// TestClientFirstDuplex: a client that speaks first keeps working after the target's first answer,
// on every transport the in-process plane serves: it writes 19 bytes, reads the 19 back, writes a
// second chunk (7 KiB, or one byte) and reads that back. With half_close the visitor closes its
// write side after the second chunk and still receives the target's whole answer, which the
// gateway's FIN must not cut off.
func TestClientFirstDuplex(t *testing.T) {
	cases := []struct {
		name      string
		second    int
		halfClose bool
	}{
		{"7KiB", 7 << 10, false},
		{"one byte", 1, false},
		{"half-close after 7KiB", 7 << 10, true},
		{"half-close after one byte", 1, true},
	}
	for _, transport := range []string{conn.TransportH2, conn.TransportWSS, conn.TransportQUIC} {
		for _, tc := range cases {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				done := make(chan error, 1)
				p := planeOn(t, transport, clientFirstTarget(t, tc.second, done), "none", nil, "rt_1")
				port := freePort(t)
				if st := p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}}); len(st) != 0 {
					t.Fatal(st)
				}
				c := dialPort(t, port)

				first := make([]byte, 19)
				_, _ = rand.Read(first)
				if err := echoed(c, first); err != nil {
					t.Fatalf("the 19-byte request: %v", err)
				}
				second := make([]byte, tc.second)
				_, _ = rand.Read(second)
				if tc.halfClose {
					// The answer is read after the FIN: write, half-close, then read.
					if _, err := c.Write(second); err != nil {
						t.Fatal(err)
					}
					if err := c.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
					got := make([]byte, len(second))
					if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, second) {
						t.Fatalf("the answer after the visitor's half-close: %v", err)
					}
				} else if err := echoed(c, second); err != nil {
					t.Fatalf("the %d-byte second chunk: %v", tc.second, err)
				}
				if !tc.halfClose {
					return
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("the target did not see the visitor's half-close: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the visitor's half-close never reached the target")
				}
			})
		}
	}
}

// echoed writes msg to c and reads the same number of bytes back, which must equal it.
func echoed(c *net.TCPConn, msg []byte) error {
	if _, err := c.Write(msg); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
