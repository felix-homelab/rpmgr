// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A client that stops reading entirely blocks the handler's write in the kernel; the write deadline
// ends it with an error at the deadline, and not when the connection's own timeout does.
func TestSetWriteDeadline_CutsAStalledReader(t *testing.T) {
	const deadline = 300 * time.Millisecond
	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	srv := httptest.NewServer(keepResponseWriter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rc := http.NewResponseController(w)
		chunk := make([]byte, 1<<20)
		var err error
		for range 512 { // far more than the socket buffers hold
			if err = SetWriteDeadline(r.Context(), start.Add(deadline)); err != nil {
				break
			}
			if _, err = w.Write(chunk); err == nil {
				err = rc.Flush()
			}
			if err != nil {
				break
			}
		}
		done <- result{err, time.Since(start)}
	})))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil { // and never reads
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if !isTimeout(r.err) {
			t.Fatalf("the write failed with %v, want a timeout", r.err)
		}
		if r.elapsed < deadline || r.elapsed > 10*time.Second {
			t.Fatalf("the stalled reader was cut after %v, want about %v", r.elapsed, deadline)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a reader that stopped reading held the handler past the deadline")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Outside a request served through Mount there is no writer to set a deadline on.
func TestSetWriteDeadline_NoWriter(t *testing.T) {
	if err := SetWriteDeadline(context.Background(), time.Now()); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("no writer: %v", err)
	}
}
