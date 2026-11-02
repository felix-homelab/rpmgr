// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// syncBuffer is a log destination that tests read while the gateway writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// count returns how many log lines contain every one of parts.
func (s *syncBuffer) count(parts ...string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for line := range strings.SplitSeq(s.b.String(), "\n") {
		ok := line != ""
		for _, p := range parts {
			ok = ok && strings.Contains(line, p)
		}
		if ok {
			n++
		}
	}
	return n
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// stallPlane is a plane to a target that serves, with the metrics of its gateway and the log of its
// tcp routes at level; port is the route rt_1's public port.
func stallPlane(t *testing.T, level slog.Level, serve func(net.Conn, *bufio.Reader, string)) (reg *prometheus.Registry, log *syncBuffer, port uint16) {
	t.Helper()
	reg = prometheus.NewRegistry()
	metrics, err := gateway.NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	p := planeWith(t, service(t, serve), "v1", metrics, "rt_1")
	log = &syncBuffer{}
	routes := gateway.NewTCPRoutes(gateway.TCPOptions{Host: "127.0.0.1", Sessions: p.sessions,
		Logger: slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: level}))})
	t.Cleanup(routes.Close)
	port = freePort(t)
	if st := routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}}); len(st) != 0 {
		t.Fatal(st)
	}
	return reg, log, port
}

// sink reads and never answers, as a target that hangs does.
func sink(c net.Conn, br *bufio.Reader, _ string) {
	_, _ = io.Copy(io.Discard, br)
	_ = c.Close()
}

// metricsOf returns the open streams of rt_1 and its bytes each way.
func metricsOf(t *testing.T, reg *prometheus.Registry) (open, in, out float64) {
	t.Helper()
	open, _ = sample(t, reg, "rpmgr_gateway_streams_open", map[string]string{"route": "rt_1"})
	in, _ = sample(t, reg, "rpmgr_route_bytes_total", map[string]string{"route": "rt_1", "direction": "in"})
	out, _ = sample(t, reg, "rpmgr_route_bytes_total", map[string]string{"route": "rt_1", "direction": "out"})
	return open, in, out
}

const stallAfterTest = 300 * time.Millisecond

// TestStall_Logged: a stream that carried 19 bytes and then nothing gets one debug line with its
// route, target, connector and byte counts, and no second one however long it stays; the counters
// show the stream open with the 19 bytes in and none out.
func TestStall_Logged(t *testing.T) {
	gateway.SetStallAfter(t, stallAfterTest)
	reg, log, port := stallPlane(t, slog.LevelDebug, sink)
	c := dialPort(t, port)
	if _, err := c.Write(make([]byte, 19)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "no stall line", func() bool {
		return log.count("stream stalled", "route=rt_1", "target=tg_rt_1", "bytes_from_client=19", "bytes_to_client=0") == 1
	})
	time.Sleep(3 * stallAfterTest)
	if n := log.count("stream stalled"); n != 1 {
		t.Fatalf("%d stall lines for one stream:\n%s", n, log)
	}
	if open, in, out := metricsOf(t, reg); open != 1 || in != 19 || out != 0 {
		t.Fatalf("open %v, in %v, out %v; want 1, 19, 0", open, in, out)
	}
}

// TestStall_NothingMoved: a connection that sends nothing at all is a stream with both counters at
// zero, present in a scrape, and is logged as stalled with zero bytes.
func TestStall_NothingMoved(t *testing.T) {
	gateway.SetStallAfter(t, stallAfterTest)
	reg, log, port := stallPlane(t, slog.LevelDebug, sink)
	c := dialPort(t, port)
	eventually(t, "no stall line", func() bool {
		return log.count("stream stalled", "bytes_from_client=0", "bytes_to_client=0") == 1
	})
	if open, in, out := metricsOf(t, reg); open != 1 || in != 0 || out != 0 {
		t.Fatalf("open %v, in %v, out %v; want 1, 0, 0", open, in, out)
	}
	if _, ok := sample(t, reg, "rpmgr_route_bytes_total", map[string]string{"route": "rt_1", "direction": "in"}); !ok {
		t.Fatal("no bytes series for a route that moved nothing")
	}
	_ = c.Close()
	eventually(t, "the stream stayed open", func() bool { open, _, _ := metricsOf(t, reg); return open == 0 })
}

// TestStall_ActiveStream: a stream that keeps moving bytes, even a few, is never logged as stalled,
// and a stream that ends before the time is not either.
func TestStall_ActiveStream(t *testing.T) {
	gateway.SetStallAfter(t, stallAfterTest)
	_, log, port := stallPlane(t, slog.LevelDebug, echoService)
	c := dialPort(t, port)
	for range 12 { // 1.2 s, four times the stall time, one echoed byte each 100 ms
		if err := ping(c, "x"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(stallAfterTest / 3)
	}
	_ = c.Close()
	short := dialPort(t, port)
	if err := ping(short, "y"); err != nil {
		t.Fatal(err)
	}
	_ = short.Close()
	time.Sleep(2 * stallAfterTest)
	if n := log.count("stream stalled"); n != 0 {
		t.Fatalf("%d stall lines for streams that moved bytes:\n%s", n, log)
	}
}

// TestStall_HalfClose: a visitor that half-closes after its request still receives the answer; the
// counters show both directions, and no stall is logged for a stream that ends.
func TestStall_HalfClose(t *testing.T) {
	gateway.SetStallAfter(t, stallAfterTest)
	reg, log, port := stallPlane(t, slog.LevelDebug, echoService)
	c := dialPort(t, port)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(c); err != nil || string(got) != "hello" {
		t.Fatalf("answer after the half-close: %q, %v", got, err)
	}
	eventually(t, "the counters", func() bool {
		open, in, out := metricsOf(t, reg)
		return open == 0 && in == 5 && out == 5
	})
	time.Sleep(2 * stallAfterTest)
	if n := log.count("stream stalled"); n != 0 {
		t.Fatalf("a stall line for a stream that ended:\n%s", log)
	}
}

// TestStall_NotAtInfo: without debug logging a stalled stream logs nothing, as the watch is not
// armed; the counters still show it.
func TestStall_NotAtInfo(t *testing.T) {
	gateway.SetStallAfter(t, stallAfterTest)
	reg, log, port := stallPlane(t, slog.LevelInfo, sink)
	c := dialPort(t, port)
	if _, err := c.Write(make([]byte, 19)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the counters", func() bool { open, in, _ := metricsOf(t, reg); return open == 1 && in == 19 })
	time.Sleep(2 * stallAfterTest)
	if log.String() != "" {
		t.Fatalf("log lines at info level:\n%s", log)
	}
}
