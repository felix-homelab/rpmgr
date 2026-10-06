// SPDX-License-Identifier: Apache-2.0

// Package load is the S1 benchmark's service and load generator. The service has three
// endpoints: a sink that counts what it receives, a source that sends for a requested time, and
// an echo. The generator measures goodput (bytes delivered and acknowledged end to end) for 1 and
// N parallel streams in either direction, and connection-setup latency (connect, send, receive
// the echo) at a fixed rate (docs/12-testing-and-quality.md#benchmarks).
package load

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var block = func() []byte {
	b := make([]byte, 32<<10)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}()

// ServeSink reads each connection to EOF, then replies with the byte count (8 bytes, big endian)
// and closes. The count is the acknowledgement the generator measures goodput with.
func ServeSink(ln net.Listener) error {
	return serve(ln, func(c *net.TCPConn) {
		buf := make([]byte, 64<<10)
		var n int64
		for {
			k, err := c.Read(buf)
			n += int64(k)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					return
				}
				break
			}
		}
		_ = binary.Write(c, binary.BigEndian, uint64(n))
		_ = c.CloseWrite()
	})
}

// ServeSource reads a duration in milliseconds (8 bytes) and sends data for that long, then
// closes its sending direction.
func ServeSource(ln net.Listener) error {
	return serve(ln, func(c *net.TCPConn) {
		var ms uint64
		if err := binary.Read(c, binary.BigEndian, &ms); err != nil || ms > 600_000 {
			return
		}
		deadline := time.Now().Add(time.Duration(ms) * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := c.Write(block); err != nil {
				return
			}
		}
		_ = c.CloseWrite()
		_, _ = io.Copy(io.Discard, c)
	})
}

// ServeEcho echoes until EOF, then half-closes.
func ServeEcho(ln net.Listener) error {
	return serve(ln, func(c *net.TCPConn) {
		_, _ = io.Copy(c, c)
		_ = c.CloseWrite()
	})
}

func serve(ln net.Listener, h func(*net.TCPConn)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			h(c.(*net.TCPConn))
		}()
	}
}

// ThroughputResult is the outcome of one goodput run.
type ThroughputResult struct {
	Bytes    int64
	Elapsed  time.Duration
	Failures int
}

// Mbps returns the aggregate goodput in Mbit/s.
func (r ThroughputResult) Mbps() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Bytes) * 8 / r.Elapsed.Seconds() / 1e6
}

// Throughput opens streams parallel connections to target. Direction "up" sends for dur and
// counts the bytes the sink acknowledges; "down" asks the source to send for dur and counts what
// arrives. Elapsed runs from the first dial to the last acknowledgement or EOF, so data still in
// flight when the timer ends is included in the time.
func Throughput(ctx context.Context, target, direction string, streams int, dur time.Duration) (ThroughputResult, error) {
	if streams < 1 {
		return ThroughputResult{}, fmt.Errorf("load: streams must be ≥ 1, got %d", streams)
	}
	if direction != "up" && direction != "down" {
		return ThroughputResult{}, fmt.Errorf("load: direction must be up or down, got %q", direction)
	}
	var total atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var n int64
			var err error
			if direction == "up" {
				n, err = upload(ctx, target, dur)
			} else {
				n, err = download(ctx, target, dur)
			}
			if err != nil {
				failures.Add(1)
				return
			}
			total.Add(n)
		}()
	}
	wg.Wait()
	return ThroughputResult{Bytes: total.Load(), Elapsed: time.Since(start), Failures: int(failures.Load())}, nil
}

func dial(ctx context.Context, target string) (*net.TCPConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func upload(ctx context.Context, target string, dur time.Duration) (int64, error) {
	c, err := dial(ctx, target)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		if _, err := c.Write(block); err != nil {
			return 0, err
		}
	}
	if err := c.CloseWrite(); err != nil {
		return 0, err
	}
	var acked uint64
	if err := binary.Read(c, binary.BigEndian, &acked); err != nil {
		return 0, fmt.Errorf("load: no acknowledgement: %w", err)
	}
	return int64(acked), nil
}

func download(ctx context.Context, target string, dur time.Duration) (int64, error) {
	c, err := dial(ctx, target)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if err := binary.Write(c, binary.BigEndian, uint64(dur.Milliseconds())); err != nil {
		return 0, err
	}
	// Half-close at once: the request is complete, and the service→client direction ends first
	// only in the service's own time.
	if err := c.CloseWrite(); err != nil {
		return 0, err
	}
	return io.Copy(io.Discard, c)
}

// SetupResult is the outcome of a connection-setup run.
type SetupResult struct {
	Latencies []time.Duration // sorted
	Failures  int
}

// Percentile returns the p-th percentile (0–100) in milliseconds.
func (r SetupResult) Percentile(p float64) float64 {
	if len(r.Latencies) == 0 {
		return 0
	}
	i := int(float64(len(r.Latencies)-1) * p / 100)
	return float64(r.Latencies[i].Microseconds()) / 1000
}

// Setup opens connections at a fixed rate for dur (open loop, so a slow tunnel cannot slow the
// arrival rate down). Each connection sends 32 bytes and waits for the echo; the latency runs from
// the start of the dial to the last echoed byte.
func Setup(ctx context.Context, target string, rate int, dur time.Duration) (SetupResult, error) {
	if rate < 1 {
		return SetupResult{}, fmt.Errorf("load: rate must be ≥ 1, got %d", rate)
	}
	interval := time.Second / time.Duration(rate)
	n := int(dur / interval)
	lat := make([]time.Duration, n)
	ok := make([]bool, n)
	var wg sync.WaitGroup
	start := time.Now()
	for i := range n {
		if wait := time.Until(start.Add(time.Duration(i) * interval)); wait > 0 {
			time.Sleep(wait)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			t0 := time.Now()
			c, err := dial(cctx, target)
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			msg := block[:32]
			if _, err := c.Write(msg); err != nil {
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil {
				return
			}
			lat[i], ok[i] = time.Since(t0), true
		}()
	}
	wg.Wait()
	var res SetupResult
	for i := range n {
		if ok[i] {
			res.Latencies = append(res.Latencies, lat[i])
		} else {
			res.Failures++
		}
	}
	sort.Slice(res.Latencies, func(a, b int) bool { return res.Latencies[a] < res.Latencies[b] })
	return res, nil
}
