// SPDX-License-Identifier: Apache-2.0

package load

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UDPResult is the outcome of a UDP run.
type UDPResult struct {
	Sent, Received int
	Elapsed        time.Duration
}

// Loss returns the share of datagrams that did not come back, in %.
func (r UDPResult) Loss() float64 {
	if r.Sent == 0 {
		return 0
	}
	return float64(r.Sent-r.Received) * 100 / float64(r.Sent)
}

// PPS returns the datagrams per second that came back.
func (r UDPResult) PPS() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Received) / r.Elapsed.Seconds()
}

// UDP sends datagrams of size bytes to an echo at rate per second for dur and counts the echoes
// that arrive until a second after the last one was sent. Each carries its sequence number, so a
// datagram counts once however often it arrives.
func UDP(ctx context.Context, target string, size, rate int, dur time.Duration) (UDPResult, error) {
	if size < 8 || size > 65000 || rate < 1 {
		return UDPResult{}, fmt.Errorf("load: UDP needs a size of 8 to 65000 bytes and a rate ≥ 1, got %d and %d", size, rate)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", target)
	if err != nil {
		return UDPResult{}, err
	}
	defer func() { _ = c.Close() }()
	n := int(dur.Seconds() * float64(rate))
	seen := make([]atomic.Bool, n)
	var received atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			k, err := c.Read(buf)
			if err != nil {
				return
			}
			if k == size {
				if i := binary.BigEndian.Uint64(buf); i < uint64(len(seen)) && !seen[i].Swap(true) {
					received.Add(1)
				}
			}
		}
	}()
	msg := slices.Clone(block[:min(size, len(block))])
	msg = append(msg, make([]byte, size-len(msg))...)
	interval := time.Second / time.Duration(rate)
	start := time.Now()
	for i := range n {
		if wait := time.Until(start.Add(time.Duration(i) * interval)); wait > 0 {
			time.Sleep(wait)
		}
		binary.BigEndian.PutUint64(msg, uint64(i))
		_, _ = c.Write(msg)
	}
	elapsed := time.Since(start)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	<-done
	return UDPResult{Sent: n, Received: int(received.Load()), Elapsed: elapsed}, nil
}

// HTTPResult is the outcome of an HTTP run.
type HTTPResult struct {
	SetupResult // request latencies
	Elapsed     time.Duration
}

// RPS returns the requests per second that succeeded.
func (r HTTPResult) RPS() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(len(r.Latencies)) / r.Elapsed.Seconds()
}

// HTTP sends GET requests for url over HTTP/2 with TLS 1.3 from workers concurrent loops for dur,
// to the gateway at addr whatever the URL's host resolves to, trusting the certificates in caPEM.
func HTTP(ctx context.Context, addr, url string, caPEM []byte, workers int, dur time.Duration) (HTTPResult, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return HTTPResult{}, errors.New("load: no CA certificate")
	}
	if workers < 1 {
		return HTTPResult{}, fmt.Errorf("load: workers must be ≥ 1, got %d", workers)
	}
	var d net.Dialer
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	var mu sync.Mutex
	var res HTTPResult
	end := time.Now().Add(dur)
	start := time.Now()
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for time.Now().Before(end) && ctx.Err() == nil {
				t0 := time.Now()
				err := get(ctx, client, url)
				mu.Lock()
				if err != nil {
					res.Failures++
				} else {
					res.Latencies = append(res.Latencies, time.Since(t0))
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	res.Elapsed = time.Since(start)
	slices.Sort(res.Latencies)
	return res, nil
}

func get(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		return fmt.Errorf("load: %s over %s", resp.Status, resp.Proto)
	}
	return nil
}

// HoldResult is the outcome of held connections.
type HoldResult struct {
	Conns, Lost int // connections held, and those that failed before the end
	Pings       int64
}

// Hold keeps conns connections to an echo open for dur, each sending an 8-byte ping every 200 ms
// and expecting it back. A connection that fails is lost and not opened again: during
// configuration changes no connection may be lost (docs/03-connections.md, "Targets [T]").
func Hold(ctx context.Context, target string, conns int, dur time.Duration) (HoldResult, error) {
	if conns < 1 {
		return HoldResult{}, fmt.Errorf("load: conns must be ≥ 1, got %d", conns)
	}
	var lost atomic.Int64
	var pings atomic.Int64
	var wg sync.WaitGroup
	end := time.Now().Add(dur)
	for range conns {
		wg.Go(func() {
			c, err := dial(ctx, target)
			if err != nil {
				lost.Add(1)
				return
			}
			defer func() { _ = c.Close() }()
			buf := make([]byte, 8)
			for i := uint64(0); time.Now().Before(end) && ctx.Err() == nil; i++ {
				msg := binary.BigEndian.AppendUint64(nil, i)
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(msg); err != nil {
					lost.Add(1)
					return
				}
				if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, msg) {
					lost.Add(1)
					return
				}
				pings.Add(1)
				time.Sleep(200 * time.Millisecond)
			}
		})
	}
	wg.Wait()
	return HoldResult{Conns: conns, Lost: int(lost.Load()), Pings: pings.Load()}, nil
}

// WhoResult counts which connector served new connections.
type WhoResult struct {
	By       map[string]int
	Failures int
}

// Who opens connections to a "who" route at rate per second for dur and counts the connectors
// that answer (VB-18: a connector whose session is blocked gets fewer new streams).
func Who(ctx context.Context, target string, rate int, dur time.Duration) (WhoResult, error) {
	if rate < 1 {
		return WhoResult{}, fmt.Errorf("load: rate must be ≥ 1, got %d", rate)
	}
	res := WhoResult{By: map[string]int{}}
	var mu sync.Mutex
	interval := time.Second / time.Duration(rate)
	n := int(dur / interval)
	start := time.Now()
	var wg sync.WaitGroup
	for i := range n {
		if wait := time.Until(start.Add(time.Duration(i) * interval)); wait > 0 {
			time.Sleep(wait)
		}
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			name, err := who(cctx, target)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failures++
				return
			}
			res.By[name]++
		})
	}
	wg.Wait()
	return res, nil
}

func who(ctx context.Context, target string) (string, error) {
	c, err := dial(ctx, target)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
