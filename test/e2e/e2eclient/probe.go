// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// gap is a time with no UDP answer.
type gap struct {
	AtMS  int64 `json:"at_ms"`
	GapMS int64 `json:"gap_ms"`
}

// probeResult is what `e2eclient probe` prints: per protocol the answered and the failed
// attempts, the first errors, and for UDP every silence over udpGap.
type probeResult struct {
	TCPOK, TCPFail   int
	HTTPOK, HTTPFail int
	UDPOK            int
	UDPGaps          []gap
	FailAtMS         []int64  // when each failed TCP or HTTP attempt started
	Errors           []string // the first few, with the protocol
}

const udpGap = 700 * time.Millisecond

// probe sends for d through the routes it is given: every `every` a new TCP connection that
// echoes 16 bytes, a new HTTP/1.1 connection that gets url, and on one UDP flow a datagram.
// A refused, reset or silent connection counts as a failure; nothing here retries.
func probe(tcpAddr, udpAddr, httpAddr, url string, d, every time.Duration) probeResult {
	var (
		mu    sync.Mutex
		res   probeResult
		wg    sync.WaitGroup
		start = time.Now()
	)
	fail := func(what string, err error, at time.Time) {
		res.FailAtMS = append(res.FailAtMS, at.Sub(start).Milliseconds())
		if len(res.Errors) < 8 {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", what, err))
		}
	}
	end := start.Add(d)
	every2 := func(f func()) {
		wg.Go(func() {
			for time.Now().Before(end) {
				go f()
				time.Sleep(every)
			}
		})
	}
	if tcpAddr != "" {
		every2(func() {
			at := time.Now()
			err := tcpEcho(tcpAddr)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.TCPFail++
				fail("tcp", err, at)
			} else {
				res.TCPOK++
			}
		})
	}
	if httpAddr != "" {
		client := via(httpAddr, false)
		client.Transport.(*http.Transport).DisableKeepAlives = true
		every2(func() {
			at := time.Now()
			err := httpGet(client, url)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.HTTPFail++
				fail("http", err, at)
			} else {
				res.HTTPOK++
			}
		})
	}
	if udpAddr != "" {
		wg.Go(func() { udpFlow(udpAddr, start, end, every, &mu, &res) })
	}
	wg.Wait()
	time.Sleep(2 * time.Second) // the attempts still in flight
	mu.Lock()
	defer mu.Unlock()
	return res
}

func tcpEcho(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second) //nolint:gosec // G704: the route under test
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	msg := []byte("0123456789abcdef")
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return fmt.Errorf("echo %q", got)
	}
	return nil
}

func httpGet(client *http.Client, url string) error {
	resp, err := client.Get(url) //nolint:gosec // G704: the route under test
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

// udpFlow keeps one UDP flow busy and records every silence over udpGap, also the one that a
// run ends in.
func udpFlow(addr string, start, end time.Time, every time.Duration, mu *sync.Mutex, res *probeResult) {
	c, err := net.Dial("udp", addr) //nolint:gosec // G704: the route under test
	if err != nil {
		mu.Lock()
		res.Errors = append(res.Errors, "udp: "+err.Error())
		mu.Unlock()
		return
	}
	defer func() { _ = c.Close() }()
	last := start
	note := func(now time.Time) {
		if g := now.Sub(last); g > udpGap {
			mu.Lock()
			res.UDPGaps = append(res.UDPGaps, gap{AtMS: last.Sub(start).Milliseconds(), GapMS: g.Milliseconds()})
			mu.Unlock()
		}
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			_ = c.SetReadDeadline(end.Add(3 * time.Second))
			if _, err := c.Read(buf); err != nil {
				if time.Now().After(end) {
					close(done)
					return
				}
				continue // an ICMP port unreachable for an earlier datagram
			}
			now := time.Now()
			note(now)
			mu.Lock()
			res.UDPOK++
			last = now
			mu.Unlock()
		}
	}()
	for time.Now().Before(end) {
		_, _ = c.Write([]byte("probe"))
		time.Sleep(every)
	}
	<-done
	mu.Lock()
	gapNow := end.Sub(last)
	mu.Unlock()
	if gapNow > udpGap+3*time.Second { // the run's last seconds without an answer
		mu.Lock()
		res.UDPGaps = append(res.UDPGaps, gap{AtMS: last.Sub(start).Milliseconds(), GapMS: gapNow.Milliseconds()})
		mu.Unlock()
	}
}

func printProbe(r probeResult) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

// scrape prints the body of url.
func scrape(url string) error {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url) //nolint:gosec // G107: the test's own admin URL
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(stdout{}, resp.Body)
	return err
}

type stdout struct{}

func (stdout) Write(p []byte) (int, error) { return fmt.Print(string(p)) }

// accepts listens on addr for d and prints the time of each TCP connection since the start, in
// milliseconds, closing each at once: the stand-in for a gateway that is down.
func accepts(addr string, d time.Duration) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()
	start := time.Now()
	var at []int64
	go func() {
		time.Sleep(d)
		_ = l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			break
		}
		at = append(at, time.Since(start).Milliseconds())
		_ = c.Close()
	}
	b, _ := json.Marshal(at)
	fmt.Println(string(b))
	return nil
}
