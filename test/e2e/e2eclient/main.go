// SPDX-License-Identifier: Apache-2.0

// Command e2eclient is the traffic side of the end-to-end tests (docs/12-testing-and-quality.md,
// "Where the cells run"): the services behind the connectors (TCP and UDP echo, an HTTP upstream
// with WebSocket and gRPC, a TLS backend), and clients that check a route's data integrity, hold
// a connection open across changes, wait until a route stops answering, or check UDP, HTTP,
// WebSocket, gRPC and TLS passthrough routes. It prints one line and exits 1 when a check fails.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: e2eclient serve|check|hold|gone|ready|udp|http|ws|grpc|tls|load [flags]"))
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "", "the route's address, host:port")
	listen := fs.String("listen", ":7", "serve: the TCP echo service's addresses, comma-separated")
	udpAddr := fs.String("udp", "", "serve: the UDP echo service's address")
	httpAddr := fs.String("http", "", "serve: the HTTP upstream's address, HTTP/1.1 and h2c")
	tlsAddr := fs.String("tls", "", "serve: the TLS backend's address, HTTP/1.1 and HTTP/2")
	certFile := fs.String("cert", "", "serve: the TLS backend's certificate")
	keyFile := fs.String("key", "", "serve: the TLS backend's key")
	sizes := fs.String("sizes", "100,3000", "udp: payload sizes, comma-separated")
	target := fs.String("url", "", "ready: the admin listener's /readyz; http: the URL to get")
	host := fs.String("host", "", "ws, grpc, tls: the server name")
	h2 := fs.Bool("h2", false, "http: speak HTTP/2")
	expect := fs.String("expect", "", "http: text the body must contain; tls: the common name of the backend's certificate")
	size := fs.Int("bytes", 1<<20, "check: bytes to send")
	duration := fs.Duration("duration", 5*time.Second, "hold: how long to hold the connection; gone: how long to wait")
	every := fs.Duration("every", 200*time.Millisecond, "hold: how often to send a ping")
	addrs := fs.String("addrs", "", "load: the routes' addresses, comma-separated")
	conns := fs.Int("conns", 2, "load: connections per address")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "serve":
		err = serveAll(*listen, *udpAddr, *httpAddr, *tlsAddr, *certFile, *keyFile)
	case "check":
		err = check(*addr, *size)
	case "hold":
		err = hold(*addr, *duration, *every)
	case "gone":
		err = gone(*addr, *duration)
	case "ready":
		err = ready(*target, *duration)
	case "udp":
		err = udpCheck(*addr, *sizes, *duration)
	case "http":
		err = httpCheck(*addr, *target, *h2, *expect)
	case "ws":
		err = wsCheck(*addr, *host)
	case "grpc":
		err = grpcCheck(*addr, *host)
	case "tls":
		err = tlsCheck(*addr, *host, *expect)
	case "load":
		err = load(*addrs, *conns, *size, *duration)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
	fmt.Println("ok")
}

func fail(err error) {
	fmt.Println("FAIL:", err)
	os.Exit(1)
}

// serve echoes every connection until the client's FIN, then answers with its own.
func serve(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			_, _ = io.Copy(c, c)
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			_ = c.Close()
		}()
	}
}

// check sends size random bytes, half-closes and expects the same bytes back and then the end.
func check(addr string, size int) error {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second) //nolint:gosec // G704: the route under test
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	up := make([]byte, size)
	_, _ = rand.Read(up)
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(up)
		if err == nil {
			err = c.(*net.TCPConn).CloseWrite()
		}
		errc <- err
	}()
	down, err := io.ReadAll(c)
	if werr := <-errc; werr != nil {
		return fmt.Errorf("write: %w", werr)
	}
	if err != nil {
		return fmt.Errorf("read after %d bytes: %w", len(down), err)
	}
	if !bytes.Equal(down, up) {
		return fmt.Errorf("echo of %d bytes: %d bytes back, sha256 %x, want %x", size, len(down), sha256.Sum256(down), sha256.Sum256(up))
	}
	return nil
}

// hold keeps one connection and pings through it every interval for d; any error fails.
func hold(addr string, d, every time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second) //nolint:gosec // G704: the route under test
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, 8)
	for i, end := 0, time.Now().Add(d); time.Now().Before(end); i++ {
		msg := fmt.Appendf(nil, "%08d", i%100000000)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(msg); err != nil {
			return fmt.Errorf("ping %d: %w", i, err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			return fmt.Errorf("pong %d: %w", i, err)
		}
		if !bytes.Equal(buf, msg) {
			return fmt.Errorf("pong %d: %q", i, buf)
		}
		time.Sleep(every)
	}
	return nil
}

// gone waits up to d until a connection to addr no longer echoes.
func gone(addr string, d time.Duration) error {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second) //nolint:gosec // G704: the route under test
		if err != nil {
			return nil
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, werr := c.Write([]byte("x"))
		_, rerr := io.ReadFull(c, make([]byte, 1))
		_ = c.Close()
		if werr != nil || rerr != nil {
			return nil
		}
	}
	return fmt.Errorf("%s still echoes after %s", addr, d)
}

// ready waits up to d until url answers 200.
func ready(url string, d time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	last := errors.New("no answer")
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		resp, err := client.Get(url) //nolint:gosec // G107: the test's own admin URL
		if err != nil {
			last = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		last = fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(body))
	}
	return last
}

// load keeps conns connections per address busy for d: each sends size random bytes, expects them
// back and repeats on the same connection, and dials again after an error. Errors, such as resets
// while a process is killed, are counted; bytes that come back changed fail the run.
func load(addrs string, conns, size int, d time.Duration) error {
	var trips, errs atomic.Int64
	var corrupt atomic.Pointer[error]
	end := time.Now().Add(d)
	var wg sync.WaitGroup
	for _, a := range strings.Split(addrs, ",") {
		for range conns {
			wg.Go(func() {
				up, down := make([]byte, size), make([]byte, size)
				for time.Now().Before(end) && corrupt.Load() == nil {
					c, err := net.DialTimeout("tcp", a, 5*time.Second) //nolint:gosec // G704: the route under test
					if err != nil {
						errs.Add(1)
						time.Sleep(200 * time.Millisecond)
						continue
					}
					for time.Now().Before(end) && corrupt.Load() == nil {
						_, _ = rand.Read(up)
						_ = c.SetDeadline(time.Now().Add(20 * time.Second))
						werr := make(chan error, 1)
						go func() { _, err := c.Write(up); werr <- err }()
						_, rerr := io.ReadFull(c, down)
						if err := errors.Join(<-werr, rerr); err != nil {
							errs.Add(1)
							break
						}
						if !bytes.Equal(down, up) {
							err := fmt.Errorf("%s: %d bytes came back changed", a, size)
							corrupt.Store(&err)
							break
						}
						trips.Add(1)
					}
					_ = c.Close()
				}
			})
		}
	}
	wg.Wait()
	fmt.Printf("round trips %d, errors %d\n", trips.Load(), errs.Load())
	if err := corrupt.Load(); err != nil {
		return *err
	}
	if trips.Load() == 0 {
		return errors.New("no round trip")
	}
	return nil
}
