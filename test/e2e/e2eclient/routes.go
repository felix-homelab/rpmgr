// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// serveAll runs the services: TCP echo on every address of listen, and the UDP echo, the HTTP
// upstream and the TLS backend where an address is given. It returns when one of them fails.
func serveAll(listen, udpAddr, httpAddr, tlsAddr, certFile, keyFile string) error {
	errs := make(chan error, 8)
	for _, a := range strings.Split(listen, ",") {
		go func() { errs <- serve(a) }()
	}
	if udpAddr != "" {
		go func() { errs <- serveUDP(udpAddr) }()
	}
	h := upstream()
	if httpAddr != "" {
		p := new(http.Protocols)
		p.SetHTTP1(true)
		p.SetUnencryptedHTTP2(true)
		srv := &http.Server{Addr: httpAddr, Handler: h, Protocols: p, ReadHeaderTimeout: 10 * time.Second}
		go func() { errs <- srv.ListenAndServe() }()
	}
	if tlsAddr != "" {
		srv := &http.Server{Addr: tlsAddr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		go func() { errs <- srv.ListenAndServeTLS(certFile, keyFile) }()
	}
	return <-errs
}

// serveUDP echoes every datagram to its sender.
func serveUDP(addr string) error {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	buf := make([]byte, 65535)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, _ = c.WriteTo(buf[:n], from)
	}
}

// upstream answers gRPC health checks, WebSocket upgrades on /ws by echoing what follows, and
// every other request with its protocol, host, path and X-Forwarded-For.
func upstream() http.Handler {
	g := grpc.NewServer()
	healthpb.RegisterHealthServer(g, health.NewServer())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc"):
			g.ServeHTTP(w, r)
		case r.URL.Path == "/ws" && strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
			c, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = brw.Flush()
			_, _ = io.Copy(c, brw)
		default:
			//nolint:gosec // G705: the test upstream echoes the request as plain text
			_, _ = fmt.Fprintf(w, "%s %s %s xff=%s", r.Proto, r.Host, r.URL.Path, r.Header.Get("X-Forwarded-For"))
		}
	})
}

// udpCheck sends a payload of each size to addr until its echo comes back, for up to d each.
func udpCheck(addr, sizes string, d time.Duration) error {
	c, err := net.Dial("udp", addr) //nolint:gosec // G704: the route under test
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, 65535)
	for _, s := range strings.Split(sizes, ",") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		p := make([]byte, n)
		_, _ = rand.Read(p)
		ok := false
		for end := time.Now().Add(d); !ok && time.Now().Before(end); {
			// A write may report an ICMP port unreachable for an earlier datagram, while a gateway
			// has not bound the route's port yet: that is a loss, retried.
			_, _ = c.Write(p)
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if m, err := c.Read(buf); err == nil && bytes.Equal(buf[:m], p) {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("no echo of %d bytes within %s", n, d)
		}
	}
	return nil
}

// via is a client that dials addr whatever the URL's host, which stays the TLS server name.
func via(addr string, h2 bool) *http.Client {
	p := new(http.Protocols)
	p.SetHTTP1(!h2)
	p.SetHTTP2(h2)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Protocols: p, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}}
}

// httpCheck gets url through addr and expects 200, the protocol asked for, and a body with expect.
func httpCheck(addr, url string, h2 bool, expect string) error {
	resp, err := via(addr, h2).Get(url) //nolint:gosec // G704: the route under test
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if want := map[bool]int{false: 1, true: 2}[h2]; resp.StatusCode != http.StatusOK || resp.ProtoMajor != want ||
		!strings.Contains(string(body), expect) {
		return fmt.Errorf("%s over HTTP/%d: %q, want 200 over HTTP/%d with %q", resp.Status, resp.ProtoMajor, body, want, expect)
	}
	return nil
}

// wsCheck upgrades /ws on host through addr and expects its echo.
func wsCheck(addr, host string) error {
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = fmt.Fprintf(c, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", host)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("upgrade: %s", resp.Status)
	}
	msg := []byte("through the tunnel")
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil || !bytes.Equal(got, msg) {
		return fmt.Errorf("echo %q: %w", got, err)
	}
	return nil
}

// grpcCheck asks the gRPC health service of host through addr, and expects an unknown service to
// fail with NotFound, a status that comes in the trailers.
func grpcCheck(addr, host string) error {
	cc, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(credentials.NewTLS(
		&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})))
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("health: %v: %w", resp, err)
	}
	if _, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{Service: "nope"}); err == nil ||
		!strings.Contains(err.Error(), "NotFound") {
		return fmt.Errorf("an unknown service: %w, want NotFound", err)
	}
	return nil
}

// tlsCheck connects to host through addr, expects the backend's certificate with common name cn,
// and gets / over the same connection.
func tlsCheck(addr, host, cn string) error {
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if got := c.ConnectionState().PeerCertificates[0].Subject.CommonName; got != cn {
		return fmt.Errorf("the certificate of %q, want the backend's %q", got, cn)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("through the passthrough: %s", resp.Status)
	}
	return nil
}
