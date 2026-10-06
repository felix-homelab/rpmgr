// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/spikes/s1/internal/load"
	"github.com/felix-homelab/rpmgr/spikes/s1/internal/pki"
	"github.com/felix-homelab/rpmgr/spikes/s1/internal/tunnel"
)

const td = "rpmgr-test"

type rig struct {
	routes map[string]string // route → public address on the gateway
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// startRig runs service, gateway and connector in-process over the given transport.
func startRig(t *testing.T, transport string, extraRoutes map[string]string) rig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	if err := pki.Generate(dir, td, "gw1", "con1"); err != nil {
		t.Fatal(err)
	}
	sink, source, echo := listen(t), listen(t), listen(t)
	go func() { _ = load.ServeSink(sink) }()
	go func() { _ = load.ServeSource(source) }()
	go func() { _ = load.ServeEcho(echo) }()

	pool, gcert, err := pki.Load(dir, "gateway")
	if err != nil {
		t.Fatal(err)
	}
	g := tunnel.NewGateway()
	serverTLS := pki.ServerConfig(pool, gcert, td)
	var tunnelAddr string
	switch transport {
	case "quic":
		qln, err := tunnel.ListenQUIC("127.0.0.1:0", serverTLS)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = qln.Close() })
		tunnelAddr = qln.Addr().String()
		go func() { _ = g.AcceptQUIC(ctx, qln) }()
	case "h2":
		tln := listen(t)
		tunnelAddr = tln.Addr().String()
		t2, err := tunnel.H2Transport()
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = g.AcceptH2(tln, serverTLS, t2) }()
	}

	routes := map[string]string{
		"sink": sink.Addr().String(), "source": source.Addr().String(), "echo": echo.Addr().String(),
	}
	for k, v := range extraRoutes {
		routes[k] = v
	}
	_, ccert, err := pki.Load(dir, "connector")
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := pki.ClientConfig(pool, ccert, pki.Identity{TrustDomain: td, Role: "gateway", ID: "gw1"})
	c := &tunnel.Connector{Routes: routes}
	switch transport {
	case "quic":
		go func() { _ = c.RunQUIC(ctx, tunnelAddr, clientTLS) }()
	case "h2":
		for range 2 {
			go func() { _ = c.RunH2(ctx, tunnelAddr, clientTLS) }()
		}
	}
	select {
	case <-g.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("no data session within 10 s")
	}

	r := rig{routes: map[string]string{}}
	for _, route := range []string{"sink", "source", "echo", "missing", "refused"} {
		ln := listen(t)
		r.routes[route] = ln.Addr().String()
		go func() { _ = g.ServeRoute(ln, route) }()
	}
	return r
}

var transports = []string{"quic", "h2"}

func TestEchoIntegrityBothDirections(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr, func(t *testing.T) {
			r := startRig(t, tr, nil)
			c, err := net.Dial("tcp", r.routes["echo"])
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			payload := make([]byte, 8<<20)
			_, _ = rand.Read(payload)
			go func() {
				_, _ = c.Write(payload)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(got) != sha256.Sum256(payload) {
				t.Fatalf("echo mismatch: %d bytes back, want %d", len(got), len(payload))
			}
		})
	}
}

// TestHalfCloseServiceKeepsSending: after the client's FIN the service still delivers its
// remaining bytes (12-testing-and-quality.md, end-to-end assertions).
func TestHalfCloseServiceKeepsSending(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr, func(t *testing.T) {
			r := startRig(t, tr, nil)
			res, err := load.Throughput(context.Background(), r.routes["source"], "down", 1, 500*time.Millisecond)
			if err != nil || res.Failures != 0 {
				t.Fatalf("down: %v, failures %d", err, res.Failures)
			}
			if res.Bytes == 0 {
				t.Fatal("no bytes after the client's half-close")
			}
		})
	}
}

func TestUploadAcknowledged(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr, func(t *testing.T) {
			r := startRig(t, tr, nil)
			res, err := load.Throughput(context.Background(), r.routes["sink"], "up", 8, 300*time.Millisecond)
			if err != nil || res.Failures != 0 || res.Bytes == 0 {
				t.Fatalf("up: %v, failures %d, bytes %d", err, res.Failures, res.Bytes)
			}
		})
	}
}

// TestUnknownRouteAndRefusedTargetReset: StreamResult other than OK closes the client
// connection without data.
func TestUnknownRouteAndRefusedTargetReset(t *testing.T) {
	closed := listen(t)
	refusedAddr := closed.Addr().String()
	_ = closed.Close()
	for _, tr := range transports {
		t.Run(tr, func(t *testing.T) {
			r := startRig(t, tr, map[string]string{"refused": refusedAddr})
			for _, route := range []string{"missing", "refused"} {
				c, err := net.Dial("tcp", r.routes[route])
				if err != nil {
					t.Fatal(err)
				}
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = c.Write([]byte("hello"))
				n, err := c.Read(make([]byte, 16))
				if n != 0 || err == nil {
					t.Fatalf("%s: read %d bytes, err %v; want closed connection", route, n, err)
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					t.Fatalf("%s: connection not closed within 10 s", route)
				}
				_ = c.Close()
			}
		})
	}
}

func TestSetupLatencyMeasured(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr, func(t *testing.T) {
			r := startRig(t, tr, nil)
			res, err := load.Setup(context.Background(), r.routes["echo"], 200, time.Second)
			if err != nil || res.Failures != 0 || len(res.Latencies) != 200 {
				t.Fatalf("setup: %v, failures %d, conns %d", err, res.Failures, len(res.Latencies))
			}
			if res.Percentile(99) <= 0 || res.Percentile(50) > res.Percentile(99) {
				t.Fatalf("percentiles p50 %.3f p99 %.3f", res.Percentile(50), res.Percentile(99))
			}
		})
	}
}

func TestMessageFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := tunnel.WriteMessage(&buf, []byte("route-1")); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("payload")
	msg, err := tunnel.ReadMessage(&buf)
	if err != nil || string(msg) != "route-1" {
		t.Fatalf("got %q, %v", msg, err)
	}
	if rest := buf.String(); rest != "payload" {
		t.Fatalf("ReadMessage consumed bytes after the message: %q left", rest)
	}
	if err := tunnel.WriteMessage(io.Discard, make([]byte, 16<<10+1)); err == nil {
		t.Fatal("oversized message written")
	}
	// A length prefix above 16 KiB is refused before allocating.
	big := []byte{0x81, 0x80, 0x04} // varint 65 537
	if _, err := tunnel.ReadMessage(bytes.NewReader(big)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized length accepted: %v", err)
	}
	if _, err := tunnel.ReadMessage(bytes.NewReader([]byte{0x05, 'a'})); err == nil {
		t.Fatal("truncated message accepted")
	}
}

func TestLoadRejectsInvalidArguments(t *testing.T) {
	ctx := context.Background()
	if _, err := load.Throughput(ctx, "127.0.0.1:1", "sideways", 1, time.Millisecond); err == nil {
		t.Fatal("unknown direction accepted")
	}
	if _, err := load.Throughput(ctx, "127.0.0.1:1", "up", 0, time.Millisecond); err == nil {
		t.Fatal("zero streams accepted")
	}
	if _, err := load.Setup(ctx, "127.0.0.1:1", 0, time.Second); err == nil {
		t.Fatal("zero rate accepted")
	}
	// A refused target counts as failures, not as an error of the run.
	closed := listen(t)
	addr := closed.Addr().String()
	_ = closed.Close()
	res, err := load.Throughput(ctx, addr, "up", 2, time.Millisecond)
	if err != nil || res.Failures != 2 {
		t.Fatalf("refused target: %v, failures %d", err, res.Failures)
	}
}

// TestPeerRoleEnforced: a connector certificate cannot pose as the gateway, so the TLS
// handshake fails instead of silently succeeding.
func TestPeerRoleEnforced(t *testing.T) {
	dir := t.TempDir()
	if err := pki.Generate(dir, td, "gw1", "con1"); err != nil {
		t.Fatal(err)
	}
	pool, ccert, err := pki.Load(dir, "connector")
	if err != nil {
		t.Fatal(err)
	}
	// The "gateway" presents the connector's certificate.
	ln, err := tunnel.ListenQUIC("127.0.0.1:0", pki.ServerConfig(pool, ccert, td))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = ln.Accept(ctx) }()
	_, err = tunnel.DialQUIC(ctx, ln.Addr().String(), pki.ClientConfig(pool, ccert, pki.Identity{TrustDomain: td, Role: "gateway", ID: "gw1"}))
	if err == nil {
		t.Fatal("handshake with a connector certificate posing as the gateway succeeded")
	}
}
