// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// recorder keeps every byte the gateway relays towards and from the controller.
type recorder struct {
	mu   sync.Mutex
	seen bytes.Buffer
}

func (r *recorder) dial(ctx context.Context, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: c, r: r}, nil
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.seen.Bytes())
}

// recordingConn records what passes; it embeds the interface, not *net.TCPConn, so io.Copy cannot
// bypass Read and Write through ReadFrom or WriteTo.
type recordingConn struct {
	net.Conn
	r *recorder
}

func (c *recordingConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.r.mu.Lock()
	c.r.seen.Write(p[:n])
	c.r.mu.Unlock()
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.r.mu.Lock()
	c.r.seen.Write(p)
	c.r.mu.Unlock()
	return c.Conn.Write(p)
}

// TestForward_ControllerNames: the agent names and the configured UI hostnames reach the private
// controller still encrypted: the client sees the controller's own certificate, and what the
// gateway relays holds the server name but never the plaintext.
func TestForward_ControllerNames(t *testing.T) {
	agentName, ui := "controller."+td, "panel.example.com"
	addr, pool := backend(t, agentName, "reauth."+agentName, ui)
	var rec recorder
	f := gateway.NewForward(addr, rec.dial, nil)
	t.Cleanup(f.Close)
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	front := serve(t, &gateway.Router{TrustDomain: td, GatewayID: "gw_01", DefaultTLS: def, Controller: f.Serve,
		ControllerNames: []string{ui}})
	const marker = "a marker only the controller may read"
	for _, sni := range []string{agentName, "reauth." + agentName, "PANEL.example.com"} {
		c, err := tls.Dial("tcp", front, &tls.Config{ServerName: sni, RootCAs: pool, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		if cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "the backend" {
			t.Fatalf("%s: the client saw %q", sni, cn)
		}
		if _, err := c.Write([]byte(marker)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(marker))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != marker {
			t.Fatalf("%s: echo %q %v", sni, got, err)
		}
		_ = c.Close()
	}
	seen := rec.bytes()
	if !bytes.Contains(seen, []byte(agentName)) {
		t.Fatal("the recording missed the ClientHello")
	}
	if bytes.Contains(seen, []byte(marker)) {
		t.Fatal("the gateway relayed plaintext")
	}
	if _, err := tls.Dial("tcp", front, &tls.Config{ServerName: "other.example.com", RootCAs: pool, MinVersion: tls.VersionTLS13}); err == nil {
		t.Fatal("a name that is not the controller's reached it")
	}
	eventually(t, "forwarded connections stay counted", func() bool { return f.Conns() == 0 })
}

// TestForward_HalfClose: the end of one direction is passed on, the other keeps working.
func TestForward_HalfClose(t *testing.T) {
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
		got, _ := io.ReadAll(c) // until the client's FIN
		_, _ = c.Write(append([]byte("after FIN: "), got...))
		_ = c.Close()
	}()
	f := gateway.NewForward(ln.Addr().String(), nil, nil)
	t.Cleanup(f.Close)
	front, back := tcpPair(t)
	go f.Serve(back)
	if _, err := front.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = front.CloseWrite()
	_ = front.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(front)
	if err != nil || string(got) != "after FIN: hello" {
		t.Fatalf("%q %v", got, err)
	}
}

// TestForward_Unreachable: a controller that does not answer resets the agent's connection at
// once, so the agent tries its next endpoint.
func TestForward_Unreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	f := gateway.NewForward(addr, nil, nil)
	t.Cleanup(f.Close)
	front, back := tcpPair(t)
	start := time.Now()
	go f.Serve(back)
	_ = front.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = front.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %s, want a reset at once", err, time.Since(start))
	}
}

// TestForward_Close: Close ends the forwarded connections and refuses new ones.
func TestForward_Close(t *testing.T) {
	addr, _ := backend(t, "controller."+td)
	f := gateway.NewForward(addr, nil, nil)
	front, back := tcpPair(t)
	go f.Serve(back)
	eventually(t, "not forwarded", func() bool { return f.Conns() == 2 })
	f.Close()
	_ = front.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := front.Read(make([]byte, 1)); err == nil {
		t.Fatal("a forwarded connection outlived Close")
	}
	front2, back2 := tcpPair(t)
	f.Serve(back2)
	_ = front2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := front2.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection was forwarded after Close")
	}
	if f.Conns() != 0 {
		t.Fatalf("%d connections counted after Close", f.Conns())
	}
}

// tcpPair returns the client's and the gateway's ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c.(*net.TCPConn), s
}

// TestRun_PassthroughAndInProcessController: a gateway with an in-process controller (all-in-one)
// has no private controller to forward to.
func TestRun_PassthroughAndInProcessController(t *testing.T) {
	var cfg config.Gateway
	cfg.Controller.Passthrough.Address = "10.0.0.5:443"
	err := gateway.Run(t.Context(), gateway.RunOptions{Config: cfg, Controller: func(c net.Conn) { _ = c.Close() }})
	if err == nil || !strings.Contains(err.Error(), "controller.passthrough") {
		t.Fatalf("got %v", err)
	}
}
