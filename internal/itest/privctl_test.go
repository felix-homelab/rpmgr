// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// relayed records what a gateway relays to and from the controller.
type relayed struct {
	mu   sync.Mutex
	seen bytes.Buffer
}

func (r *relayed) dial(ctx context.Context, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &relayedConn{Conn: c, r: r}, nil
}

func (r *relayed) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.seen.Bytes())
}

// relayedConn embeds the interface, so io.Copy cannot bypass Read and Write.
type relayedConn struct {
	net.Conn
	r *relayed
}

func (c *relayedConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

func (c *relayedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.r.mu.Lock()
	c.r.seen.Write(p[:n])
	c.r.mu.Unlock()
	return n, err
}

func (c *relayedConn) Write(p []byte) (int, error) {
	c.r.mu.Lock()
	c.r.seen.Write(p)
	c.r.mu.Unlock()
	return c.Conn.Write(p)
}

// TestPrivateController: a gateway forwards the controller's names to a controller that only it
// reaches (R23): the UI answers on its hostname, an agent enrolls and keeps its control session
// through the gateway, and the gateway relays only ciphertext, so the enrollment token never
// crosses it in clear. A controller that stops answering resets new connections at once.
func TestPrivateController(t *testing.T) {
	c := itest.StartController(t, itest.Options{})
	dir := t.TempDir()
	gwPort := freeTCPUDPPort(t)
	gw := c.EnrollGateway(t, filepath.Join(dir, "gw-id"), c.GatewayGroup(t, "edge"), []string{addr(gwPort)})
	var cfg config.Gateway
	cfg.Version = 1
	cfg.Controller.Endpoints = []string{c.URL}
	cfg.Controller.Passthrough = config.Passthrough{Address: strings.TrimPrefix(c.URL, "https://"), Hostnames: []string{itest.UIHostname}}
	cfg.IdentityDir, cfg.StateDir = gw.Dir, filepath.Join(dir, "gw-state")
	cfg.Listen.TCP, cfg.Listen.UDP, cfg.Listen.Admin = addr(gwPort), addr(gwPort), addr(freeTCPUDPPort(t))
	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	var rec relayed
	runRole(t, func(ctx context.Context, listening func()) error {
		return gateway.Run(ctx, gateway.RunOptions{Config: cfg, Version: "0.1.0", DrainPeriod: 200 * time.Millisecond,
			Listening: listening, ForwardDial: rec.dial})
	})

	toGateway := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr(gwPort))
	}
	web := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, a string) (net.Conn, error) { return toGateway(ctx, a) },
		TLSClientConfig: &tls.Config{RootCAs: c.UIRoots, MinVersion: tls.VersionTLS13}}}
	resp, err := web.Get("https://" + itest.UIHostname + "/.well-known/rpmgr/trust-bundle")
	if err != nil {
		t.Fatalf("the UI through the gateway: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the UI through the gateway: %s", resp.Status)
	}

	tok := c.EnrollmentToken(t, func(tc *ent.EnrollmentTokenCreate) { tc.SetRole("connector") })
	conDir := filepath.Join(dir, "con-id")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: "https://" + itest.UIHostname, Pin: pki.RootPin(c.CA.Root()),
		Token: tok, IdentityDir: conDir, HTTPClient: web, Host: &agentv1.HostFacts{Hostname: "itest"}, Version: "0.1.0",
		Dial: toGateway}); err != nil {
		t.Fatalf("enrollment through the gateway: %v", err)
	}
	id, err := agent.Load(conDir)
	if err != nil {
		t.Fatal(err)
	}
	run(t, agent.ClientOptions{Identity: id, Endpoints: []string{"https://" + addr(gwPort)}, Version: "0.1.0", BootID: "b1"})
	waitFor(t, "a control session through the gateway", func() bool { return slices.Contains(c.Sessions.Connected(), id.AgentID) })

	seen := rec.bytes()
	if !bytes.Contains(seen, []byte("controller."+c.CA.TrustDomain())) || !bytes.Contains(seen, []byte(itest.UIHostname)) {
		t.Fatal("the recording missed the ClientHellos")
	}
	if bytes.Contains(seen, []byte(tok)) {
		t.Fatal("the enrollment token crossed the gateway in clear")
	}

	c.Stop()
	start := time.Now()
	_, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr(gwPort),
		&tls.Config{ServerName: "controller." + c.CA.TrustDomain(), RootCAs: c.UIRoots, MinVersion: tls.VersionTLS13})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("a stopped controller: %v after %s, want a reset at once", err, time.Since(start))
	}
}
