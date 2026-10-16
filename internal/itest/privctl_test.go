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

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
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
// reaches (R23), and the instance settings list the gateway's address among the controller
// endpoints: the UI answers on its hostname, an agent enrolls, gets that endpoint and keeps its
// control session through the gateway, and the gateway relays only ciphertext, so the enrollment
// token never crosses it in clear. A changed list reaches the agent with its next snapshot, and its
// next session and the host's commands use it. A controller that stops answering resets new
// connections at once.
func TestPrivateController(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: routes.Sources()})
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
		return gateway.Run(ctx, gateway.RunOptions{Config: cfg, Version: "0.1.0", DrainPeriod: 200 * time.Millisecond, Logger: c.Logs.Logger(),
			Listening: listening, ForwardDial: rec.dial})
	})

	toGateway := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr(gwPort))
	}
	web := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, a string) (net.Conn, error) { return toGateway(ctx, a) },
		TLSClientConfig: &tls.Config{RootCAs: c.UIRoots, MinVersion: tls.VersionTLS13}}}
	viaGateway := "https://" + addr(gwPort)
	setEndpoints := func(eps ...string) {
		t.Helper()
		if _, err := settings.UpdateInstance(c.Sys, c.DB, &rpmgrv1.InstanceSettings{ControllerEndpoints: eps},
			&fieldmaskpb.FieldMask{Paths: []string{"controller_endpoints"}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	setEndpoints(viaGateway)
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
	if !slices.Equal(id.Endpoints, []string{viaGateway}) {
		t.Fatalf("enrolled with the controller endpoints %v, want the gateway's %s", id.Endpoints, viaGateway)
	}
	conState := filepath.Join(dir, "con-state")
	if err := os.MkdirAll(conState, 0o750); err != nil {
		t.Fatal(err)
	}
	applied := &recorder{}
	ctl, err := agent.NewControl(agent.ControlOptions{IdentityDir: conDir, StateDir: conState, Version: "0.1.0", Applier: applied,
		Backoff: fast(), Logger: c.Logs.Logger()})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopRun := context.WithCancel(context.Background())
	running := make(chan struct{})
	go func() { _ = ctl.Run(runCtx); close(running) }()
	t.Cleanup(func() { stopRun(); <-running })
	controllerAddr := func() string { a, _ := ctl.ControllerAddr(); return a }
	waitFor(t, "a control session through the gateway", func() bool {
		return slices.Contains(c.Sessions.Connected(), id.AgentID) && controllerAddr() == addr(gwPort)
	})
	waitFor(t, "a snapshot naming the gateway", func() bool { return slices.Equal(applied.lastEndpoints(), []string{viaGateway}) })

	seen := rec.bytes()
	if !bytes.Contains(seen, []byte("controller."+c.CA.TrustDomain())) || !bytes.Contains(seen, []byte(itest.UIHostname)) {
		t.Fatal("the recording missed the ClientHellos")
	}
	if bytes.Contains(seen, []byte(tok)) {
		t.Fatal("the enrollment token crossed the gateway in clear")
	}

	// The operator lists the controller's direct address instead: the connected agent learns it
	// with its next snapshot and dials it once its session ends.
	setEndpoints(c.URL)
	waitFor(t, "a snapshot naming the controller", func() bool { return slices.Equal(applied.lastEndpoints(), []string{c.URL}) })
	c.Sessions.Send(id.AgentID, &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Goodbye{
		Goodbye: &agentv1.Goodbye{Reason: agentv1.GoodbyeReason_GOODBYE_REASON_SHUTDOWN}}})
	waitFor(t, "a direct control session", func() bool {
		return slices.Contains(c.Sessions.Connected(), id.AgentID) && controllerAddr() == strings.TrimPrefix(c.URL, "https://")
	})

	// The host's commands follow the stored snapshot, not the enrollment: `rpmgr status` shows the
	// controller's address, and `rpmgr diag clock` and `rpmgr leave` dial it, never the gateway.
	waitFor(t, "a stored snapshot naming the controller", func() bool {
		l, err := agent.ReadLocal(conDir, conState, time.Now())
		return err == nil && slices.Equal(l.ControllerEndpoints(), []string{c.URL}) && slices.Equal(l.Endpoints, []string{viaGateway})
	})
	var dialMu sync.Mutex
	var dialled []string
	dial := func(ctx context.Context, a string) (net.Conn, error) {
		dialMu.Lock()
		dialled = append(dialled, a)
		dialMu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, "tcp", a)
	}
	if clk, err := agent.MeasureClock(ctx, conDir, conState, "0.1.0", time.Now, dial); err != nil || clk.Endpoint != c.URL {
		t.Fatalf("the clock measured at %q: %v, want %s", clk.Endpoint, err, c.URL)
	}
	stopRun()
	<-running
	if _, err := agent.Leave(ctx, conDir, conState, dial); err != nil {
		t.Fatalf("leave: %v", err)
	}
	dialMu.Lock()
	if len(dialled) == 0 || slices.ContainsFunc(dialled, func(a string) bool { return a != strings.TrimPrefix(c.URL, "https://") }) {
		t.Errorf("the host's commands dialled %v, want only the controller", dialled)
	}
	dialMu.Unlock()

	c.Stop()
	start := time.Now()
	_, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr(gwPort),
		&tls.Config{ServerName: "controller." + c.CA.TrustDomain(), RootCAs: c.UIRoots, MinVersion: tls.VersionTLS13})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("a stopped controller: %v after %s, want a reset at once", err, time.Since(start))
	}
}
