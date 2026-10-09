// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// echoServer echoes every connection until the client's FIN.
func echoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// dataPlane is a controller with a gateway and a connector, each run by its role's Run, and a tcp
// route from the gateway's port to an echo service next to the connector.
type dataPlane struct {
	c                  *itest.Controller
	routeID, connector string
	gatewayID          string
	publicPort         int
	gwCfg              config.Gateway
	stopGateway        func()
	conCfg             config.Connector
	stopConnector      func()
	broken             atomic.Bool // the gateway's snapshot gets an invalid resource
}

func newDataPlane(t *testing.T) *dataPlane {
	t.Helper()
	p := &dataPlane{}
	sources := append(routes.Sources(), func(_ context.Context, _ *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
		if a.Identity.Kind != pki.KindGateway || !p.broken.Load() {
			return nil, nil
		}
		return []*agentv1.Resource{{Id: "rt_broken", Kind: &agentv1.Resource_GatewayTcpRoute{GatewayTcpRoute: &agentv1.GatewayTCPRoute{}}}}, nil
	})
	p.c = itest.StartController(t, itest.Options{Sources: sources})
	c := p.c
	dir := t.TempDir()
	tunnelPort, svc := freeTCPUDPPort(t), echoServer(t)
	p.publicPort = freeTCPUDPPort(t)
	group := c.GatewayGroup(t, "eu")
	gw := c.EnrollGateway(t, filepath.Join(dir, "gw-id"), group, []string{addr(tunnelPort)})
	con := c.EnrollConnector(t, filepath.Join(dir, "con-id"))
	p.connector, p.gatewayID = con.AgentID, gw.AgentID
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		if _, err := routes.AddPool(c.Sys, tx, c.Org, group, routes.TCP, p.publicPort, p.publicPort); err != nil {
			return nil, err
		}
		alloc, err := routes.Allocate(c.Sys, tx, c.Org, group, routes.TCP, p.publicPort)
		if err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("echo").SetType("tcp").SetGatewayGroupID(group).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		p.routeID = r.ID
		if err := tx.RouteTCP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetPortAllocationID(alloc.ID).Exec(c.Sys); err != nil {
			return nil, err
		}
		return []string{r.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(con.AgentID).
			SetKind("address").SetHost("127.0.0.1").SetPort(svc).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}

	p.gwCfg.Version = 1
	p.gwCfg.Controller.Endpoints = []string{c.URL}
	p.gwCfg.IdentityDir, p.gwCfg.StateDir = gw.Dir, filepath.Join(dir, "gw-state")
	p.gwCfg.Listen.TCP, p.gwCfg.Listen.UDP, p.gwCfg.Listen.Admin = addr(tunnelPort), addr(tunnelPort), addr(freeTCPUDPPort(t))
	if err := os.MkdirAll(p.gwCfg.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	p.startGateway(t)

	var cc config.Connector
	cc.Version = 1
	cc.Controller.Endpoints = []string{c.URL}
	cc.IdentityDir, cc.StateDir = con.Dir, filepath.Join(dir, "con-state")
	cc.PolicyFile = filepath.Join(dir, "policy.yaml")
	cc.Listen.Admin = addr(freeTCPUDPPort(t))
	if err := os.MkdirAll(cc.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	policy := fmt.Sprintf("version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [%d]\n", svc)
	if err := os.WriteFile(cc.PolicyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	p.conCfg = cc
	p.startConnector(t, nil)
	return p
}

// startGateway runs the gateway role; stopGateway ends it.
func (p *dataPlane) startGateway(t *testing.T) {
	t.Helper()
	p.stopGateway = runRole(t, func(ctx context.Context, listening func()) error {
		return gateway.Run(ctx, gateway.RunOptions{Config: p.gwCfg, Version: "0.1.0", DrainPeriod: 200 * time.Millisecond, Listening: listening,
			Logger: p.c.Logs.Logger()})
	})
}

// startConnector runs the connector role on the clock now (nil is time.Now); stopConnector ends it.
func (p *dataPlane) startConnector(t *testing.T, now func() time.Time) {
	t.Helper()
	p.stopConnector = runRole(t, func(ctx context.Context, listening func()) error {
		return connector.Run(ctx, connector.RunOptions{Config: p.conCfg, Version: "0.1.0", Getenv: func(string) string { return "" },
			Now: now, Listening: listening, Logger: p.c.Logs.Logger()})
	})
}

// runRole runs a role until the returned function or the test's cleanup stops it.
func runRole(t *testing.T, run func(ctx context.Context, listening func()) error) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listening, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- run(ctx, func() { close(listening) }) }()
	select {
	case <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("the role did not start: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the role did not start")
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("the role ended with %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("the role did not stop")
		}
	}
	t.Cleanup(stop)
	return stop
}

// dial connects to the route's public port once it answers through the whole data plane.
func (p *dataPlane) dial(t *testing.T) *net.TCPConn {
	t.Helper()
	var c *net.TCPConn
	waitFor(t, "the route does not answer", func() bool {
		conn, err := net.Dial("tcp", addr(p.publicPort))
		if err != nil {
			return false
		}
		if ping(conn, "hello") != nil {
			_ = conn.Close()
			return false
		}
		c = conn.(*net.TCPConn)
		return true
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ping(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != msg {
		return fmt.Errorf("echo %q", b)
	}
	return nil
}

func (p *dataPlane) revise(t *testing.T, fn func(tx *ent.Tx) error) {
	t.Helper()
	if _, err := store.ConfigTx(p.c.Sys, p.c.DB, func(tx *ent.Tx) ([]string, error) { return []string{p.routeID}, fn(tx) }); err != nil {
		t.Fatal(err)
	}
}

// TestTCPRoute_EndToEnd: a public connection to a tcp route's port reaches the service behind the
// connector through controller-configured gateway and connector processes, 4 MiB each way intact
// and with the client's half-close kept; neither an unrelated change nor a change of the same
// route resets it.
func TestTCPRoute_EndToEnd(t *testing.T) {
	p := newDataPlane(t)
	c := p.dial(t)
	up := make([]byte, 4<<20)
	_, _ = rand.Read(up)
	big, err := net.Dial("tcp", addr(p.publicPort))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = big.Write(up)
		_ = big.(*net.TCPConn).CloseWrite()
	}()
	down, err := io.ReadAll(big)
	if err != nil || sha256.Sum256(down) != sha256.Sum256(up) {
		t.Fatalf("4 MiB through the data plane: %d bytes, %v", len(down), err)
	}
	_ = big.Close()

	p.revise(t, func(tx *ent.Tx) error { return tx.Org.Create().SetName("org-b").SetSlug("org-b").Exec(p.c.Sys) })
	time.Sleep(500 * time.Millisecond)
	if err := ping(c, "after an unrelated change"); err != nil {
		t.Fatal(err)
	}
	p.revise(t, func(tx *ent.Tx) error {
		return tx.RouteTCP.Update().SetIdleTimeoutSeconds(7200).Exec(p.c.Sys)
	})
	time.Sleep(500 * time.Millisecond)
	if err := ping(c, "after a change of the same route"); err != nil {
		t.Fatal(err)
	}
}

// TestBadSnapshotKeepsLastKnownGood (traffic clause): a snapshot the gateway rejects changes
// nothing it runs: an open connection keeps working and new connections are still served; a
// gateway restarted while the controller is down serves the route from its last-known-good copy.
func TestBadSnapshotKeepsLastKnownGood(t *testing.T) {
	p := newDataPlane(t)
	c := p.dial(t)
	p.broken.Store(true)
	p.revise(t, func(tx *ent.Tx) error { return tx.Org.Create().SetName("org-b").SetSlug("org-b").Exec(p.c.Sys) })
	waitFor(t, "the gateway did not reject the snapshot", func() bool {
		st, err := p.c.DB.Client().AgentState.Get(p.c.Sys, p.gatewayID)
		return err == nil && controller.ApplyStatus(st, time.Now()) == controller.ApplyRejected
	})
	if err := ping(c, "after a rejected snapshot"); err != nil {
		t.Fatal(err)
	}
	if err := ping(p.dial(t), "a new connection"); err != nil {
		t.Fatal(err)
	}

	p.broken.Store(false)
	p.c.Stop()
	p.stopGateway()
	p.startGateway(t)
	if err := ping(p.dial(t), "after a restart without a controller"); err != nil {
		t.Fatal(err)
	}
}

// TestConnectorRole_Refusals: a connector does not start with a gateway's identity or with a proxy
// variable it cannot use.
func TestConnectorRole_Refusals(t *testing.T) {
	c := itest.StartController(t, itest.Options{})
	gw := c.EnrollGateway(t, filepath.Join(t.TempDir(), "gw"), c.GatewayGroup(t, "eu"), []string{"127.0.0.1:1"})
	con := c.EnrollConnector(t, filepath.Join(t.TempDir(), "con"))
	cfg := func(identity string) config.Connector {
		var cc config.Connector
		cc.Version = 1
		cc.Controller.Endpoints = []string{c.URL}
		cc.IdentityDir, cc.StateDir, cc.PolicyFile = identity, t.TempDir(), filepath.Join(t.TempDir(), "policy.yaml")
		cc.Listen.Admin = addr(freeTCPUDPPort(t))
		return cc
	}
	none := func(string) string { return "" }
	if err := connector.Run(context.Background(), connector.RunOptions{Config: cfg(gw.Dir), Getenv: none, Logger: c.Logs.Logger()}); err == nil ||
		!strings.Contains(err.Error(), "gateway") {
		t.Fatalf("a gateway's identity: %v", err)
	}
	proxy := func(k string) string { return map[string]string{"HTTPS_PROXY": "ftp://proxy.example"}[k] }
	if err := connector.Run(context.Background(), connector.RunOptions{Config: cfg(con.Dir), Getenv: proxy, Logger: c.Logs.Logger()}); err == nil ||
		!strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Fatalf("an unusable proxy: %v", err)
	}
}
