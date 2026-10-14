// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/memnet"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestDataSession_InMemory: a gateway and a connector in one process, as all-in-one runs them,
// serve a tcp route pinned to QUIC over one in-memory data session, although the gateway's tunnel
// endpoint answers nothing; both register their metrics on one registry, apart by a role label,
// and neither serves an admin listener of its own.
func TestDataSession_InMemory(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: routes.Sources()})
	dir := t.TempDir()
	tunnelPort, publicPort, svc := freeTCPUDPPort(t), freeTCPUDPPort(t), echoServer(t)
	group := c.GatewayGroup(t, "eu")
	gw := c.EnrollGateway(t, filepath.Join(dir, "gw-id"), group, []string{addr(freeTCPUDPPort(t))}) // nothing listens there
	con := c.EnrollConnector(t, filepath.Join(dir, "con-id"))
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		if _, err := routes.AddPool(c.Sys, tx, c.Org, group, routes.TCP, publicPort, publicPort); err != nil {
			return nil, err
		}
		alloc, err := routes.Allocate(c.Sys, tx, c.Org, group, routes.TCP, publicPort)
		if err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("echo").SetType("tcp").SetGatewayGroupID(group).SetTransport("quic").Save(c.Sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteTCP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetPortAllocationID(alloc.ID).Exec(c.Sys); err != nil {
			return nil, err
		}
		return []string{r.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(con.AgentID).
			SetKind("address").SetHost("127.0.0.1").SetPort(svc).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}

	reg := telemetry.NewRegistry()
	var (
		mu     sync.Mutex
		checks []func(context.Context) error
	)
	readiness := func(check func(context.Context) error) {
		mu.Lock()
		checks = append(checks, check)
		mu.Unlock()
	}
	tunnels := memnet.NewListener()
	gwCfg := gatewayConfig(t, c, gw.Dir, tunnelPort)
	runRole(t, func(ctx context.Context, listening func()) error {
		return gateway.Run(ctx, gateway.RunOptions{Config: gwCfg, Version: "0.1.0", DrainPeriod: 100 * time.Millisecond, Logger: c.Logs.Logger(),
			Listening: listening, Registry: telemetry.WithLabels(reg, prometheus.Labels{"role": "gateway"}), Readiness: readiness, Tunnels: tunnels})
	})
	var cc config.Connector
	cc.Version = 1
	cc.Controller.Endpoints = []string{c.URL}
	cc.IdentityDir, cc.StateDir = con.Dir, filepath.Join(dir, "con-state")
	cc.PolicyFile = filepath.Join(dir, "policy.yaml")
	cc.Listen.Admin = addr(freeTCPUDPPort(t))
	if err := os.MkdirAll(cc.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cc.PolicyFile, fmt.Appendf(nil, "version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [%d]\n", svc), 0o600); err != nil {
		t.Fatal(err)
	}
	runRole(t, func(ctx context.Context, listening func()) error {
		return connector.Run(ctx, connector.RunOptions{Config: cc, Version: "0.1.0", Getenv: func(string) string { return "" }, Logger: c.Logs.Logger(),
			Listening: listening, Registry: telemetry.WithLabels(reg, prometheus.Labels{"role": "connector"}), Readiness: readiness,
			InProcess: &connector.InProcess{GatewayID: gw.AgentID, Dial: func(ctx context.Context) (net.Conn, error) { return tunnels.Dial(ctx, "") }}})
	})

	waitFor(t, "the route does not answer through the in-memory session", func() bool {
		conn, err := net.Dial("tcp", addr(publicPort))
		if err != nil {
			return false
		}
		defer func() { _ = conn.Close() }()
		return ping(conn, "hello") == nil
	})
	waitFor(t, "a role is not ready", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, check := range checks {
			if check(context.Background()) != nil {
				return false
			}
		}
		return len(checks) == 2
	})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]bool{}
	for _, mf := range mfs {
		if mf.GetName() != "rpmgr_agent_applied_revision" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "role" {
					roles[l.GetValue()] = true
				}
			}
		}
	}
	if !roles["gateway"] || !roles["connector"] || len(roles) != 2 {
		t.Fatalf("rpmgr_agent_applied_revision for roles %v, want gateway and connector", roles)
	}
	for _, admin := range []string{gwCfg.Listen.Admin, cc.Listen.Admin} {
		if resp, err := http.Get("http://" + admin + "/healthz"); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("an admin listener of its own on %s", admin)
		}
	}
}
