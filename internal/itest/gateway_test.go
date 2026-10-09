// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/testutil/freeport"
)

func freeTCPUDPPort(t *testing.T) int { return freeport.Port(t) }

func addr(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

// gatewayConfig is the boot file of a gateway enrolled into identityDir, listening on loopback.
func gatewayConfig(t *testing.T, c *itest.Controller, identityDir string, tunnelPort int) config.Gateway {
	t.Helper()
	var cfg config.Gateway
	cfg.Version = 1
	cfg.Controller.Endpoints = []string{c.URL}
	cfg.IdentityDir, cfg.StateDir = identityDir, filepath.Join(t.TempDir(), "state")
	cfg.Listen.TCP, cfg.Listen.UDP, cfg.Listen.Admin = addr(tunnelPort), addr(tunnelPort), addr(freeTCPUDPPort(t))
	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestGatewayRole: an enrolled gateway runs from its boot file: it becomes ready once its control
// session applied a snapshot, serves its routes' ports and port 443 for data sessions, keeps a
// stateless reset key, refuses a connector's identity, and stops at once when no stream is open.
func TestGatewayRole(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: routes.Sources()})
	group := c.GatewayGroup(t, "eu")
	tunnelPort, publicPort := freeTCPUDPPort(t), freeTCPUDPPort(t)
	gw := c.EnrollGateway(t, filepath.Join(t.TempDir(), "gw"), group, []string{addr(tunnelPort)})
	con := c.EnrollConnector(t, filepath.Join(t.TempDir(), "con"))
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		if _, err := routes.AddPool(c.Sys, tx, c.Org, group, routes.TCP, publicPort, publicPort); err != nil {
			return nil, err
		}
		alloc, err := routes.Allocate(c.Sys, tx, c.Org, group, routes.TCP, publicPort)
		if err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("db").SetType("tcp").SetGatewayGroupID(group).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteTCP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetPortAllocationID(alloc.ID).Exec(c.Sys); err != nil {
			return nil, err
		}
		return []string{r.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(con.AgentID).
			SetKind("address").SetHost("127.0.0.1").SetPort(5432).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}

	cfg := gatewayConfig(t, c, gw.Dir, tunnelPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listening, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- gateway.Run(ctx, gateway.RunOptions{Config: cfg, Version: "0.1.0", DrainPeriod: 30 * time.Second,
			Listening: func() { close(listening) }})
	}()
	select {
	case <-listening:
	case err := <-done:
		t.Fatalf("Run: %v", err)
	}
	waitFor(t, "the gateway is not ready", func() bool {
		resp, err := http.Get("http://" + cfg.Listen.Admin + "/readyz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	// The route's port answers, and resets the connection: no connector session yet.
	waitFor(t, "the route's port does not listen", func() bool {
		conn, err := net.Dial("tcp", addr(publicPort))
		if conn != nil {
			_ = conn.Close()
		}
		return err == nil || errors.Is(err, syscall.ECONNRESET) // the reset may come before Dial returns
	})
	// Port 443 completes a handshake for an unknown name with the default certificate.
	_, err := tls.Dial("tcp", addr(tunnelPort), &tls.Config{ServerName: "unknown.example", MinVersion: tls.VersionTLS13})
	var wrongName x509.HostnameError
	if !errors.As(err, &wrongName) || wrongName.Certificate.Subject.CommonName != "default.invalid" {
		t.Fatalf("an unknown name on port 443: %v, want the default certificate", err)
	}
	if st, err := os.Stat(filepath.Join(cfg.StateDir, gateway.ResetKeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stateless reset key: %v %v", st, err)
	}

	begin := time.Now()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run ended with %v", err)
	}
	if d := time.Since(begin); d > 5*time.Second {
		t.Fatalf("stopping without open streams took %s", d)
	}
	if conn, err := net.Dial("tcp", addr(publicPort)); err == nil {
		_ = conn.Close()
		t.Fatal("the route's port still listens after Run returned")
	}

	// A connector's identity is not a gateway's.
	wrong := gatewayConfig(t, c, con.Dir, freeTCPUDPPort(t))
	if err := gateway.Run(context.Background(), gateway.RunOptions{Config: wrong}); err == nil || !strings.Contains(err.Error(), "connector") {
		t.Fatalf("a connector's identity: %v", err)
	}
}
