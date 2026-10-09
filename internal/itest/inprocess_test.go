// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// redirect is a dialer that takes any address to the controller, counting its dials: an agent whose
// endpoint names a host that does not resolve reaches the controller only through it.
type redirect struct {
	to    string
	dials atomic.Int64
}

func (r *redirect) dial(ctx context.Context, _ string) (net.Conn, error) {
	r.dials.Add(1)
	var d net.Dialer
	return d.DialContext(ctx, "tcp", r.to)
}

func newRedirect(t *testing.T, c *itest.Controller) *redirect {
	t.Helper()
	u, err := url.Parse(c.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &redirect{to: u.Host}
}

// TestControlSession_Dial: an agent's enrollment and its control session go through the dialer it
// is given, as all-in-one's in-process gateway reaches its controller.
func TestControlSession_Dial(t *testing.T) {
	c := itest.StartController(t, itest.Options{})
	r := newRedirect(t, c)
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	c.DB.Client().EnrollmentToken.Create().SetOrgID(c.Org).SetTokenHash(token.Hash(tok)).SetRole("connector").
		SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy("usr_itest").ExecX(c.Sys)
	dir := filepath.Join(t.TempDir(), "con")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: "https://controller.invalid", Pin: pki.RootPin(c.CA.Root()), Token: tok,
		IdentityDir: dir, Bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.CA.Root().Raw}), Dial: r.dial,
		Host: &agentv1.HostFacts{Hostname: "itest"}, Version: "0.1.0"}); err != nil {
		t.Fatalf("enrollment through the dialer: %v", err)
	}
	enrolled := r.dials.Load()
	if enrolled == 0 {
		t.Fatal("enrollment did not use the dialer")
	}
	id, err := agent.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	client, _, _ := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{"https://controller.invalid"}, Version: "0.1.0",
		Dial: r.dial})
	waitFor(t, "no session through the dialer", func() bool { return welcomes(client) == 1 })
	if r.dials.Load() == enrolled {
		t.Fatal("the control session did not use the dialer")
	}
}

// TestGatewayRole_InProcess: a gateway given a controller hand-off and a registry passes the
// controller's names on port 443 to it and serves no admin listener of its own; its readiness goes
// to the caller.
func TestGatewayRole_InProcess(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: routes.Sources()})
	tunnelPort := freeTCPUDPPort(t)
	gw := c.EnrollGateway(t, filepath.Join(t.TempDir(), "gw"), c.GatewayGroup(t, "eu"), []string{addr(tunnelPort)})
	cfg := gatewayConfig(t, c, gw.Dir, tunnelPort)
	r := newRedirect(t, c)
	handed := make(chan string, 4)
	var ready atomic.Pointer[func(context.Context) error]
	reg := telemetry.NewRegistry()
	runRole(t, func(ctx context.Context, listening func()) error {
		return gateway.Run(ctx, gateway.RunOptions{Config: cfg, Version: "0.1.0", DrainPeriod: 100 * time.Millisecond, Logger: c.Logs.Logger(), Listening: listening,
			Dial: r.dial, Registry: reg, Readiness: func(check func(context.Context) error) { ready.Store(&check) },
			ControllerNames: []string{"panel.example.com"},
			Controller: func(conn net.Conn) {
				handed <- conn.RemoteAddr().String()
				_ = conn.Close()
			}})
	})
	waitFor(t, "the gateway is not ready", func() bool {
		check := ready.Load()
		return check != nil && (*check)(context.Background()) == nil
	})
	if r.dials.Load() == 0 {
		t.Fatal("the control plane did not use the dialer")
	}
	for _, name := range []string{"controller." + gw.TrustDomain, "PANEL.example.com"} {
		conn, err := tls.Dial("tcp", addr(tunnelPort), &tls.Config{ServerName: name, MinVersion: tls.VersionTLS13})
		if err == nil {
			_ = conn.Close()
		}
		select {
		case <-handed:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s was not handed to the controller", name)
		}
	}
	if resp, err := http.Get("http://" + cfg.Listen.Admin + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an admin listener of its own")
	}
	if mfs, err := reg.Gather(); err != nil || len(mfs) == 0 {
		t.Fatalf("no metrics in the given registry: %v", err)
	}
}
