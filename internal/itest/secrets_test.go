// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// TestSecretsNeverLogged drives the paths that handle tokens and keys with every component of the
// controller and both roles logging at the debug level to a checking sink (docs/12, "Security
// testing"); the rest of the integration suite logs to such a sink too.
func TestSecretsNeverLogged(t *testing.T) {
	p := newDataPlane(t) // enrolls a gateway and a connector with tokens, runs their sessions
	c := p.dial(t)
	if err := ping(c, "through the tunnel"); err != nil {
		t.Fatal(err)
	}

	unknown, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	p.c.Logs.Secret(unknown)
	expired := p.c.EnrollmentToken(t, func(tc *ent.EnrollmentTokenCreate) {
		tc.SetRole("connector").SetExpiresAt(time.Now().Add(-time.Minute))
	})
	for name, tok := range map[string]string{"an unknown token": unknown, "an expired token": expired} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: p.c.URL, Pin: pki.RootPin(p.c.CA.Root()), Token: tok,
			IdentityDir: filepath.Join(t.TempDir(), "id"), Bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.c.CA.Root().Raw}),
			Host: &agentv1.HostFacts{Hostname: "itest"}, Version: "0.1.0"})
		cancel()
		if err == nil {
			t.Fatalf("enrollment with %s succeeded", name)
		}
	}

	p.broken.Store(true)
	p.revise(t, func(tx *ent.Tx) error { return tx.Org.Create().SetName("org-b").SetSlug("org-b").Exec(p.c.Sys) })
	waitFor(t, "the gateway did not reject the snapshot", func() bool {
		st, err := p.c.DB.Client().AgentState.Get(p.c.Sys, p.gatewayID)
		return err == nil && controller.ApplyStatus(st, time.Now()) == controller.ApplyRejected
	})
	p.stopConnector()
	p.stopGateway()
	t.Logf("%d log lines checked", p.c.Logs.Lines())
	if p.c.Logs.Lines() == 0 {
		t.Fatal("nothing was logged, so nothing was checked")
	}
}
