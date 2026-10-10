// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedidentity"
)

// enrolledWithState enrolls a connector and gives it a state directory holding a stored snapshot and
// deny-list, as a connector that ran leaves behind.
func enrolledWithState(t *testing.T, c *itest.Controller) (agent.Loaded, string) {
	t.Helper()
	dir := t.TempDir()
	l := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{agent.LastKnownGoodFile, agent.DenyListFile} {
		if err := os.WriteFile(filepath.Join(state, f), []byte("stored"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return l, state
}

func identityOf(t *testing.T, l agent.Loaded) pki.Identity {
	t.Helper()
	id, err := pki.ParseSPIFFE(l.Certificate.Leaf.URIs[0], l.TrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestLeave: `rpmgr leave` has the controller revoke the agent's identity and decommission its
// connector or gateway, logged and audited with the agent as the actor, and only then removes the
// identity and the stored state from the host. With the identity revoked already, or the
// controller unreachable, nothing is removed.
func TestLeave(t *testing.T) {
	ctx := context.Background()
	c := itest.StartController(t, itest.Options{})
	con, state := enrolledWithState(t, c)
	left, err := agent.Leave(ctx, con.Dir, state, nil)
	if err != nil || left.AgentID != con.AgentID {
		t.Fatalf("leave: %v %v", left.AgentID, err)
	}
	for _, dir := range []string{con.Dir, state} {
		if es, err := os.ReadDir(dir); err != nil || len(es) != 0 {
			t.Errorf("%s still holds %v (%v)", dir, es, err)
		}
	}
	id := identityOf(t, con)
	if row := c.DB.Client().Connector.GetX(c.Sys, con.AgentID); row.DecommissionedAt == nil || row.Enabled {
		t.Errorf("the connector after leaving: %+v", row)
	}
	if !c.DB.Client().RevokedIdentity.Query().Where(revokedidentity.ID(id.String())).ExistX(c.Sys) {
		t.Error("the identity is not revoked")
	}
	if e := c.DB.Client().AuditEntry.Query().Where(auditentry.Action("identity.revoke"), auditentry.TargetID(con.AgentID)).OnlyX(c.Sys); string(e.ActorType) != string(audit.ActorAgent) || e.ActorID != con.AgentID {
		t.Errorf("audit entry %+v", e)
	}
	if es, err := revlog.Read(c.RevLogPath); err != nil || len(es) == 0 || es[len(es)-1].Kind != revlog.IdentityRevoked || es[len(es)-1].Subject != id.String() {
		t.Errorf("revocation log %+v %v", es, err)
	}

	gw := c.EnrollGateway(t, filepath.Join(t.TempDir(), "gw"), c.GatewayGroup(t, "eu"), []string{"127.0.0.1:1"})
	if _, err := agent.Leave(ctx, gw.Dir, t.TempDir(), nil); err != nil {
		t.Fatalf("a gateway leaves: %v", err)
	}
	if row := c.DB.Client().Gateway.GetX(c.Sys, gw.AgentID); row.DecommissionedAt == nil {
		t.Error("the gateway is not decommissioned")
	}

	revoked, revokedState := enrolledWithState(t, c)
	if err := c.Revoker().RevokeIdentity(c.Sys, identityOf(t, revoked), "decommissioned", controller.Actor{Type: audit.ActorUser, ID: "usr_admin"}); err != nil {
		t.Fatal(err)
	}
	unreachable, unreachableState := enrolledWithState(t, c)
	if _, err := agent.Leave(ctx, revoked.Dir, revokedState, nil); !errors.Is(err, agent.ErrNotLeft) {
		t.Errorf("an identity revoked already: %v", err)
	}
	c.Stop()
	if _, err := agent.Leave(ctx, unreachable.Dir, unreachableState, nil); !errors.Is(err, agent.ErrNotLeft) {
		t.Errorf("the controller unreachable: %v", err)
	}
	for _, kept := range []struct{ id, state string }{{revoked.Dir, revokedState}, {unreachable.Dir, unreachableState}} {
		if _, err := agent.Load(kept.id); err != nil {
			t.Errorf("a refused leave removed the identity: %v", err)
		}
		if _, err := os.Stat(filepath.Join(kept.state, agent.LastKnownGoodFile)); err != nil {
			t.Errorf("a refused leave removed the stored snapshot: %v", err)
		}
	}
}

// TestDiagClock: `rpmgr diag clock` reports a controller clock 45 s ahead as about 45 s; without a
// controller it fails.
func TestDiagClock(t *testing.T) {
	c := itest.StartController(t, itest.Options{Now: func() time.Time { return time.Now().Add(45 * time.Second) }})
	l := c.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	clk, err := agent.MeasureClock(context.Background(), l.Dir, "0.1.0", time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if clk.Offset < 40*time.Second || clk.Offset > 50*time.Second || clk.RTT <= 0 || clk.RTT > 5*time.Second || clk.Endpoint != c.URL {
		t.Errorf("clock %+v, want an offset of about 45 s", clk)
	}
	c.Stop()
	if _, err := agent.MeasureClock(context.Background(), l.Dir, "0.1.0", time.Now, nil); err == nil {
		t.Error("no controller, and still a measurement")
	}
}

// TestDiagTransport: `rpmgr diag transport` completes a QUIC and a TCP handshake to the gateway of
// the connector's configuration and closes them, and the route keeps working; a gateway the
// configuration does not name, a connector without configuration and a gateway host are refused.
func TestDiagTransport(t *testing.T) {
	p := newDataPlane(t)
	p.dial(t) // the connector runs with its configuration
	d, err := connector.Diagnose(context.Background(), p.conCfg.IdentityDir, p.conCfg.StateDir, p.gatewayID, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Probes) != 2 {
		t.Fatalf("probes %+v", d.Probes)
	}
	for _, pr := range d.Probes {
		if pr.Err != nil || pr.Gateway != p.gatewayID || pr.Handshake <= 0 || pr.Transport == connector.TransportQUIC && pr.RTT <= 0 {
			t.Errorf("probe %+v", pr)
		}
	}
	if d.MTU <= 0 || d.Interface == "" {
		t.Errorf("no MTU towards the gateway: %+v", d)
	}
	p.dial(t) // the route still answers

	// What `rpmgr status` reads: the stored snapshot verifies; a damaged one is reported.
	l, err := agent.ReadLocal(p.conCfg.IdentityDir, p.conCfg.StateDir, time.Now())
	if err != nil || l.Snapshot == nil || l.SnapshotErr != nil || l.Snapshot.GetRevision().GetSeq() == 0 {
		t.Errorf("local state: %+v %v", l.SnapshotErr, err)
	}
	damaged := t.TempDir()
	if err := os.WriteFile(filepath.Join(damaged, agent.LastKnownGoodFile), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := agent.ReadLocal(p.conCfg.IdentityDir, damaged, time.Now()); err != nil || l.Snapshot != nil || l.SnapshotErr == nil {
		t.Errorf("a damaged snapshot: %+v %v", l.SnapshotErr, err)
	}

	if _, err := connector.Diagnose(context.Background(), p.conCfg.IdentityDir, p.conCfg.StateDir, "gw_unknown", time.Now); err == nil {
		t.Error("a gateway the configuration does not name")
	}
	fresh := p.c.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	if _, err := connector.Diagnose(context.Background(), fresh.Dir, t.TempDir(), "", time.Now); err == nil {
		t.Error("a connector without configuration")
	}
	if _, err := connector.Diagnose(context.Background(), p.gwCfg.IdentityDir, p.gwCfg.StateDir, "", time.Now); err == nil {
		t.Error("a gateway's identity")
	}
}
