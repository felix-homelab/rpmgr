// SPDX-License-Identifier: Apache-2.0

package allinone_test

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// TestAllInOne_ReplacesRevokedAgents (#599): Run replaces a built-in gateway and connector whose
// identities are revoked as a whole, as a restore that replays the revocation log leaves them, by
// new ones that it enrolls, instead of stopping the start. The revocations stay. The new gateway
// keeps the old one's group, name and tunnel endpoints, the new connector its name and route
// targets, so the route is served again; the old ones are decommissioned, each step audited. Then
// it does so again for a connector whose identity is both revoked and missing. An ordinary gateway
// whose identity is revoked is left alone and never adopted, and a plain restart replaces nothing.
func TestAllInOne_ReplacesRevokedAgents(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, group := h.db(t)
	gwDir, conDir := h.cfg.Gateway().IdentityDir, h.cfg.Connector().IdentityDir
	id, err := agent.Load(gwDir)
	if err != nil {
		t.Fatal(err)
	}
	td := id.TrustDomain
	oldGW := db.Client().Gateway.GetX(sys, r.GatewayID)
	svc, public := echoService(t), freePort(t)
	route := tcpRoute(t, db, sys, group, "echo", public, r.ConnectorID, "127.0.0.1:"+strconv.Itoa(svc))
	if err := os.WriteFile(h.cfg.PolicyFile, []byte("version: 1\nallow_targets: [0.0.0.0/0]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteID := pki.Identity{TrustDomain: td, Org: group.OrgID, Kind: pki.KindGateway, ID: ids.New("gw")}
	remote := db.Client().Gateway.Create().SetID(remoteID.ID).SetOrgID(group.OrgID).SetGatewayGroupID(group.ID).SetName("remote").
		SetTunnelEndpoints([]string{"gw2.example.com:443"}).SetSpiffeID(remoteID.String()).SaveX(sys)
	revokeIdentity(t, db, sys, remoteID)
	revokeIdentity(t, db, sys, pki.Identity{TrustDomain: td, Org: group.OrgID, Kind: pki.KindGateway, ID: r.GatewayID})
	revokeIdentity(t, db, sys, pki.Identity{TrustDomain: td, Org: group.OrgID, Kind: pki.KindConnector, ID: r.ConnectorID})
	tokens := func() int {
		return db.Client().EnrollmentToken.Query().Where(enrollmenttoken.BuiltIn(true)).CountX(sys)
	}
	before := tokens()

	stop := h.run(t)
	waitFor(t, "not ready with revoked identities", h.ready)
	waitFor(t, "the route is not served through the new connector", func() bool { return echoes(public) })
	stop()

	gw := db.Client().Gateway.Query().Where(gateway.BuiltIn(true), gateway.DecommissionedAtIsNil()).OnlyX(sys)
	if gw.ID == r.GatewayID || gw.Name != oldGW.Name || gw.GatewayGroupID != oldGW.GatewayGroupID ||
		!slices.Equal(gw.TunnelEndpoints, oldGW.TunnelEndpoints) || !gw.Enabled {
		t.Errorf("the new gateway %+v, the old one %+v", gw, oldGW)
	}
	if old := db.Client().Gateway.GetX(sys, r.GatewayID); old.DecommissionedAt == nil || old.Enabled {
		t.Errorf("the old gateway is in service: %+v", old)
	}
	if got, err := agent.ReadIdentity(gwDir); err != nil || got.AgentID != gw.ID {
		t.Errorf("the gateway's identity %+v %v, want %s", got, err, gw.ID)
	}
	con := db.Client().Connector.Query().Where(connector.BuiltIn(true), connector.DecommissionedAtIsNil()).OnlyX(sys)
	if con.ID == r.ConnectorID || con.Name != "local" || con.PubkeySha256 == "awaiting-enrollment" {
		t.Errorf("the new connector %+v", con)
	}
	if old := db.Client().Connector.GetX(sys, r.ConnectorID); old.DecommissionedAt == nil {
		t.Errorf("the old connector is in service: %+v", old)
	}
	if got, err := agent.ReadIdentity(conDir); err != nil || got.AgentID != con.ID {
		t.Errorf("the connector's identity %+v %v, want %s", got, err, con.ID)
	}
	if tg := db.Client().RouteTarget.Query().Where(routetarget.RouteID(route)).OnlyX(sys); tg.ConnectorID != con.ID {
		t.Errorf("the route's target is on %s, want %s", tg.ConnectorID, con.ID)
	}
	if n := db.Client().RevokedIdentity.Query().CountX(sys); n != 3 {
		t.Errorf("%d revoked identities, want the 3 revoked", n)
	}
	if g := db.Client().Gateway.GetX(sys, remote.ID); g.BuiltIn || g.DecommissionedAt != nil {
		t.Errorf("the ordinary gateway was taken over: %+v", g)
	}
	for _, want := range []struct{ action, target, reason string }{
		{"gateway.decommission", r.GatewayID, "its identity is revoked; replaced by gateway " + gw.ID},
		{"gateway.create", gw.ID, "replaces gateway " + r.GatewayID + ", whose identity is revoked"},
		{"connector.decommission", r.ConnectorID, "its identity is revoked; replaced by connector " + con.ID},
		{"connector.create", con.ID, "replaces connector " + r.ConnectorID + ", whose identity is revoked"},
		{"route.update", route, "moved to connector " + con.ID + ", which replaces it"},
		{"enrollment_token.create", "", "is revoked; it is replaced by gateway " + gw.ID},
		{"enrollment_token.create", "", "is revoked; it is replaced by connector " + con.ID},
	} {
		q := db.Client().AuditEntry.Query().Where(auditentry.Action(want.action))
		if want.target != "" {
			q.Where(auditentry.TargetID(want.target))
		}
		if !slices.ContainsFunc(q.AllX(sys), func(e *ent.AuditEntry) bool { return strings.Contains(e.Reason, want.reason) }) {
			t.Errorf("no audit entry %s %s with %q", want.action, want.target, want.reason)
		}
	}
	if tokens() != before+2 {
		t.Errorf("%d built-in tokens after %d, want 2 more", tokens(), before)
	}

	// A plain restart replaces nothing.
	stop = h.run(t)
	waitFor(t, "not ready after a restart", h.ready)
	stop()
	if n := db.Client().Gateway.Query().Where(gateway.BuiltIn(true)).CountX(sys); n != 2 || tokens() != before+2 {
		t.Errorf("a restart replaced again: %d built-in gateways, %d tokens", n, tokens())
	}

	// A connector whose identity is revoked and missing is replaced too, never enrolled as itself.
	revokeIdentity(t, db, sys, pki.Identity{TrustDomain: td, Org: group.OrgID, Kind: pki.KindConnector, ID: con.ID})
	if err := os.RemoveAll(conDir); err != nil {
		t.Fatal(err)
	}
	stop = h.run(t)
	waitFor(t, "not ready with a revoked, missing connector identity", h.ready)
	waitFor(t, "the route is not served through the third connector", func() bool { return echoes(public) })
	stop()
	third := db.Client().Connector.Query().Where(connector.BuiltIn(true), connector.DecommissionedAtIsNil()).OnlyX(sys)
	if third.ID == con.ID || third.ID == r.ConnectorID {
		t.Errorf("the connector was not replaced: %s", third.ID)
	}
	if got, err := agent.ReadIdentity(conDir); err != nil || got.AgentID != third.ID {
		t.Errorf("the connector's identity %+v %v, want %s", got, err, third.ID)
	}
}
