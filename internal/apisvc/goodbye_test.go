// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// TestAgentsBelowMinimum (docs/09-web-ui.md, "Connector and gateway lists"): a connector or
// gateway the controller refused for its version shows that it is below min_agent_version, the
// version it came with and the reason of the Goodbye, in the lists too; one whose session was
// accepted, or that never connected, shows neither.
func TestAgentsBelowMinimum(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	old := c.Connector.Create().SetOrgID(org).SetName("old").SetSpiffeID("spiffe://t/old").SetPubkeySha256("a").SaveX(e.sys)
	cur := c.Connector.Create().SetOrgID(org).SetName("cur").SetSpiffeID("spiffe://t/cur").SetPubkeySha256("b").SaveX(e.sys)
	never := c.Connector.Create().SetOrgID(org).SetName("never").SetSpiffeID("spiffe://t/never").SetPubkeySha256("c").SaveX(e.sys)
	gw := c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group).SetName("gw1").SetSlot(1).SetTunnelEndpoints([]string{"gw1.example:443"}).
		SetSpiffeID("spiffe://t/gw1").SaveX(e.sys)
	for id, goodbye := range map[string]string{old.ID: "upgrade_required", cur.ID: "", gw.ID: "upgrade_required"} {
		v := "1.5.0"
		if goodbye != "" {
			v = "1.3.9"
		}
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetAgentVersion(v).SetLastGoodbye(goodbye).
			SetDisconnectedAt(e.clock).SaveX(e.sys)
	}

	list, err := ada.con.ListConnectors(ctx, connect.NewRequest(&rpmgrv1.ListConnectorsRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*rpmgrv1.AgentSession{}
	for _, x := range list.Msg.GetConnectors() {
		got[x.GetId()] = x.GetSession()
	}
	if s := got[old.ID]; !s.GetBelowMinAgentVersion() || s.GetLastGoodbyeReason() != "upgrade_required" || s.GetVersion() != "1.3.9" || s.GetConnected() {
		t.Errorf("the refused connector: %v", s)
	}
	for _, id := range []string{cur.ID, never.ID} {
		if s := got[id]; s.GetBelowMinAgentVersion() || s.GetLastGoodbyeReason() != "" {
			t.Errorf("connector %s: %v", id, s)
		}
	}
	one, err := ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: old.ID}))
	if err != nil || !one.Msg.GetConnector().GetSession().GetBelowMinAgentVersion() {
		t.Errorf("get connector: %v %v", one, err)
	}
	g, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gw.ID}))
	if err != nil || !g.Msg.GetGateway().GetStatus().GetBelowMinAgentVersion() || g.Msg.GetGateway().GetStatus().GetLastGoodbyeReason() != "upgrade_required" {
		t.Errorf("the refused gateway: %v %v", g, err)
	}
}
