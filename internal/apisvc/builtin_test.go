// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// TestBuiltInAgents (ADR-0019): all-in-one's own gateway and connector show as built in, cannot be
// decommissioned nor re-enrolled through the API, as their process would stop with them, and can
// still be switched off; other agents are not built in.
func TestBuiltInAgents(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	gw, err := createGateway(ada, org, group, "local", "panel.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	e.db.Client().Gateway.UpdateOneID(gw.GetId()).SetBuiltIn(true).ExecX(e.sys)
	other, err := createGateway(ada, org, group, "other", "other.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	con := e.addConnector(t, org, "local", func(c *ent.ConnectorCreate) { c.SetBuiltIn(true) })
	nas := e.addConnector(t, org, "nas", nil)

	g, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gw.GetId()}))
	if err != nil || !g.Msg.GetGateway().GetBuiltIn() {
		t.Fatalf("the built-in gateway: %v %v", g, err)
	}
	if g, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: other.GetId()})); err != nil || g.Msg.GetGateway().GetBuiltIn() {
		t.Fatalf("another gateway: %v %v", g, err)
	}
	c, err := ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: con.ID}))
	if err != nil || !c.Msg.GetConnector().GetBuiltIn() {
		t.Fatalf("the built-in connector: %v %v", c, err)
	}
	if c, err := ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: nas.ID})); err != nil || c.Msg.GetConnector().GetBuiltIn() {
		t.Fatalf("another connector: %v %v", c, err)
	}

	_, err = ada.gw.DecommissionGateway(ctx, connect.NewRequest(&rpmgrv1.DecommissionGatewayRequest{GatewayId: gw.GetId()}))
	if code(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "cannot be decommissioned") {
		t.Fatalf("decommissioning the built-in gateway: %v", err)
	}
	_, err = ada.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: con.ID}))
	if code(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "cannot be decommissioned") {
		t.Fatalf("decommissioning the built-in connector: %v", err)
	}
	if e.db.Client().Gateway.GetX(e.sys, gw.GetId()).DecommissionedAt != nil || e.db.Client().Connector.GetX(e.sys, con.ID).DecommissionedAt != nil ||
		e.denied.Load() != 0 {
		t.Fatal("a refused decommission changed something")
	}

	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.enr.CreateGatewayEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayEnrollmentTokenRequest{GatewayId: gw.GetId()})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a token for the built-in gateway: %v", err)
	}
	if _, err := ada.enr.CreateEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org, ConnectorId: con.ID})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a re-enrollment token for the built-in connector: %v", err)
	}
	if _, err := ada.enr.CreateGatewayEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayEnrollmentTokenRequest{GatewayId: other.GetId()})); err != nil {
		t.Fatalf("a token for another gateway: %v", err)
	}

	off, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: gw.GetId()},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}}))
	if err != nil || off.Msg.GetGateway().GetEnabled() || !off.Msg.GetGateway().GetBuiltIn() {
		t.Fatalf("draining the built-in gateway: %v %v", off, err)
	}
	coff, err := ada.con.UpdateConnector(ctx, connect.NewRequest(&rpmgrv1.UpdateConnectorRequest{Connector: &rpmgrv1.Connector{Id: con.ID},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}}))
	if err != nil || coff.Msg.GetConnector().GetEnabled() {
		t.Fatalf("disabling the built-in connector: %v %v", coff, err)
	}
	if _, err := ada.con.UpdateConnector(ctx, connect.NewRequest(&rpmgrv1.UpdateConnectorRequest{Connector: &rpmgrv1.Connector{Id: con.ID},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"built_in"}}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("an update of built_in: %v", err)
	}
}
