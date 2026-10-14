// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/token"
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
		t.Fatalf("an update of a connector's built_in: %v", err)
	}
	for _, id := range []string{gw.GetId(), other.GetId()} {
		if _, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: id, BuiltIn: id != gw.GetId()},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"built_in"}}})); code(err) != connect.CodeInvalidArgument {
			t.Fatalf("an update of a gateway's built_in: %v", err)
		}
	}
	if e.db.Client().Gateway.GetX(e.sys, gw.GetId()).BuiltIn != true || e.db.Client().Gateway.GetX(e.sys, other.GetId()).BuiltIn {
		t.Fatal("an update changed built_in")
	}
}

// TestBuiltInTokens (ADR-0019): the tokens all-in-one makes for its own connector are neither
// listed nor revocable through the API; the org's other tokens are.
func TestBuiltInTokens(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	mine, err := ada.enr.CreateEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	builtIn := e.db.Client().EnrollmentToken.Create().SetOrgID(org).SetTokenHash(token.Hash(tok)).SetRole("connector").SetBuiltIn(true).
		SetMaxUses(1).SetExpiresAt(e.clock.Add(time.Hour)).SetCreatedBy("local-cli").SaveX(e.sys)
	for _, inactive := range []bool{false, true} {
		r, err := ada.enr.ListEnrollmentTokens(ctx, connect.NewRequest(&rpmgrv1.ListEnrollmentTokensRequest{OrgId: org, ShowInactive: inactive}))
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, tk := range r.Msg.GetEnrollmentTokens() {
			ids = append(ids, tk.GetId())
		}
		if !slices.Contains(ids, mine.Msg.GetEnrollmentToken().GetId()) || slices.Contains(ids, builtIn.ID) {
			t.Fatalf("listed (inactive too: %v): %v", inactive, ids)
		}
	}
	if _, err := ada.enr.RevokeEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.RevokeEnrollmentTokenRequest{EnrollmentTokenId: builtIn.ID})); code(err) != connect.CodeNotFound {
		t.Fatalf("revoking a built-in token: %v", err)
	}
	if e.db.Client().EnrollmentToken.GetX(e.sys, builtIn.ID).RevokedAt != nil {
		t.Fatal("the built-in token was revoked")
	}
	if _, err := ada.enr.RevokeEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.RevokeEnrollmentTokenRequest{EnrollmentTokenId: mine.Msg.GetEnrollmentToken().GetId()})); err != nil {
		t.Fatalf("revoking another token: %v", err)
	}
}
