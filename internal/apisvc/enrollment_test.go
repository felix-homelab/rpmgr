// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/settings"
)

func ptr[T any](v T) *T { return &v }

// TestEnrollmentTokens: minting needs a step-up; a token is single-use and lasts an hour unless
// set otherwise, 30 days at most; only an ephemeral token with a set lifetime enrolls more than one
// connector; a re-enrollment token names a live connector of the org and nothing else.
func TestEnrollmentTokens(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	create := func(b *browser, m *rpmgrv1.CreateEnrollmentTokenRequest) (*rpmgrv1.CreateEnrollmentTokenResponse, error) {
		m.OrgId = org
		r, err := b.enr.CreateEnrollmentToken(ctx, connect.NewRequest(m))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	if _, err := create(ada, &rpmgrv1.CreateEnrollmentTokenRequest{}); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	first, err := create(ada, &rpmgrv1.CreateEnrollmentTokenRequest{Labels: map[string]string{"site": "office"}, GatewayGroupId: group})
	tk := first.GetEnrollmentToken()
	if err != nil || !strings.HasPrefix(first.GetToken(), "rpmgr_enr_") || tk.GetMaxUses() != 1 || tk.GetEphemeral() ||
		tk.GetRole() != rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR || tk.GetCreatedBy() != e.ada || tk.GetGatewayGroupId() != group ||
		!tk.GetExpireTime().AsTime().Equal(e.clock.Add(time.Hour).Truncate(time.Microsecond)) && !tk.GetExpireTime().AsTime().Equal(e.clock.Add(time.Hour)) {
		t.Fatalf("a default token: %v %v", first, err)
	}
	unlimited, err := create(ada, &rpmgrv1.CreateEnrollmentTokenRequest{Ephemeral: true, MaxUses: ptr[int32](0), Ttl: durationpb.New(24 * time.Hour)})
	if err != nil || unlimited.GetEnrollmentToken().GetMaxUses() != 0 || !unlimited.GetEnrollmentToken().GetEphemeral() {
		t.Fatalf("an unlimited ephemeral token: %v %v", unlimited, err)
	}
	if _, err := create(ada, &rpmgrv1.CreateEnrollmentTokenRequest{Ephemeral: true, MaxUses: ptr[int32](5), Ttl: durationpb.New(30 * 24 * time.Hour)}); err != nil {
		t.Fatalf("five uses for 30 days: %v", err)
	}

	con := e.db.Client().Connector.Create().SetOrgID(org).SetName("nas").SetSpiffeID("spiffe://rpmgr-teststor/org/" + org + "/connector/x").
		SetPubkeySha256("k").SaveX(e.sys)
	gone := e.db.Client().Connector.Create().SetOrgID(org).SetName("old").SetSpiffeID("spiffe://rpmgr-teststor/org/" + org + "/connector/y").
		SetPubkeySha256("k").SetDecommissionedAt(e.clock).SaveX(e.sys)
	if r, err := create(ada, &rpmgrv1.CreateEnrollmentTokenRequest{ConnectorId: con.ID}); err != nil ||
		r.GetEnrollmentToken().GetConnectorId() != con.ID || r.GetEnrollmentToken().GetMaxUses() != 1 {
		t.Fatalf("a re-enrollment token: %v %v", r, err)
	}
	for name, c := range map[string]struct {
		m    *rpmgrv1.CreateEnrollmentTokenRequest
		want connect.Code
	}{
		"31 days":                    {&rpmgrv1.CreateEnrollmentTokenRequest{Ttl: durationpb.New(31 * 24 * time.Hour)}, connect.CodeInvalidArgument},
		"a zero lifetime":            {&rpmgrv1.CreateEnrollmentTokenRequest{Ttl: durationpb.New(0)}, connect.CodeInvalidArgument},
		"multi-use, not ephemeral":   {&rpmgrv1.CreateEnrollmentTokenRequest{MaxUses: ptr[int32](2), Ttl: durationpb.New(time.Hour)}, connect.CodeInvalidArgument},
		"multi-use without lifetime": {&rpmgrv1.CreateEnrollmentTokenRequest{Ephemeral: true, MaxUses: ptr[int32](2)}, connect.CodeInvalidArgument},
		"unlimited without lifetime": {&rpmgrv1.CreateEnrollmentTokenRequest{Ephemeral: true, MaxUses: ptr[int32](0)}, connect.CodeInvalidArgument},
		"negative uses":              {&rpmgrv1.CreateEnrollmentTokenRequest{MaxUses: ptr[int32](-1)}, connect.CodeInvalidArgument},
		"a bad label":                {&rpmgrv1.CreateEnrollmentTokenRequest{Labels: map[string]string{"Not Valid": "x"}}, connect.CodeInvalidArgument},
		"a missing group":            {&rpmgrv1.CreateEnrollmentTokenRequest{GatewayGroupId: "gwg_missing"}, connect.CodeNotFound},
		"re-enrolling, with labels":  {&rpmgrv1.CreateEnrollmentTokenRequest{ConnectorId: con.ID, Labels: map[string]string{"a": "b"}}, connect.CodeInvalidArgument},
		"re-enrolling, ephemeral":    {&rpmgrv1.CreateEnrollmentTokenRequest{ConnectorId: con.ID, Ephemeral: true}, connect.CodeInvalidArgument},
		"re-enrolling, in a group":   {&rpmgrv1.CreateEnrollmentTokenRequest{ConnectorId: con.ID, GatewayGroupId: group}, connect.CodeInvalidArgument},
		"re-enrolling, multi-use":    {&rpmgrv1.CreateEnrollmentTokenRequest{ConnectorId: con.ID, MaxUses: ptr[int32](0), Ephemeral: true, Ttl: durationpb.New(time.Hour)}, connect.CodeInvalidArgument},
		"re-enrolling a missing one": {&rpmgrv1.CreateEnrollmentTokenRequest{ConnectorId: "con_missing"}, connect.CodeNotFound},
		"re-enrolling a retired one": {&rpmgrv1.CreateEnrollmentTokenRequest{ConnectorId: gone.ID}, connect.CodeFailedPrecondition},
	} {
		if _, err := create(ada, c.m); code(err) != c.want {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

}

// TestEnrollmentTokens_Roles: an Operator mints connector tokens only where the org allows it, and
// never gateway tokens; a gateway token is single-use, scoped to its gateway and group, refused
// for a decommissioned gateway.
func TestEnrollmentTokens_Roles(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	for _, b := range []*browser{ada, op} {
		if err := b.stepUp(pw, ""); err != nil {
			t.Fatal(err)
		}
	}
	connectorToken := func(b *browser) (*rpmgrv1.EnrollmentToken, error) {
		r, err := b.enr.CreateEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateEnrollmentTokenRequest{OrgId: org}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetEnrollmentToken(), nil
	}
	gatewayToken := func(b *browser, id string) (*rpmgrv1.EnrollmentToken, error) {
		r, err := b.enr.CreateGatewayEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayEnrollmentTokenRequest{GatewayId: id}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetEnrollmentToken(), nil
	}
	if _, err := connectorToken(op); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Operator in an org that does not allow it: %v", err)
	}
	if _, err := settings.UpdateOrg(e.sys, e.db, org, &rpmgrv1.OrgSettings{OperatorsMayEnroll: ptr(true)},
		&fieldmaskpb.FieldMask{Paths: []string{"operators_may_enroll"}}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := connectorToken(op); err != nil {
		t.Fatalf("an Operator in an org that allows it: %v", err)
	}
	if _, err := gatewayToken(op, gw.GetId()); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Operator mints a gateway token: %v", err)
	}
	gt, err := gatewayToken(ada, gw.GetId())
	if err != nil || gt.GetRole() != rpmgrv1.AgentRole_AGENT_ROLE_GATEWAY || gt.GetGatewayId() != gw.GetId() ||
		gt.GetGatewayGroupId() != group || gt.GetMaxUses() != 1 {
		t.Fatalf("a gateway token: %v %v", gt, err)
	}
	if _, err := gatewayToken(ada, "gw_missing"); code(err) != connect.CodeNotFound {
		t.Fatalf("a missing gateway: %v", err)
	}
	if _, err := ada.gw.DecommissionGateway(ctx, connect.NewRequest(&rpmgrv1.DecommissionGatewayRequest{GatewayId: gw.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := gatewayToken(ada, gw.GetId()); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a decommissioned gateway: %v", err)
	}
}
