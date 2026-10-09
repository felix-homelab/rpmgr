// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/settings"
)

func ptr[T any](v T) *T { return &v }

// TestEnrollmentTokens: minting needs a step-up; a token is single-use and lasts an hour unless
// set otherwise, 30 days at most; only an ephemeral token with a set lifetime enrolls more than one
// connector; a re-enrollment token names a live connector of the org and nothing else; the list
// leaves out what can no longer enroll, and never holds a token.
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

	list := func(inactive bool) []*rpmgrv1.EnrollmentToken {
		t.Helper()
		r, err := ada.enr.ListEnrollmentTokens(ctx, connect.NewRequest(&rpmgrv1.ListEnrollmentTokensRequest{OrgId: org, ShowInactive: inactive}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetEnrollmentTokens()
	}
	if n := len(list(false)); n != 4 {
		t.Fatalf("%d live tokens, want 4", n)
	}
	e.db.Client().EnrollmentToken.UpdateOneID(tk.GetId()).SetUseCount(1).ExecX(e.sys) // used up
	e.clock = e.clock.Add(2 * time.Hour)                                              // the 1-hour ones expire
	live := list(false)
	if len(live) != 2 || len(list(true)) != 4 {
		t.Fatalf("live %d, all %d", len(live), len(list(true)))
	}
	for _, l := range list(true) {
		if strings.Contains(l.String(), "rpmgr_enr_") {
			t.Fatalf("the list holds a token: %v", l)
		}
	}
}

// TestEnrollmentTokens_Roles: an Operator mints connector tokens only where the org allows it, and
// never gateway tokens; a gateway token is single-use, scoped to its gateway and group, refused
// for a decommissioned gateway; revoking a gateway's token needs infrastructure.write, from the
// role and, for an API token, from its scopes; a second revocation keeps the first's time.
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
	opToken, err := connectorToken(op)
	if err != nil {
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

	revoke := func(b *browser, id string) (*rpmgrv1.EnrollmentToken, error) {
		r, err := b.enr.RevokeEnrollmentToken(ctx, connect.NewRequest(&rpmgrv1.RevokeEnrollmentTokenRequest{EnrollmentTokenId: id}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetEnrollmentToken(), nil
	}
	if _, err := revoke(op, gt.GetId()); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Operator revokes a gateway token: %v", err)
	}
	// An Owner's API token without infrastructure.write in its scopes cannot either.
	pat, err := ada.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "ci",
		Scopes: []string{"connectors.write"}}))
	if err != nil {
		t.Fatal(err)
	}
	bot := e.browser()
	bot.bearer = pat.Msg.GetToken()
	if _, err := revoke(bot, gt.GetId()); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a token scoped to connectors revokes a gateway token: %v", err)
	}
	if r, err := revoke(ada, gt.GetId()); err != nil || r.GetRevokeTime() == nil {
		t.Fatalf("an Owner revokes a gateway token: %v %v", r, err)
	}
	r, err := revoke(op, opToken.GetId())
	if err != nil || r.GetRevokeTime() == nil {
		t.Fatalf("an Operator revokes a connector token: %v %v", r, err)
	}
	e.clock = e.clock.Add(time.Minute)
	if again, err := revoke(op, opToken.GetId()); err != nil || !again.GetRevokeTime().AsTime().Equal(r.GetRevokeTime().AsTime()) {
		t.Fatalf("a second revocation: %v %v", again, err)
	}
	if _, err := revoke(ada, "enr_missing"); code(err) != connect.CodeNotFound {
		t.Fatalf("a missing token: %v", err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := revoke(vwr, opToken.GetId()); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer revokes: %v", err)
	}
	if r, err := vwr.enr.ListEnrollmentTokens(ctx, connect.NewRequest(&rpmgrv1.ListEnrollmentTokensRequest{OrgId: org, ShowInactive: true})); err != nil ||
		len(r.Msg.GetEnrollmentTokens()) != 2 {
		t.Fatalf("a Viewer lists: %v %v", r, err)
	}
}

// TestGetInstallCommand: the command names the controller and the pin, never a token; a gateway's
// gets --role gateway and no targets; each target is checked as the local policy reads it and
// quoted, so that a shell gives back exactly the arguments; anything else is refused.
func TestGetInstallCommand(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	get := func(b *browser, role rpmgrv1.AgentRole, targets ...string) (*rpmgrv1.GetInstallCommandResponse, error) {
		r, err := b.enr.GetInstallCommand(ctx, connect.NewRequest(&rpmgrv1.GetInstallCommandRequest{OrgId: org, Role: role, AllowTargets: targets}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	plain, err := get(ada, rpmgrv1.AgentRole_AGENT_ROLE_UNSPECIFIED)
	want := "curl -fsSL 'https://panel.example.com/install.sh' | sudo sh -s -- \\\n" +
		"  --controller 'https://panel.example.com' --ca-pin 'sha256:3q2+7w=='"
	if err != nil || plain.GetCommand() != want || plain.GetControllerUrl() != "https://panel.example.com" || plain.GetCaPin() != "sha256:3q2+7w==" {
		t.Fatalf("a connector's command:\n%s\n%v", plain.GetCommand(), err)
	}
	gw, err := get(ada, rpmgrv1.AgentRole_AGENT_ROLE_GATEWAY)
	if err != nil || !strings.HasSuffix(gw.GetCommand(), " \\\n  --role gateway") {
		t.Fatalf("a gateway's command:\n%s\n%v", gw.GetCommand(), err)
	}

	targets := []string{"10.0.0.5:5432", "[2001:db8::5]:443", "/run/postgresql/.s.PGSQL.5432", "/run/a b/$HOME*.sock"}
	withTargets, err := get(ada, rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR, targets...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withTargets.GetCommand(), "rpmgr_enr_") {
		t.Fatal("the command holds a token")
	}
	// What the installer would get as its arguments, as a shell parses them.
	_, args, _ := strings.Cut(withTargets.GetCommand(), "sudo sh -s --")
	out, err := exec.Command("/bin/sh", "-c", `printf '%s\n'`+args).Output()
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"--controller", "https://panel.example.com", "--ca-pin", "sha256:3q2+7w=="}
	for _, tg := range targets {
		wantArgs = append(wantArgs, "--allow-target", tg)
	}
	if got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n"); !slices.Equal(got, wantArgs) {
		t.Fatalf("the shell parses %q, want %q", got, wantArgs)
	}

	for name, tg := range map[string]string{
		"no port": "10.0.0.5", "a name": "db.example.com:5432", "port 0": "10.0.0.5:0", "port 65536": "10.0.0.5:65536",
		"a relative path": "run/x.sock", "an unclean path": "/run/../x.sock", "a quote": "/run/a'b.sock",
		"a line break": "/run/a\nb.sock", "a zone": "[fe80::1%eth0]:22",
	} {
		if _, err := get(ada, rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR, tg); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := get(ada, rpmgrv1.AgentRole_AGENT_ROLE_GATEWAY, "10.0.0.5:5432"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a gateway with targets: %v", err)
	}
	if _, err := get(ada, rpmgrv1.AgentRole(9)); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("an undefined role: %v", err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := get(vwr, rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR); err != nil {
		t.Fatalf("a Viewer: %v", err)
	}
}

// TestShellQuote: a shell reads back exactly what was quoted, quotes, spaces, globs, variables and
// command substitutions included.
func TestShellQuote(t *testing.T) {
	for _, s := range []string{"", "plain", "it's", "''", "a b", "$HOME", "`id`", "$(id)", "*", "back\\slash", "a'b'c", "\"double\""} {
		out, err := exec.Command("/bin/sh", "-c", "printf '%s' "+apisvc.ShellQuote(s)).Output()
		if err != nil || string(out) != s {
			t.Errorf("%q came back as %q: %v", s, out, err)
		}
	}
}
