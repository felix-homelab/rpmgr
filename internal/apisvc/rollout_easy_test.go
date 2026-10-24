// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
)

// easyFleet is the agents of the easy rollout tests: connectors and a gateway that take updates
// over the air, and agents an easy rollout refuses.
type easyFleet struct {
	con1, con2, gw, noOTA, never, builtIn, gone string
}

func newEasyFleet(t *testing.T, c *ent.Client, sys context.Context, org, group string, now time.Time) easyFleet {
	t.Helper()
	con := func(name string) *ent.ConnectorCreate {
		return c.Connector.Create().SetOrgID(org).SetName(name).SetSpiffeID("spiffe://t/" + name).SetPubkeySha256(name)
	}
	session := func(id string, caps ...string) {
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetAgentVersion("1.4.2").
			SetCapabilities(caps).SetLastSeenAt(now).SaveX(sys)
	}
	f := easyFleet{
		con1:    con("nas").SaveX(sys).ID,
		con2:    con("pi").SaveX(sys).ID,
		noOTA:   con("container").SaveX(sys).ID,
		never:   con("new").SaveX(sys).ID,
		builtIn: con("own").SetBuiltIn(true).SaveX(sys).ID,
		gone:    con("gone").SetDecommissionedAt(now).SaveX(sys).ID,
		gw: c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group).SetName("gw1").SetSlot(1).
			SetTunnelEndpoints([]string{"gw1.example:443"}).SetSpiffeID("spiffe://t/gw1").SaveX(sys).ID,
	}
	for _, id := range []string{f.con1, f.con2, f.gw, f.builtIn} {
		session(id, agentproto.CapOTA)
	}
	session(f.noOTA)
	return f
}

// TestEasyRollouts (docs/04-security.md, "Easy rollouts"; D129): an easy rollout takes its queue
// in order and only agents that update over the air; Update on agents starts an easy rollout of
// the controller's own version or joins the running or paused one, keeping an agent's place; it
// is refused while a staged rollout or a rollout of another release runs; an easy rollout has no
// stages; each call takes a step-up and is audited; an org Admin may do none of it.
func TestEasyRollouts(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	sys := e.sys
	c := e.db.Client()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	rels := map[string]string{}
	for _, v := range []string{"1.4.2", "1.5.0"} {
		resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, v, 10, release.Stable)))
		if err != nil {
			t.Fatal(err)
		}
		rels[v] = resp.Msg.GetRelease().GetId()
	}
	c.Release.Update().SetMirroredAt(e.clock).ExecX(sys)
	f := newEasyFleet(t, c, sys, org, group, e.clock)

	create := func(req *rpmgrv1.CreateRolloutRequest) (*rpmgrv1.Rollout, error) {
		resp, err := ada.rel.CreateRollout(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetRollout(), nil
	}
	easy := rpmgrv1.RolloutMode_ROLLOUT_MODE_EASY
	upgrade := func(b *browser, agents ...string) (*rpmgrv1.UpgradeAgentsResponse, error) {
		resp, err := b.rel.UpgradeAgents(ctx, connect.NewRequest(&rpmgrv1.UpgradeAgentsRequest{AgentIds: agents}))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	// What a request must hold for each kind of rollout.
	for name, req := range map[string]*rpmgrv1.CreateRolloutRequest{
		"easy without agents":      {ReleaseId: rels["1.4.2"], Mode: easy},
		"easy with a canary":       {ReleaseId: rels["1.4.2"], Mode: easy, AgentIds: []string{f.con1}, CanaryAgentIds: []string{f.con2}},
		"staged without a canary":  {ReleaseId: rels["1.4.2"]},
		"staged with a queue":      {ReleaseId: rels["1.4.2"], CanaryAgentIds: []string{f.con1}, AgentIds: []string{f.con2}},
		"advanced without a canar": {ReleaseId: rels["1.4.2"], Mode: rpmgrv1.RolloutMode_ROLLOUT_MODE_ADVANCED},
		"an undefined mode":        {ReleaseId: rels["1.4.2"], Mode: rpmgrv1.RolloutMode(7), AgentIds: []string{f.con1}},
		"an agent twice":           {ReleaseId: rels["1.4.2"], Mode: easy, AgentIds: []string{f.con1, f.con1}},
	} {
		if _, err := create(req); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Agents an easy rollout cannot update, whether queued at its creation or by Update.
	for name, id := range map[string]string{"without ota": f.noOTA, "never connected": f.never, "built in": f.builtIn,
		"decommissioned": f.gone, "unknown": "con_nosuchagent"} {
		if _, err := create(&rpmgrv1.CreateRolloutRequest{ReleaseId: rels["1.4.2"], Mode: easy, AgentIds: []string{f.con1, id}}); code(err) !=
			connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonNotUpgradable {
			t.Errorf("an easy rollout with an agent %s: %v", name, err)
		}
		if _, err := upgrade(ada, id); reason(err) != apisvc.ReasonNotUpgradable {
			t.Errorf("Update on an agent %s: %v", name, err)
		}
	}
	if n := c.Rollout.Query().CountX(sys); n != 0 {
		t.Fatalf("refused requests left %d rollouts", n)
	}

	// Update with no rollout running starts an easy rollout of the controller's own version.
	got, err := upgrade(ada, f.con2, f.gw)
	if err != nil {
		t.Fatal(err)
	}
	ro := got.GetRollout()
	if ro.GetMode() != easy || ro.GetVersion() != "1.5.0" || ro.GetState() != rpmgrv1.RolloutState_ROLLOUT_STATE_RUNNING ||
		ro.GetCounts().GetPending() != 2 || ro.GetCreateUserId() != e.ada {
		t.Fatalf("the rollout Update started: %v", ro)
	}
	if ts := got.GetRolloutTargets(); len(ts) != 2 || ts[0].GetAgentId() != f.con2 || ts[0].GetPosition() != 1 || ts[0].GetAgentName() != "pi" ||
		ts[1].GetAgentId() != f.gw || ts[1].GetPosition() != 2 || ts[1].GetAgentKind() != rpmgrv1.AgentKind_AGENT_KIND_GATEWAY ||
		ts[0].GetVersionBefore() != "1.4.2" {
		t.Errorf("the queue Update started: %v", ts)
	}
	// Joining: a new agent goes to the end, a queued one keeps its place; a paused rollout takes
	// agents too.
	if _, err := ada.rel.PauseRollout(ctx, connect.NewRequest(&rpmgrv1.PauseRolloutRequest{RolloutId: ro.GetId()})); err != nil {
		t.Fatal(err)
	}
	got, err = upgrade(ada, f.con1, f.con2)
	if err != nil {
		t.Fatal(err)
	}
	if ts := got.GetRolloutTargets(); got.GetRollout().GetId() != ro.GetId() || len(ts) != 2 || ts[0].GetPosition() != 3 || ts[1].GetPosition() != 1 {
		t.Errorf("joining the paused rollout: %v", got)
	}
	list, err := ada.rel.ListRolloutTargets(ctx, connect.NewRequest(&rpmgrv1.ListRolloutTargetsRequest{RolloutId: ro.GetId()}))
	if err != nil || len(list.Msg.GetRolloutTargets()) != 3 {
		t.Fatalf("the queue: %v %v", list, err)
	}
	for _, x := range list.Msg.GetRolloutTargets() {
		if want := map[string]int32{f.con2: 1, f.gw: 2, f.con1: 3}[x.GetAgentId()]; x.GetPosition() != want || x.GetCanary() {
			t.Errorf("%s at position %d, want %d", x.GetAgentName(), x.GetPosition(), want)
		}
	}
	if _, err := ada.rel.ResumeRollout(ctx, connect.NewRequest(&rpmgrv1.ResumeRolloutRequest{RolloutId: ro.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rel.AdvanceRollout(ctx, connect.NewRequest(&rpmgrv1.AdvanceRolloutRequest{RolloutId: ro.GetId(),
		Next: &rpmgrv1.AdvanceRolloutRequest_All{All: true}})); reason(err) != apisvc.ReasonRolloutMode {
		t.Errorf("an easy rollout advanced: %v", err)
	}
	if _, err := create(&rpmgrv1.CreateRolloutRequest{ReleaseId: rels["1.5.0"], Mode: easy, AgentIds: []string{f.con1}}); reason(err) != apisvc.ReasonRolloutActive {
		t.Errorf("a second rollout beside the easy one: %v", err)
	}
	cancel := func(id string) {
		t.Helper()
		if _, err := ada.rel.CancelRollout(ctx, connect.NewRequest(&rpmgrv1.CancelRolloutRequest{RolloutId: id})); err != nil {
			t.Fatal(err)
		}
	}
	cancel(ro.GetId())

	// An easy rollout of an older release, created with its queue in order: Update does not join it.
	older, err := create(&rpmgrv1.CreateRolloutRequest{ReleaseId: rels["1.4.2"], Mode: easy, AgentIds: []string{f.gw, f.con1}})
	if err != nil || older.GetMode() != easy || older.GetCounts().GetPending() != 2 || older.GetStage() != rpmgrv1.RolloutStage_ROLLOUT_STAGE_CANARY {
		t.Fatalf("an easy rollout of 1.4.2: %v %v", older, err)
	}
	if _, err := upgrade(ada, f.con2); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonRolloutActive {
		t.Errorf("Update while an easy rollout of another release runs: %v", err)
	}
	cancel(older.GetId())

	// A staged rollout: Update is refused, and the staged rollout keeps no queue.
	staged, err := create(&rpmgrv1.CreateRolloutRequest{ReleaseId: rels["1.5.0"], CanaryAgentIds: []string{f.con1}})
	if err != nil || staged.GetMode() != rpmgrv1.RolloutMode_ROLLOUT_MODE_ADVANCED {
		t.Fatalf("a staged rollout: %v %v", staged, err)
	}
	if _, err := upgrade(ada, f.con2); reason(err) != apisvc.ReasonRolloutActive {
		t.Errorf("Update while a staged rollout runs: %v", err)
	}
	if n := c.Rollout.Query().Where(rollout.ModeEQ(rollout.ModeEasy)).CountX(sys); n != 2 {
		t.Errorf("%d easy rollouts, want 2", n)
	}
	cancel(staged.GetId())

	// Update takes a step-up, and an org Admin may not use it.
	e.clock = e.clock.Add(api.StepUpWindow + time.Minute)
	if _, err := upgrade(ada, f.con2); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("Update without a step-up: %v", err)
	}
	h, err := password.Hash(ctx, pw, password.LowMemory)
	if err != nil {
		t.Fatal(err)
	}
	carol := c.User.Create().SetEmail("carol@example.com").SetDisplayName("Carol").SetPasswordHash(h).SaveX(sys)
	c.Membership.Create().SetOrgID(org).SetUserID(carol.ID).SetRole("admin").SetCreatedBy("test").ExecX(sys)
	admin := e.browser()
	if err := admin.login("carol@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := admin.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := upgrade(admin, f.con2); code(err) != connect.CodePermissionDenied {
		t.Errorf("an org Admin's Update: %v", err)
	}
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.ReleaseService.UpgradeAgents"),
		auditentry.ResultEQ(auditentry.ResultSuccess)).CountX(sys); n != 2 {
		t.Errorf("%d audit entries of a successful UpgradeAgents, want 2", n)
	}
}

// TestUpgradeAgents_ControllerRelease: Update targets the controller's own release, so it is
// refused while that release is not recorded, from a development build, and while the release is
// a pre-release on a stable instance; a release the mirror does not hold yet starts a mirror check.
func TestUpgradeAgents_ControllerRelease(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	var asked int
	e.rel.MirrorNow = func() { asked++ }
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	f := newEasyFleet(t, e.db.Client(), e.sys, org, group, e.clock)
	upgrade := func() error {
		_, err := ada.rel.UpgradeAgents(ctx, connect.NewRequest(&rpmgrv1.UpgradeAgentsRequest{AgentIds: []string{f.con1}}))
		return err
	}
	if err := upgrade(); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("Update while the controller's release is not recorded: %v", err)
	}
	e.rel.Version = "1.5.0-rc.1"
	if _, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, "1.5.0-rc.1", 10, release.Prerelease))); err != nil {
		t.Fatal(err)
	}
	if err := upgrade(); reason(err) != apisvc.ReasonReleaseChannel {
		t.Errorf("Update to a pre-release on a stable instance: %v", err)
	}
	pre := rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{UpdateChannel: &pre},
		&fieldmaskpb.FieldMask{Paths: []string{"update_channel"}}, 0); err != nil {
		t.Fatal(err)
	}
	checks := asked
	if err := upgrade(); err != nil {
		t.Errorf("Update to the controller's pre-release on the pre-release channel: %v", err)
	}
	if asked != checks+1 {
		t.Error("Update of a release the mirror does not hold asked for no mirror check")
	}
	e.rel.Version = "dev"
	if err := upgrade(); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("Update from a development build: %v", err)
	}
}
