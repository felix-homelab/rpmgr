// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	entrelease "github.com/felix-homelab/rpmgr/internal/store/ent/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestRollouts (docs/04-security.md, "Over-the-air updates"; D121): a rollout is refused for a
// release the mirror does not hold or one newer than the controller, and for canary agents it
// cannot update; it targets every connector and enrolled gateway that is neither decommissioned
// nor built in, with the version each ran; one rollout runs at a time; it advances only upwards
// and only while running, under its etag; a pause needs no step-up, resuming does; a cancelled
// rollout makes room for the next; each change is audited; an org Owner sees and does nothing.
func TestRollouts(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	sys := e.sys
	c := e.db.Client()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	var old *rpmgrv1.Release
	for _, v := range []string{"1.4.2", "1.6.0"} {
		resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, v, 10, release.Stable)))
		if err != nil {
			t.Fatal(err)
		}
		if v == "1.4.2" {
			old = resp.Msg.GetRelease()
		}
	}

	// The fleet: what a rollout updates and what it leaves out.
	con1 := c.Connector.Create().SetOrgID(org).SetName("nas").SetSpiffeID("spiffe://t/con1").SetPubkeySha256("a").SaveX(sys)
	con2 := c.Connector.Create().SetOrgID(org).SetName("pi").SetSpiffeID("spiffe://t/con2").SetPubkeySha256("b").SaveX(sys)
	gone := c.Connector.Create().SetOrgID(org).SetName("gone").SetSpiffeID("spiffe://t/con3").SetPubkeySha256("c").
		SetDecommissionedAt(e.clock).SaveX(sys)
	builtIn := c.Connector.Create().SetOrgID(org).SetName("own").SetSpiffeID("spiffe://t/con4").SetPubkeySha256("d").SetBuiltIn(true).SaveX(sys)
	gw := c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group).SetName("gw1").SetSlot(1).SetTunnelEndpoints([]string{"gw1.example:443"}).
		SetSpiffeID("spiffe://t/gw1").SaveX(sys)
	fresh := c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group).SetName("gw2").SetSlot(2).SetTunnelEndpoints([]string{"gw2.example:443"}).
		SaveX(sys)
	c.AgentSession.Create().SetID(con1.ID).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetAgentVersion("1.4.2").SaveX(sys)

	create := func(b *browser, rel string, canary ...string) (*rpmgrv1.Rollout, error) {
		resp, err := b.rel.CreateRollout(ctx, connect.NewRequest(&rpmgrv1.CreateRolloutRequest{ReleaseId: rel, CanaryAgentIds: canary}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetRollout(), nil
	}
	if _, err := create(ada, old.GetId(), con1.ID); reason(err) != apisvc.ReasonReleaseNotMirrored {
		t.Errorf("a release the mirror does not hold: %v", err)
	}
	c.Release.Update().SetMirroredAt(e.clock).ExecX(sys)
	newer := c.Release.Query().Where(entrelease.Version("1.6.0")).OnlyX(sys)
	if _, err := create(ada, newer.ID, con1.ID); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonReleaseNewer {
		t.Errorf("a release newer than the controller: %v", err)
	}
	for _, canary := range []string{gone.ID, builtIn.ID, fresh.ID, "con_nosuchagent"} {
		if _, err := create(ada, old.GetId(), canary); code(err) != connect.CodeInvalidArgument {
			t.Errorf("canary %s: %v", canary, err)
		}
	}
	if _, err := create(ada, "rel_nosuchrelease", con1.ID); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown release: %v", err)
	}
	ro, err := create(ada, old.GetId(), con1.ID)
	if err != nil || ro.GetVersion() != "1.4.2" || ro.GetStage() != rpmgrv1.RolloutStage_ROLLOUT_STAGE_CANARY || ro.GetPercentage() != 0 ||
		ro.GetState() != rpmgrv1.RolloutState_ROLLOUT_STATE_RUNNING || ro.GetCounts().GetPending() != 3 || ro.GetCreateUserId() != e.ada {
		t.Fatalf("a rollout: %v %v", ro, err)
	}
	if _, err := create(ada, old.GetId(), con2.ID); reason(err) != apisvc.ReasonRolloutActive {
		t.Errorf("a second rollout: %v", err)
	}

	targets := map[string]*rpmgrv1.RolloutTarget{}
	for page := ""; ; {
		resp, err := ada.rel.ListRolloutTargets(ctx, connect.NewRequest(&rpmgrv1.ListRolloutTargetsRequest{RolloutId: ro.GetId(),
			PageSize: 2, PageToken: page}))
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range resp.Msg.GetRolloutTargets() {
			targets[x.GetAgentId()] = x
		}
		if page = resp.Msg.GetNextPageToken(); page == "" {
			break
		}
	}
	if len(targets) != 3 || targets[gone.ID] != nil || targets[builtIn.ID] != nil || targets[fresh.ID] != nil {
		t.Fatalf("the targets: %v", targets)
	}
	if x := targets[con1.ID]; !x.GetCanary() || x.GetVersionBefore() != "1.4.2" || x.GetAgentName() != "nas" || x.GetOrgId() != org ||
		x.GetAgentKind() != rpmgrv1.AgentKind_AGENT_KIND_CONNECTOR || x.GetBucket() != int32(store.RolloutBucket(con1.ID)) || //nolint:gosec // G115: 0 to 99
		x.GetState() != rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_PENDING {
		t.Errorf("the canary: %v", x)
	}
	if x := targets[gw.ID]; x.GetCanary() || x.GetAgentKind() != rpmgrv1.AgentKind_AGENT_KIND_GATEWAY || x.GetAgentName() != "gw1" || x.GetVersionBefore() != "" {
		t.Errorf("the gateway: %v", x)
	}
	if resp, err := ada.rel.ListRolloutTargets(ctx, connect.NewRequest(&rpmgrv1.ListRolloutTargetsRequest{RolloutId: ro.GetId(),
		States: []rpmgrv1.RolloutTargetState{rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_UPDATED}})); err != nil || len(resp.Msg.GetRolloutTargets()) != 0 {
		t.Errorf("the updated targets: %v %v", resp, err)
	}
	if _, err := ada.rel.ListRolloutTargets(ctx, connect.NewRequest(&rpmgrv1.ListRolloutTargetsRequest{RolloutId: "rol_nosuchrollout"})); code(err) != connect.CodeNotFound {
		t.Errorf("the targets of an unknown rollout: %v", err)
	}

	advance := func(etag string, pct int32, all bool) (*rpmgrv1.Rollout, error) {
		req := &rpmgrv1.AdvanceRolloutRequest{RolloutId: ro.GetId(), Etag: etag}
		if all {
			req.Next = &rpmgrv1.AdvanceRolloutRequest_All{All: true}
		} else {
			req.Next = &rpmgrv1.AdvanceRolloutRequest_Percentage{Percentage: pct}
		}
		resp, err := ada.rel.AdvanceRollout(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetRollout(), nil
	}
	if _, err := advance("99", 25, false); reason(err) != api.ReasonEtagMismatch {
		t.Errorf("a stale etag: %v", err)
	}
	if _, err := advance(ro.GetEtag(), 100, false); code(err) != connect.CodeInvalidArgument {
		t.Errorf("100 %% as a percentage: %v", err)
	}
	ro, err = advance(ro.GetEtag(), 25, false)
	if err != nil || ro.GetStage() != rpmgrv1.RolloutStage_ROLLOUT_STAGE_PERCENTAGE || ro.GetPercentage() != 25 || ro.GetUpdateUserId() != e.ada {
		t.Fatalf("to 25 %%: %v %v", ro, err)
	}
	if _, err := advance("", 10, false); code(err) != connect.CodeInvalidArgument {
		t.Errorf("down to 10 %%: %v", err)
	}

	// A pause needs no step-up; everything else does.
	e.clock = e.clock.Add(api.StepUpWindow + time.Minute)
	paused, err := ada.rel.PauseRollout(ctx, connect.NewRequest(&rpmgrv1.PauseRolloutRequest{RolloutId: ro.GetId()}))
	if err != nil || paused.Msg.GetRollout().GetState() != rpmgrv1.RolloutState_ROLLOUT_STATE_PAUSED || paused.Msg.GetRollout().GetPauseReason() == "" {
		t.Fatalf("a pause: %v %v", paused, err)
	}
	if _, err := ada.rel.ResumeRollout(ctx, connect.NewRequest(&rpmgrv1.ResumeRolloutRequest{RolloutId: ro.GetId()})); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("a resume without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := advance("", 50, false); reason(err) != apisvc.ReasonRolloutState {
		t.Errorf("a paused rollout advanced: %v", err)
	}
	if _, err := ada.rel.PauseRollout(ctx, connect.NewRequest(&rpmgrv1.PauseRolloutRequest{RolloutId: ro.GetId()})); reason(err) != apisvc.ReasonRolloutState {
		t.Errorf("a paused rollout paused: %v", err)
	}
	resumed, err := ada.rel.ResumeRollout(ctx, connect.NewRequest(&rpmgrv1.ResumeRolloutRequest{RolloutId: ro.GetId()}))
	if err != nil || resumed.Msg.GetRollout().GetState() != rpmgrv1.RolloutState_ROLLOUT_STATE_RUNNING || resumed.Msg.GetRollout().GetPauseReason() != "" {
		t.Fatalf("a resume: %v %v", resumed, err)
	}
	ro, err = advance("", 0, true)
	if err != nil || ro.GetStage() != rpmgrv1.RolloutStage_ROLLOUT_STAGE_ALL || ro.GetPercentage() != 100 {
		t.Fatalf("to all: %v %v", ro, err)
	}
	if _, err := advance("", 0, true); reason(err) != apisvc.ReasonRolloutState {
		t.Errorf("beyond all: %v", err)
	}
	if got, err := ada.rel.ListRollouts(ctx, connect.NewRequest(&rpmgrv1.ListRolloutsRequest{ActiveOnly: true})); err != nil ||
		len(got.Msg.GetRollouts()) != 1 || got.Msg.GetRollouts()[0].GetId() != ro.GetId() {
		t.Errorf("the active rollouts: %v %v", got, err)
	}
	cancelled, err := ada.rel.CancelRollout(ctx, connect.NewRequest(&rpmgrv1.CancelRolloutRequest{RolloutId: ro.GetId(), Etag: ro.GetEtag()}))
	if err != nil || cancelled.Msg.GetRollout().GetState() != rpmgrv1.RolloutState_ROLLOUT_STATE_CANCELLED {
		t.Fatalf("a cancel: %v %v", cancelled, err)
	}
	if _, err := ada.rel.CancelRollout(ctx, connect.NewRequest(&rpmgrv1.CancelRolloutRequest{RolloutId: ro.GetId()})); reason(err) != apisvc.ReasonRolloutState {
		t.Errorf("a cancelled rollout cancelled: %v", err)
	}
	if got, err := ada.rel.ListRollouts(ctx, connect.NewRequest(&rpmgrv1.ListRolloutsRequest{ActiveOnly: true})); err != nil || len(got.Msg.GetRollouts()) != 0 {
		t.Errorf("the active rollouts after the cancel: %v %v", got, err)
	}
	next, err := create(ada, old.GetId(), gw.ID)
	if err != nil {
		t.Fatalf("a rollout after the cancel: %v", err)
	}
	if got, err := ada.rel.ListRollouts(ctx, connect.NewRequest(&rpmgrv1.ListRolloutsRequest{})); err != nil || len(got.Msg.GetRollouts()) != 2 ||
		got.Msg.GetRollouts()[0].GetId() != next.GetId() {
		t.Errorf("the rollouts, newest first: %v %v", got, err)
	}
	if got, err := ada.rel.GetRollout(ctx, connect.NewRequest(&rpmgrv1.GetRolloutRequest{RolloutId: ro.GetId()})); err != nil ||
		got.Msg.GetRollout().GetState() != rpmgrv1.RolloutState_ROLLOUT_STATE_CANCELLED || got.Msg.GetRollout().GetCounts().GetPending() != 3 {
		t.Errorf("the cancelled rollout: %v %v", got, err)
	}
	if _, err := ada.rel.GetRollout(ctx, connect.NewRequest(&rpmgrv1.GetRolloutRequest{RolloutId: "rol_nosuchrollout"})); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown rollout: %v", err)
	}
	if n := c.Rollout.Query().Where(rollout.Active(true)).CountX(sys); n != 1 {
		t.Errorf("%d active rollouts", n)
	}
	for action, want := range map[string]int{"CreateRollout": 2, "AdvanceRollout": 2, "PauseRollout": 1, "ResumeRollout": 1, "CancelRollout": 1} {
		if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.ReleaseService."+action), auditentry.ResultEQ(auditentry.ResultSuccess)).
			CountX(sys); n != want {
			t.Errorf("%d audit entries of a successful %s, want %d", n, action, want)
		}
	}

	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.rel.CreateRollout(ctx, connect.NewRequest(&rpmgrv1.CreateRolloutRequest{ReleaseId: old.GetId(),
		CanaryAgentIds: []string{con2.ID}})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner creates a rollout: %v", err)
	}
	if _, err := bob.rel.GetRollout(ctx, connect.NewRequest(&rpmgrv1.GetRolloutRequest{RolloutId: next.GetId()})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner reads a rollout: %v", err)
	}
	if _, err := bob.rel.PauseRollout(ctx, connect.NewRequest(&rpmgrv1.PauseRolloutRequest{RolloutId: next.GetId()})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner pauses: %v", err)
	}
}

// TestRollouts_DevelopmentController: a controller without a release version runs no rollout.
func TestRollouts_DevelopmentController(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	e.rel.Version = "dev"
	ctx := context.Background()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, "1.4.2", 1, release.Stable)))
	if err != nil {
		t.Fatal(err)
	}
	e.db.Client().Release.Update().SetMirroredAt(e.clock).ExecX(e.sys)
	con := e.db.Client().Connector.Create().SetOrgID(org).SetName("nas").SetSpiffeID("spiffe://t/con1").SetPubkeySha256("a").SaveX(e.sys)
	if _, err := ada.rel.CreateRollout(ctx, connect.NewRequest(&rpmgrv1.CreateRolloutRequest{ReleaseId: resp.Msg.GetRelease().GetId(),
		CanaryAgentIds: []string{con.ID}})); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonReleaseNewer {
		t.Errorf("a rollout from a development build: %v", err)
	}
}

// TestRollouts_VersionAndChannel (D121; docs/04-security.md, "Release signing"): no rollout installs
// a release below min_agent_version, whose agents the controller would refuse; a pre-release is
// rolled out only on an instance on the pre-release channel, and there only if it is no newer than
// the controller by semantic versioning.
func TestRollouts_VersionAndChannel(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for v, ch := range map[string]string{"1.3.9": release.Stable, "1.5.0-rc.1": release.Prerelease, "1.6.0-rc.1": release.Prerelease} {
		resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, v, 10, ch)))
		if err != nil {
			t.Fatal(v, err)
		}
		ids[v] = resp.Msg.GetRelease().GetId()
	}
	e.db.Client().Release.Update().SetMirroredAt(e.clock).ExecX(e.sys)
	con := e.db.Client().Connector.Create().SetOrgID(org).SetName("nas").SetSpiffeID("spiffe://t/con1").SetPubkeySha256("a").SaveX(e.sys)
	create := func(v string) error {
		_, err := ada.rel.CreateRollout(ctx, connect.NewRequest(&rpmgrv1.CreateRolloutRequest{ReleaseId: ids[v], CanaryAgentIds: []string{con.ID}}))
		return err
	}
	if err := create("1.3.9"); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonReleaseBelowMin {
		t.Errorf("a release below min_agent_version: %v", err)
	}
	if err := create("1.5.0-rc.1"); reason(err) != apisvc.ReasonReleaseChannel {
		t.Errorf("a pre-release on the stable channel: %v", err)
	}
	pre := rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{UpdateChannel: &pre},
		&fieldmaskpb.FieldMask{Paths: []string{"update_channel"}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := create("1.6.0-rc.1"); reason(err) != apisvc.ReasonReleaseNewer {
		t.Errorf("a pre-release of a newer version: %v", err)
	}
	if err := create("1.5.0-rc.1"); err != nil {
		t.Errorf("a pre-release of the controller's version on the pre-release channel: %v", err)
	}
}
