// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// TestUpdateController (docs/04-security.md, "Controllers and all-in-ones over the air"; D158): the
// Instance Admin, after a step-up, has the controller stage a release for the root updater; the
// target must be newer than the controller, held by the mirror and taken by the channel; nothing
// is staged over an update under way, while a rollout runs, on a host that cannot take it, or by
// anyone else; the state follows the updater's status file; the request is audited.
func TestUpdateController(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t) // the controller runs 1.5.0
	ctx := context.Background()
	var staged []string
	var status update.Status
	statusErr := fs.ErrNotExist
	blocked := ""
	e.rel.Self = &apisvc.SelfUpdate{
		Blocked: func() string { return blocked },
		Stage:   func(_ context.Context, v string) error { staged = append(staged, v); return nil },
		Status:  func() (update.Status, error) { return status, statusErr },
	}
	up := func(b *browser, id string) (*rpmgrv1.ControllerUpdate, error) {
		resp, err := b.rel.UpdateController(ctx, connect.NewRequest(&rpmgrv1.UpdateControllerRequest{ReleaseId: id}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetUpdate(), nil
	}
	upload := func(v string, channel string) string {
		resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, v, 10, channel)))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.GetRelease().GetId()
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	newer, same, older, pre := upload("1.6.0", release.Stable), upload("1.5.0", release.Stable), upload("1.4.2", release.Stable),
		upload("1.7.0-rc.1", release.Prerelease)
	mirrored := func(ids ...string) {
		for _, id := range ids {
			e.db.Client().Release.UpdateOneID(id).SetMirroredAt(e.clock).ExecX(e.sys)
		}
	}

	fresh := e.browser() // the same Instance Admin in a session that has not stepped up
	if err := fresh.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	mirrored(newer)
	if _, err := up(fresh, newer); reason(err) != api.ReasonStepUpRequired || len(staged) != 0 {
		t.Errorf("without a step-up: %v", err)
	}
	for name, tc := range map[string]struct {
		id, reason string
	}{
		"a release the mirror does not hold":  {newer, apisvc.ReasonControllerUpdate},
		"the controller's own version":        {same, apisvc.ReasonControllerUpdate},
		"an older release, a downgrade":       {older, apisvc.ReasonControllerUpdate},
		"a pre-release on the stable channel": {pre, apisvc.ReasonReleaseChannel},
	} {
		mirrored(newer, same, older, pre)
		if name == "a release the mirror does not hold" {
			e.db.Client().Release.UpdateOneID(newer).ClearMirroredAt().ExecX(e.sys)
		}
		if _, err := up(ada, tc.id); code(err) != connect.CodeFailedPrecondition || reason(err) != tc.reason {
			t.Errorf("%s: %v", name, err)
		}
	}
	mirrored(newer)
	if _, err := up(ada, "rel_nosuchrelease"); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown release: %v", err)
	}
	if len(staged) != 0 {
		t.Fatalf("staged %v after refusals", staged)
	}

	// A host that cannot take it, and a stage that fails.
	blocked = "the controller runs on postgres (P2-M08)"
	if _, err := up(ada, newer); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonControllerUpdate {
		t.Errorf("a blocked host: %v", err)
	}
	if got, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{})); err != nil ||
		got.Msg.GetBlocked() != blocked || got.Msg.GetRunningVersion() != "1.5.0" {
		t.Errorf("GetControllerUpdate of a blocked host: %v, %v", got, err)
	}
	blocked = ""

	// A rollout in the way.
	c := e.db.Client()
	rel := c.Release.GetX(e.sys, same)
	ro := c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy(e.ada).SaveX(e.sys)
	if _, err := up(ada, newer); reason(err) != apisvc.ReasonRolloutActive {
		t.Errorf("while a rollout runs: %v", err)
	}
	c.Rollout.DeleteOne(ro).ExecX(e.sys)

	// The update: staged, then followed through the updater's status.
	got, err := up(ada, newer)
	if err != nil || len(staged) != 1 || staged[0] != "1.6.0" || got.GetVersion() != "1.6.0" ||
		got.GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED {
		t.Fatalf("UpdateController = %v, %v; staged %v", got, err, staged)
	}
	if _, err := up(ada, newer); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a second update while the first is staged: %v", err)
	}
	read := func() *rpmgrv1.ControllerUpdate {
		t.Helper()
		resp, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.GetUpdate()
	}
	// An outcome from before the request is history, not the update's.
	statusErr, status = nil, update.Status{State: update.RolledBack, Version: "1.6.0", Reason: "old", At: e.clock.Add(-time.Hour)}
	if u := read(); u.GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED {
		t.Errorf("an old outcome: %v", u)
	}
	for _, tc := range []struct {
		st    update.Status
		state rpmgrv1.ControllerUpdateState
	}{
		{update.Status{State: update.Updating, Step: update.StepBackingUp}, rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATING},
		{update.Status{State: update.Updated}, rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATED},
		{update.Status{State: update.RolledBack, Reason: "restored from /usr/local/bin/rpmgr.backup", Previous: "1.5.0"}, rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_ROLLED_BACK},
		{update.Status{State: update.RollbackFailed, Reason: "restore failed"}, rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_ROLLBACK_FAILED},
		{update.Status{State: update.Refused, Reason: "the backup failed"}, rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_REFUSED},
	} {
		tc.st.Version, tc.st.At = "1.6.0", e.clock.Add(time.Second)
		status = tc.st
		if u := read(); u.GetState() != tc.state || u.GetStep() != tc.st.Step || u.GetReason() != tc.st.Reason || u.GetPrevious() != tc.st.Previous {
			t.Errorf("status %+v read as %v", tc.st, u)
		}
	}
	// The status of an update that ended no longer blocks the next request.
	if _, err := up(ada, newer); err != nil || len(staged) != 2 {
		t.Errorf("an update after a refused one: %v, staged %v", err, staged)
	}

	// A stage that fails is an error, and nothing is recorded as under way.
	e.rel.Self.Stage = func(context.Context, string) error { return errors.New("no space left") }
	e.rel.Self = &apisvc.SelfUpdate{Stage: e.rel.Self.Stage, Status: func() (update.Status, error) { return update.Status{}, fs.ErrNotExist }}
	if _, err := up(ada, newer); code(err) != connect.CodeInternal {
		t.Errorf("a stage that fails: %v", err)
	}
	if u := read(); u != nil {
		t.Errorf("an update after a failed stage: %v", u)
	}

	// Nobody but an Instance Admin.
	bob, _ := e.addOwner(t, storetest.Org(t, e.db, "org-b"), "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := up(bob, newer); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner updates the controller: %v", err)
	}
	if _, err := bob.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner reads the update: %v", err)
	}
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.ReleaseService.UpdateController"), auditentry.ResultEQ(auditentry.ResultSuccess)).CountX(e.sys); n != 2 {
		t.Errorf("%d audit entries of successful updates; want 2", n)
	}
	_ = org
}

// A controller without the root updater refuses, and says so.
func TestUpdateController_NoUpdater(t *testing.T) {
	_, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rel.UpdateController(ctx, connect.NewRequest(&rpmgrv1.UpdateControllerRequest{ReleaseId: "rel_x"})); reason(err) != apisvc.ReasonControllerUpdate {
		t.Errorf("a controller without Self: %v", err)
	}
	resp, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{}))
	if err != nil || resp.Msg.GetBlocked() == "" || resp.Msg.GetUpdate() != nil {
		t.Errorf("GetControllerUpdate = %v, %v", resp, err)
	}
}

// A status of `updating` that the root updater stopped writing to, as after a crash, is no update
// under way, whereas a recent one is; a controller that restarted lost what it staged.
func TestGetControllerUpdate_StaleUpdating(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	var at time.Time
	e.rel.Self = &apisvc.SelfUpdate{Stage: func(context.Context, string) error { return nil },
		Status: func() (update.Status, error) {
			return update.Status{State: update.Updating, Step: update.StepHandingOver, Version: "1.6.0", At: at}, nil
		}}
	for name, tc := range map[string]struct {
		at   time.Time
		want rpmgrv1.ControllerUpdateState
	}{
		"written a minute ago": {e.clock.Add(-time.Minute), rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATING},
		"written an hour ago":  {e.clock.Add(-time.Hour), rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UNSPECIFIED},
	} {
		at = tc.at
		resp, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{}))
		if err != nil || resp.Msg.GetUpdate().GetState() != tc.want {
			t.Errorf("%s: %v, %v; want %v", name, resp, err, tc.want)
		}
	}
}

// A controller older than the first release that can update itself, v0.3.0, is updated by hand
// once: the API says so and stages nothing, whatever else is right.
func TestUpdateController_ByHand(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	staged := 0
	e.rel.Self = &apisvc.SelfUpdate{Stage: func(context.Context, string) error { staged++; return nil },
		Status: func() (update.Status, error) { return update.Status{}, fs.ErrNotExist }}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, "1.6.0", 10, release.Stable)))
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Msg.GetRelease().GetId()
	e.db.Client().Release.UpdateOneID(id).SetMirroredAt(e.clock).ExecX(e.sys)
	for _, running := range []string{"0.2.0", "0.2.9", "dev"} {
		e.rel.Version = running
		_, err := ada.rel.UpdateController(ctx, connect.NewRequest(&rpmgrv1.UpdateControllerRequest{ReleaseId: id}))
		if code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonControllerUpdate || !strings.Contains(err.Error(), update.ByHand) {
			t.Errorf("running %s: %v; want the by-hand refusal", running, err)
		}
		got, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{}))
		if err != nil || !got.Msg.GetByHand() || got.Msg.GetBlocked() != update.ByHand {
			t.Errorf("running %s: GetControllerUpdate = %v, %v", running, got, err)
		}
	}
	if staged != 0 {
		t.Errorf("staged %d times", staged)
	}
	e.rel.Version = "0.3.0-rc.1" // a pre-release of v0.3.0 has the feature
	if got, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{})); err != nil || got.Msg.GetByHand() {
		t.Errorf("running 0.3.0-rc.1: %v, %v", got, err)
	}
}

// TestUpdateController_HostPolicy (#1135): the controller reads the host's own policy, as the root
// updater trusts it, before it stages: a pre-release on a stable host and auto_update other than
// auto are refused with the command that fixes them, and the status says why, with the host's
// settings; a stable release on a stable host is staged; a policy that cannot be trusted refuses;
// one the controller may not read leaves the decision to the updater.
func TestUpdateController_HostPolicy(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t) // the controller runs 1.5.0
	ctx := context.Background()
	var staged []string
	pol := policy.Defaults()
	var polErr error
	e.rel.Self = &apisvc.SelfUpdate{
		Stage:  func(_ context.Context, v string) error { staged = append(staged, v); return nil },
		Status: func() (update.Status, error) { return update.Status{}, fs.ErrNotExist },
		Policy: func() (*policy.Policy, error) { return pol, polErr },
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	preChannel := rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{UpdateChannel: &preChannel},
		&fieldmaskpb.FieldMask{Paths: []string{"update_channel"}}, 0); err != nil {
		t.Fatal(err)
	}
	upload := func(v, channel string) string {
		resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, v, 10, channel)))
		if err != nil {
			t.Fatal(err)
		}
		id := resp.Msg.GetRelease().GetId()
		e.db.Client().Release.UpdateOneID(id).SetMirroredAt(e.clock).ExecX(e.sys)
		return id
	}
	stable, pre := upload("1.6.0", release.Stable), upload("1.7.0-rc.1", release.Prerelease)
	up := func(id string) error {
		_, err := ada.rel.UpdateController(ctx, connect.NewRequest(&rpmgrv1.UpdateControllerRequest{ReleaseId: id}))
		return err
	}
	read := func() *rpmgrv1.GetControllerUpdateResponse {
		t.Helper()
		resp, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg
	}
	refused := func(name, id, want string) {
		t.Helper()
		err := up(id)
		if code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonControllerUpdate || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want a refusal naming %q", name, err, want)
		}
		if len(staged) != 0 {
			t.Fatalf("%s: staged %v", name, staged)
		}
	}

	refused("a pre-release on a stable host", pre, "sudo rpmgr policy set-update-channel prerelease")
	if m := read(); m.GetHostUpdateChannel() != policy.ChannelStable || m.GetHostAutoUpdate() != policy.AutoUpdateAuto || m.GetBlocked() != "" {
		t.Errorf("status of a stable host: %v", m)
	}
	pol = &policy.Policy{AutoUpdate: policy.AutoUpdateOff, UpdateChannel: policy.ChannelPrerelease}
	refused("auto_update off", stable, "sudo rpmgr policy set-auto-update auto")
	if m := read(); !strings.Contains(m.GetBlocked(), "set-auto-update auto") || m.GetHostAutoUpdate() != policy.AutoUpdateOff {
		t.Errorf("status of a host with auto_update off: %v", m)
	}
	pol = &policy.Policy{AutoUpdate: policy.AutoUpdateNotify, UpdateChannel: policy.ChannelStable}
	refused("auto_update notify", stable, "auto_update: notify")
	pol, polErr = nil, errors.New("update: /etc/rpmgr/policy.yaml has mode 0666; only its owner may write it")
	refused("a policy others may write", stable, "has mode 0666")
	if m := read(); m.GetHostPolicyError() == "" || m.GetBlocked() == "" || m.GetHostUpdateChannel() != "" {
		t.Errorf("status of an untrusted policy: %v", m)
	}

	// The controller may not read the file: the updater decides, and now says why.
	polErr = fs.ErrPermission
	if m := read(); m.GetBlocked() != "" || m.GetHostPolicyError() != "" {
		t.Errorf("status of an unreadable policy: %v", m)
	}
	polErr = nil

	// A stable release on a stable host, and a pre-release on a host that takes them.
	pol = policy.Defaults()
	if err := up(stable); err != nil || len(staged) != 1 {
		t.Fatalf("a stable release on a stable host: %v; staged %v", err, staged)
	}
	e.rel.Self.Status = func() (update.Status, error) {
		return update.Status{State: update.Updated, Version: "1.6.0", At: e.clock.Add(time.Second)}, nil
	}
	pol = &policy.Policy{AutoUpdate: policy.AutoUpdateAuto, UpdateChannel: policy.ChannelPrerelease}
	if err := up(pre); err != nil || len(staged) != 2 {
		t.Errorf("a pre-release on a host that takes them: %v; staged %v", err, staged)
	}
}

// A refusal of the root updater before it has verified the manifest names no version; it counts as
// the staged release's when it is newer than the request. One from before the request does not.
func TestGetControllerUpdate_RefusalWithoutVersion(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	var status update.Status
	e.rel.Self = &apisvc.SelfUpdate{
		Stage:  func(context.Context, string) error { return nil },
		Status: func() (update.Status, error) { return status, nil },
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, "1.6.0", 10, release.Stable)))
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Msg.GetRelease().GetId()
	e.db.Client().Release.UpdateOneID(id).SetMirroredAt(e.clock).ExecX(e.sys)
	if _, err := ada.rel.UpdateController(ctx, connect.NewRequest(&rpmgrv1.UpdateControllerRequest{ReleaseId: id})); err != nil {
		t.Fatal(err)
	}
	read := func() *rpmgrv1.ControllerUpdate {
		got, err := ada.rel.GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return got.Msg.GetUpdate()
	}
	status = update.Status{State: update.Refused, Reason: "refused: manifest", At: e.clock.Add(-time.Hour)}
	if u := read(); u.GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED {
		t.Errorf("an old refusal: %v", u)
	}
	status.At = e.clock.Add(time.Second)
	if u := read(); u.GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_REFUSED || u.GetVersion() != "1.6.0" || u.GetReason() != "refused: manifest" {
		t.Errorf("a new refusal: %v", u)
	}
	status = update.Status{State: update.Updated, At: e.clock.Add(time.Second)} // no version, no refusal: not the update's
	if u := read(); u.GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED {
		t.Errorf("a status of no version that is no refusal: %v", u)
	}
	// No status at all within the wait: the message names where the reason is.
	status = update.Status{}
	e.clock = e.clock.Add(3 * time.Minute)
	if u := read(); u.GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_REFUSED ||
		!strings.Contains(u.GetReason(), "journalctl -u rpmgr-update.service") {
		t.Errorf("no status within the wait: %v", u)
	}
	// Both a refusal and a missing start are retried by pressing Update again, which stages the
	// release once more; the old outcome is history then.
	restaged := 0
	e.rel.Self.Stage = func(context.Context, string) error { restaged++; return nil }
	for _, why := range []string{"after no start", "after a refusal"} {
		resp, err := ada.rel.UpdateController(ctx, connect.NewRequest(&rpmgrv1.UpdateControllerRequest{ReleaseId: id}))
		if err != nil || resp.Msg.GetUpdate().GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED {
			t.Fatalf("the retry %s: %v, %v", why, resp, err)
		}
		status = update.Status{State: update.Refused, Reason: "refused: manifest", At: e.clock.Add(time.Second)}
		if u := read(); u.GetState() != rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_REFUSED {
			t.Errorf("the refusal of the retry %s: %v", why, u)
		}
		e.clock = e.clock.Add(time.Minute)
	}
	if restaged != 2 {
		t.Errorf("staged %d times by the retries; want 2", restaged)
	}
}
