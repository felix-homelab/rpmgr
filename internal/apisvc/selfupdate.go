// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// ReasonControllerUpdate is the reason of an update of the controller that cannot be started
// (docs/07-api.md, "Errors"); the message says why.
const ReasonControllerUpdate = "CONTROLLER_UPDATE_REFUSED"

// stagedWait is how long a staged release counts as under way while the root updater has
// reported nothing: the path unit starts it at once, so a longer wait means it did not start.
const stagedWait = 2 * time.Minute

// updatingStale is how long a status of `updating` stays believed without the root updater writing
// again: it writes at each step, so an older one is from an updater that died, as with a crash or
// a reboot, and the next run at boot resolves it. A restart of the controller loses what it staged,
// so without this a dead update would show as under way for good.
const updatingStale = 30 * time.Minute

// SelfUpdate connects ReleaseService to the controller's host (D158). The controller stages a
// release for the root updater, which backs the database up, installs it and restarts the
// controller; it never installs anything itself.
type SelfUpdate struct {
	// Stage copies the mirror's release into the directory the root updater watches, the manifest
	// last (agent.StageRelease).
	Stage func(ctx context.Context, version string) error
	// Blocked returns why this host cannot update the controller over the air, such as a missing
	// root updater or a PostgreSQL database, or "".
	Blocked func() string
	// Status reads the root updater's status file; nil is update.ReadStatus of update.StatusFile.
	Status func() (update.Status, error)

	mu     sync.Mutex
	staged string    // the version staged by the last request
	at     time.Time // when
}

// UpdateController implements ReleaseService: it checks the target, stages it and returns the
// state. Step-up and audit are those of the API.
func (r *Releases) UpdateController(ctx context.Context, req *connect.Request[rpmgrv1.UpdateControllerRequest]) (
	*connect.Response[rpmgrv1.UpdateControllerResponse], error) {
	u := r.Self
	if u == nil || u.Stage == nil {
		return nil, refusedUpdate("this controller has no root updater")
	}
	if !update.HasSelfUpdate(r.Version) {
		// Its backup and restore are those of the running release, which must have them.
		return nil, refusedUpdate(update.ByHand)
	}
	if why := u.blocked(); why != "" {
		return nil, refusedUpdate(why)
	}
	sys, c := store.CarryTxHook(r.Sys, ctx), r.DB.ReadClient()
	rel, err := c.Release.Get(sys, req.Msg.GetReleaseId())
	if ent.IsNotFound(err) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("apisvc: no such release"))
	}
	if err != nil {
		return nil, err
	}
	switch {
	case !release.Releasable(r.Version):
		return nil, refusedUpdate("a development build of the controller is not updated over the air")
	case compareVersions(rel.Version, r.Version) <= 0:
		return nil, refusedUpdate(fmt.Sprintf("release %s is not newer than the controller's %s; the controller is never downgraded, "+
			"as its database may be migrated", rel.Version, r.Version))
	case rel.MirroredAt == nil:
		return nil, refusedUpdate(fmt.Sprintf("the mirror does not hold release %s yet", rel.Version))
	}
	if err := checkChannel(sys, c, rel); err != nil {
		return nil, err
	}
	if n, err := c.Rollout.Query().Where(rollout.Active(true)).Count(sys); err != nil || n > 0 {
		return nil, errors.Join(err, errIf(n > 0, rolloutActive()))
	}
	// One update at a time: while the staged release or the updater is under way, nothing new is
	// staged over it.
	if cur := u.current(r.now()); cur != nil && (cur.State == rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED ||
		cur.State == rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATING) {
		return nil, refusedUpdate(fmt.Sprintf("the update to %s is under way", cur.Version))
	}
	if err := u.Stage(ctx, rel.Version); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("apisvc: staging %s: %w", rel.Version, err))
	}
	u.mu.Lock()
	u.staged, u.at = rel.Version, r.now()
	u.mu.Unlock()
	return connect.NewResponse(&rpmgrv1.UpdateControllerResponse{Update: u.current(r.now())}), nil
}

// GetControllerUpdate implements ReleaseService.
func (r *Releases) GetControllerUpdate(context.Context, *connect.Request[rpmgrv1.GetControllerUpdateRequest]) (
	*connect.Response[rpmgrv1.GetControllerUpdateResponse], error) {
	out := &rpmgrv1.GetControllerUpdateResponse{RunningVersion: r.Version}
	if u := r.Self; u != nil && u.Stage != nil {
		out.Blocked = u.blocked()
		out.Update = u.current(r.now())
		if out.ByHand = !update.HasSelfUpdate(r.Version); out.ByHand {
			out.Blocked = update.ByHand
		}
	} else {
		out.Blocked = "this controller has no root updater"
	}
	return connect.NewResponse(out), nil
}

func (u *SelfUpdate) blocked() string {
	if u.Blocked == nil {
		return ""
	}
	return u.Blocked()
}

// current is the update the root updater's status file and the last request tell of: the
// updater's report once it is about the staged release, else the staged release, else the
// updater's last report, else nothing.
func (u *SelfUpdate) current(now time.Time) *rpmgrv1.ControllerUpdate {
	u.mu.Lock()
	staged, at := u.staged, u.at
	u.mu.Unlock()
	read := u.Status
	if read == nil {
		read = func() (update.Status, error) { return update.ReadStatus(update.StatusFile) }
	}
	st, err := read()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return &rpmgrv1.ControllerUpdate{Version: staged, State: rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATING,
			Reason: "the updater's status cannot be read: " + err.Error()}
	}
	if err == nil && st.State == update.Updating && now.Sub(st.At) > updatingStale {
		st = update.Status{} // an updater that stopped writing: no update is under way
	}
	state, known := map[string]rpmgrv1.ControllerUpdateState{update.Updating: rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATING,
		update.Updated:        rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATED,
		update.RolledBack:     rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_ROLLED_BACK,
		update.RollbackFailed: rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_ROLLBACK_FAILED,
		update.Refused:        rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_REFUSED}[st.State]
	// The status counts only when it is newer than the request: an earlier outcome is history.
	if err == nil && known && (staged == "" || (st.Version == staged && !st.At.Before(at))) {
		return &rpmgrv1.ControllerUpdate{Version: st.Version, State: state, Step: st.Step, Reason: st.Reason, Previous: st.Previous,
			UpdateTime: timestamppb.New(st.At)}
	}
	if staged == "" {
		return nil
	}
	if now.Sub(at) > stagedWait {
		return &rpmgrv1.ControllerUpdate{Version: staged, State: rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_REFUSED,
			Reason: "the root updater did not start within " + stagedWait.String() + "; see systemctl status rpmgr-update", UpdateTime: timestamppb.New(at)}
	}
	return &rpmgrv1.ControllerUpdate{Version: staged, State: rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED, UpdateTime: timestamppb.New(at)}
}

func refusedUpdate(why string) error {
	return withReason(connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: "+why)), ReasonControllerUpdate)
}
