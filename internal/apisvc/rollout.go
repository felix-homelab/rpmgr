// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	entrelease "github.com/felix-homelab/rpmgr/internal/store/ent/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// The reasons of a rollout refused or changed out of turn (docs/07-api.md, "Errors").
const (
	ReasonRolloutActive   = "ROLLOUT_ACTIVE"
	ReasonReleaseNewer    = "RELEASE_NEWER_THAN_CONTROLLER"
	ReasonReleaseBelowMin = "RELEASE_BELOW_MIN_AGENT_VERSION"
	ReasonReleaseChannel  = "RELEASE_NOT_ON_CHANNEL"
	ReasonRolloutState    = "ROLLOUT_STATE"
	ReasonRolloutMode     = "ROLLOUT_MODE"
	ReasonNotUpgradable   = "AGENT_NOT_UPGRADABLE"
)

// pausedByHand is the pause reason of a rollout an Instance Admin paused.
const pausedByHand = "paused by an Instance Admin"

var (
	rolloutStages = map[rollout.Stage]rpmgrv1.RolloutStage{rollout.StageCanary: rpmgrv1.RolloutStage_ROLLOUT_STAGE_CANARY,
		rollout.StagePercentage: rpmgrv1.RolloutStage_ROLLOUT_STAGE_PERCENTAGE, rollout.StageAll: rpmgrv1.RolloutStage_ROLLOUT_STAGE_ALL}
	rolloutStates = map[rollout.State]rpmgrv1.RolloutState{rollout.StateRunning: rpmgrv1.RolloutState_ROLLOUT_STATE_RUNNING,
		rollout.StatePaused: rpmgrv1.RolloutState_ROLLOUT_STATE_PAUSED, rollout.StateCompleted: rpmgrv1.RolloutState_ROLLOUT_STATE_COMPLETED,
		rollout.StateCancelled: rpmgrv1.RolloutState_ROLLOUT_STATE_CANCELLED}
	targetStates = map[rollouttarget.State]rpmgrv1.RolloutTargetState{
		rollouttarget.StatePending:    rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_PENDING,
		rollouttarget.StateOffered:    rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_OFFERED,
		rollouttarget.StateStaged:     rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_STAGED,
		rollouttarget.StateUpdated:    rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_UPDATED,
		rollouttarget.StateRolledBack: rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_ROLLED_BACK,
		rollouttarget.StateRefused:    rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_REFUSED,
		rollouttarget.StateSkipped:    rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_SKIPPED,
		rollouttarget.StateStalled:    rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_STALLED}
	agentKinds = map[rollouttarget.AgentKind]rpmgrv1.AgentKind{rollouttarget.AgentKindConnector: rpmgrv1.AgentKind_AGENT_KIND_CONNECTOR,
		rollouttarget.AgentKindGateway: rpmgrv1.AgentKind_AGENT_KIND_GATEWAY}
	rolloutModes = map[rollout.Mode]rpmgrv1.RolloutMode{rollout.ModeAdvanced: rpmgrv1.RolloutMode_ROLLOUT_MODE_ADVANCED,
		rollout.ModeEasy: rpmgrv1.RolloutMode_ROLLOUT_MODE_EASY}
)

// CreateRollout implements ReleaseService. In a staged rollout every connector and enrolled gateway
// that is not decommissioned and not built in gets a target; built-in agents run in the
// controller's process and update with it. An easy rollout gets a target for each agent of its
// queue, in its order (D129).
func (r *Releases) CreateRollout(ctx context.Context, req *connect.Request[rpmgrv1.CreateRolloutRequest]) (
	*connect.Response[rpmgrv1.CreateRolloutResponse], error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	m := req.Msg
	easy := m.GetMode() == rpmgrv1.RolloutMode_ROLLOUT_MODE_EASY
	switch {
	case easy && (len(m.GetAgentIds()) == 0 || len(m.GetCanaryAgentIds()) > 0):
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("apisvc: an easy rollout takes its queue in agent_ids, at least one agent, and no canary agents"))
	case !easy && (len(m.GetCanaryAgentIds()) == 0 || len(m.GetAgentIds()) > 0):
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("apisvc: a staged rollout takes at least one canary agent, and no agent_ids"))
	}
	var row *ent.Rollout
	mirrored := false
	create := func(tx *ent.Tx) error {
		rel, err := tx.Release.Get(sys, m.GetReleaseId())
		if err != nil {
			return err
		}
		if err := r.checkTarget(sys, tx, rel); err != nil {
			return err
		}
		mirrored = rel.MirroredAt != nil
		if n, err := tx.Rollout.Query().Where(rollout.Active(true)).Count(sys); err != nil || n > 0 {
			return errors.Join(err, errIf(n > 0, rolloutActive()))
		}
		agents, err := rolloutAgents(sys, tx)
		if err != nil {
			return err
		}
		if easy {
			queue, err := queueOf(agents, m.GetAgentIds())
			if err != nil {
				return err
			}
			if row, err = tx.Rollout.Create().SetReleaseID(rel.ID).SetMode(rollout.ModeEasy).SetCreatedBy(callerID(ctx)).Save(sys); err != nil {
				return err
			}
			_, err = store.QueueRolloutTargets(sys, tx, row.ID, queue)
			return err
		}
		for _, id := range m.GetCanaryAgentIds() {
			if _, ok := agents[id]; !ok {
				return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
					"apisvc: canary agent %s is not a connector or enrolled gateway that a rollout updates", id))
			}
		}
		row, err = tx.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy(callerID(ctx)).Save(sys)
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(agents))
		for id := range agents {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		const chunk = 500
		for start := 0; start < len(ids); start += chunk {
			var bulk []*ent.RolloutTargetCreate
			for _, id := range ids[start:min(start+chunk, len(ids))] {
				a := agents[id]
				bulk = append(bulk, tx.RolloutTarget.Create().SetRolloutID(row.ID).SetAgentID(id).SetAgentKind(a.kind).
					SetCanary(slices.Contains(m.GetCanaryAgentIds(), id)).SetBucket(store.RolloutBucket(id)).SetVersionBefore(a.version))
			}
			if err := tx.RolloutTarget.CreateBulk(bulk...).Exec(sys); err != nil {
				return err
			}
		}
		return nil
	}
	// A configuration transaction: the new revision makes every agent's snapshot compile again, so
	// that the rollout job's offers reach the agents.
	_, err := store.ConfigTx(sys, r.DB, func(tx *ent.Tx) ([]string, error) {
		if err := create(tx); err != nil {
			return nil, err
		}
		return []string{row.ID}, nil
	})
	if store.IsUniqueViolation(err) {
		err = rolloutActive() // another rollout was created at the same time
	}
	if err != nil {
		return nil, storeError(err)
	}
	if !mirrored {
		r.mirrorNow() // the mirror keeps the target from now on; the rollout job offers it once it holds it (D125)
	}
	out, err := r.rolloutOf(sys, row)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.CreateRolloutResponse{Rollout: out}), nil
}

// UpgradeAgents implements ReleaseService (docs/04-security.md, "Easy rollouts"; D129): the agents
// join the end of the queue of the easy rollout of the controller's own version that runs or is
// paused, or start one when no rollout does. An agent queued before keeps its place.
func (r *Releases) UpgradeAgents(ctx context.Context, req *connect.Request[rpmgrv1.UpgradeAgentsRequest]) (
	*connect.Response[rpmgrv1.UpgradeAgentsResponse], error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	var row *ent.Rollout
	var targets []*ent.RolloutTarget
	mirrored := true
	_, err := store.ConfigTx(sys, r.DB, func(tx *ent.Tx) ([]string, error) {
		rel, err := tx.Release.Query().Where(entrelease.Version(r.Version)).Only(sys)
		switch {
		case ent.IsNotFound(err) || !release.Releasable(r.Version):
			return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
				"apisvc: the controller's own release %s is not recorded; upload it or let the release check find it", r.Version))
		case err != nil:
			return nil, err
		}
		agents, err := rolloutAgents(sys, tx)
		if err != nil {
			return nil, err
		}
		queue, err := queueOf(agents, req.Msg.GetAgentIds())
		if err != nil {
			return nil, err
		}
		row, err = tx.Rollout.Query().Where(rollout.Active(true)).Only(sys)
		switch {
		case ent.IsNotFound(err):
			if err := r.checkTarget(sys, tx, rel); err != nil {
				return nil, err
			}
			mirrored = rel.MirroredAt != nil
			if row, err = tx.Rollout.Create().SetReleaseID(rel.ID).SetMode(rollout.ModeEasy).SetCreatedBy(callerID(ctx)).Save(sys); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		case row.Mode != rollout.ModeEasy:
			return nil, withReason(connect.NewError(connect.CodeFailedPrecondition,
				errors.New("apisvc: a staged rollout runs or is paused; let it complete or cancel it first")), ReasonRolloutActive)
		case row.ReleaseID != rel.ID:
			return nil, withReason(connect.NewError(connect.CodeFailedPrecondition,
				errors.New("apisvc: an easy rollout of another release runs or is paused; let it complete or cancel it first")), ReasonRolloutActive)
		}
		if targets, err = store.QueueRolloutTargets(sys, tx, row.ID, queue); err != nil {
			return nil, err
		}
		return []string{row.ID}, nil
	})
	if store.IsUniqueViolation(err) {
		err = rolloutActive() // another rollout was created at the same time
	}
	if err != nil {
		return nil, storeError(err)
	}
	if !mirrored {
		r.mirrorNow()
	}
	out := &rpmgrv1.UpgradeAgentsResponse{}
	if out.Rollout, err = r.rolloutOf(sys, row); err != nil {
		return nil, err
	}
	if out.RolloutTargets, err = r.targetsOf(sys, r.DB.ReadClient(), targets); err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// checkTarget refuses a release no rollout may target: one of a development build of the
// controller, one newer than the controller, one below its min_agent_version, and a pre-release
// on a stable instance.
func (r *Releases) checkTarget(ctx context.Context, tx *ent.Tx, rel *ent.Release) error {
	switch {
	case !release.Releasable(r.Version):
		return withReason(connect.NewError(connect.CodeFailedPrecondition,
			errors.New("apisvc: a development build of the controller runs no rollout")), ReasonReleaseNewer)
	case compareVersions(rel.Version, r.Version) > 0:
		return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"apisvc: release %s is newer than the controller's %s; upgrade the controller first", rel.Version, r.Version)), ReasonReleaseNewer)
	case r.MinAgentVersion != "" && compareVersions(rel.Version, r.MinAgentVersion) < 0:
		return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"apisvc: release %s is below %s, the oldest agent version the controller accepts; its agents could not connect",
			rel.Version, r.MinAgentVersion)), ReasonReleaseBelowMin)
	}
	return checkChannel(ctx, tx.Client(), rel)
}

// checkChannel refuses a pre-release on an instance whose update channel is stable.
func checkChannel(ctx context.Context, c *ent.Client, rel *ent.Release) error {
	set, _, err := settings.Instance(ctx, c)
	if err != nil {
		return err
	}
	if pre := rel.Channel == entrelease.ChannelPrerelease || semver.Prerelease("v"+rel.Version) != ""; pre &&
		set.GetUpdateChannel() != rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE {
		return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"apisvc: release %s is a pre-release and the instance's update channel is stable; every host on it would refuse it",
			rel.Version)), ReasonReleaseChannel)
	}
	return nil
}

// queueOf is an easy rollout's queue of the agents named, in their order. An agent that is not a
// connector or enrolled gateway in service, that is built in, or that has not announced the
// capability ota is refused with its reason (D129).
func queueOf(agents map[string]rolloutAgent, ids []string) ([]store.RolloutAgent, error) {
	out := make([]store.RolloutAgent, 0, len(ids))
	for _, id := range ids {
		a, ok := agents[id]
		switch {
		case !ok:
			return nil, withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
				"apisvc: agent %s is not a connector or enrolled gateway in service that updates over the air; built-in agents update with the controller", id)),
				ReasonNotUpgradable)
		case !a.ota:
			return nil, withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
				"apisvc: agent %s has not announced over-the-air updates: it runs without the root updater or with its units not enabled (install.sh --upgrade --restart installs them and restarts the agent), in the container image, or has never connected", id)),
				ReasonNotUpgradable)
		}
		out = append(out, store.RolloutAgent{ID: id, Kind: a.kind, VersionBefore: a.version})
	}
	return out, nil
}

// GetRollout implements ReleaseService.
func (r *Releases) GetRollout(ctx context.Context, req *connect.Request[rpmgrv1.GetRolloutRequest]) (
	*connect.Response[rpmgrv1.GetRolloutResponse], error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	row, err := r.DB.ReadClient().Rollout.Get(sys, req.Msg.GetRolloutId())
	if err != nil {
		return nil, storeError(err)
	}
	out, err := r.rolloutOf(sys, row)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.GetRolloutResponse{Rollout: out}), nil
}

// ListRollouts implements ReleaseService: the newest first.
func (r *Releases) ListRollouts(ctx context.Context, req *connect.Request[rpmgrv1.ListRolloutsRequest]) (
	*connect.Response[rpmgrv1.ListRolloutsResponse], error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	size, err := api.PageSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := r.API.AfterPage(req.Msg.GetPageToken(), req.Msg)
	if err != nil {
		return nil, err
	}
	q := r.DB.ReadClient().Rollout.Query().Order(ent.Desc(rollout.FieldID)).Limit(size + 1)
	if req.Msg.GetActiveOnly() {
		q.Where(rollout.Active(true))
	}
	if after != "" {
		q.Where(rollout.IDLT(after))
	}
	rows, err := q.All(sys)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListRolloutsResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = r.API.PageToken(rows[size-1].ID, req.Msg)
	}
	if out.Rollouts, err = r.rolloutsOf(sys, rows); err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// ListRolloutTargets implements ReleaseService.
func (r *Releases) ListRolloutTargets(ctx context.Context, req *connect.Request[rpmgrv1.ListRolloutTargetsRequest]) (
	*connect.Response[rpmgrv1.ListRolloutTargetsResponse], error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := r.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	c := r.DB.ReadClient()
	if _, err := c.Rollout.Get(sys, m.GetRolloutId()); err != nil {
		return nil, storeError(err)
	}
	q := c.RolloutTarget.Query().Where(rollouttarget.RolloutID(m.GetRolloutId())).Order(ent.Asc(rollouttarget.FieldID)).Limit(size + 1)
	if len(m.GetStates()) > 0 {
		var states []rollouttarget.State
		for s, v := range targetStates {
			if slices.Contains(m.GetStates(), v) {
				states = append(states, s)
			}
		}
		q.Where(rollouttarget.StateIn(states...))
	}
	if after != "" {
		q.Where(rollouttarget.IDGT(after))
	}
	rows, err := q.All(sys)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListRolloutTargetsResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = r.API.PageToken(rows[size-1].ID, m)
	}
	if out.RolloutTargets, err = r.targetsOf(sys, c, rows); err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// targetsOf are rollout targets as the API shows them, with their agents' names and orgs.
func (r *Releases) targetsOf(ctx context.Context, c *ent.Client, rows []*ent.RolloutTarget) ([]*rpmgrv1.RolloutTarget, error) {
	names, err := agentNames(ctx, c, rows)
	if err != nil {
		return nil, storeError(err)
	}
	out := make([]*rpmgrv1.RolloutTarget, 0, len(rows))
	for _, t := range rows {
		n := names[t.AgentID]
		x := &rpmgrv1.RolloutTarget{Id: t.ID, RolloutId: t.RolloutID, AgentId: t.AgentID,
			AgentKind: agentKinds[t.AgentKind], AgentName: n[0], OrgId: n[1], Canary: t.Canary, Bucket: int32(t.Bucket), //nolint:gosec // G115: 0 to 99
			State: targetStates[t.State], Reason: t.Reason, VersionBefore: t.VersionBefore, UpdateTime: timestamppb.New(t.UpdatedAt)}
		if t.Position != nil {
			x.Position = int32(*t.Position) //nolint:gosec // G115: one per agent
		}
		out = append(out, x)
	}
	return out, nil
}

// AdvanceRollout implements ReleaseService: a running rollout moves to a higher percentage or to
// all agents; a paused one must be resumed first.
func (r *Releases) AdvanceRollout(ctx context.Context, req *connect.Request[rpmgrv1.AdvanceRolloutRequest]) (
	*connect.Response[rpmgrv1.AdvanceRolloutResponse], error) {
	m := req.Msg
	out, err := r.change(ctx, m.GetRolloutId(), m.GetEtag(), []rollout.State{rollout.StateRunning}, func(cur *ent.Rollout, u *ent.RolloutUpdateOne) error {
		switch {
		case cur.Mode == rollout.ModeEasy:
			return withReason(connect.NewError(connect.CodeFailedPrecondition,
				errors.New("apisvc: an easy rollout has no stages; its agents update one after another")), ReasonRolloutMode)
		case cur.Stage == rollout.StageAll:
			return stateError("the rollout reaches every agent already")
		case m.GetAll():
			u.SetStage(rollout.StageAll).SetPercentage(100)
		case int(m.GetPercentage()) <= cur.Percentage:
			return stateError(fmt.Sprintf("the rollout is at %d %%; the next stage must be higher", cur.Percentage))
		default:
			u.SetStage(rollout.StagePercentage).SetPercentage(int(m.GetPercentage()))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.AdvanceRolloutResponse{Rollout: out}), nil
}

// PauseRollout implements ReleaseService.
func (r *Releases) PauseRollout(ctx context.Context, req *connect.Request[rpmgrv1.PauseRolloutRequest]) (
	*connect.Response[rpmgrv1.PauseRolloutResponse], error) {
	out, err := r.change(ctx, req.Msg.GetRolloutId(), req.Msg.GetEtag(), []rollout.State{rollout.StateRunning},
		func(_ *ent.Rollout, u *ent.RolloutUpdateOne) error {
			u.SetState(rollout.StatePaused).SetPauseReason(pausedByHand)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.PauseRolloutResponse{Rollout: out}), nil
}

// ResumeRollout implements ReleaseService.
func (r *Releases) ResumeRollout(ctx context.Context, req *connect.Request[rpmgrv1.ResumeRolloutRequest]) (
	*connect.Response[rpmgrv1.ResumeRolloutResponse], error) {
	out, err := r.change(ctx, req.Msg.GetRolloutId(), req.Msg.GetEtag(), []rollout.State{rollout.StatePaused},
		func(_ *ent.Rollout, u *ent.RolloutUpdateOne) error {
			u.SetState(rollout.StateRunning).SetPauseReason("")
			return nil
		})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ResumeRolloutResponse{Rollout: out}), nil
}

// CancelRollout implements ReleaseService.
func (r *Releases) CancelRollout(ctx context.Context, req *connect.Request[rpmgrv1.CancelRolloutRequest]) (
	*connect.Response[rpmgrv1.CancelRolloutResponse], error) {
	out, err := r.change(ctx, req.Msg.GetRolloutId(), req.Msg.GetEtag(), []rollout.State{rollout.StateRunning, rollout.StatePaused},
		func(_ *ent.Rollout, u *ent.RolloutUpdateOne) error {
			u.SetState(rollout.StateCancelled)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.CancelRolloutResponse{Rollout: out}), nil
}

// change applies set to a rollout in one of the states from, under its etag, and records the
// caller as the one who changed it. It is a configuration transaction, which takes the config_seq
// row lock first, so changes of a rollout from the API happen one after the other, and its revision
// makes the snapshots compile again; the update names the version it read, so a change the
// rollout job made meanwhile makes it read the rollout again, at most three times.
func (r *Releases) change(ctx context.Context, id, etag string, from []rollout.State, set func(*ent.Rollout, *ent.RolloutUpdateOne) error) (
	*rpmgrv1.Rollout, error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	var row *ent.Rollout
	for attempt := 1; ; attempt++ {
		_, err := store.ConfigTx(sys, r.DB, func(tx *ent.Tx) ([]string, error) {
			cur, err := tx.Rollout.Get(sys, id)
			if err != nil {
				return nil, err
			}
			if etag != "" && etag != etagOf(cur.Version) {
				now, err := r.rolloutOf(sys, cur)
				if err != nil {
					return nil, err
				}
				return nil, api.CheckEtag(etag, cur.Version, now)
			}
			if !slices.Contains(from, cur.State) {
				return nil, stateError(fmt.Sprintf("the rollout is %s", cur.State))
			}
			u := cur.Update().Where(rollout.Version(cur.Version)).SetUpdatedBy(callerID(ctx))
			if err := set(cur, u); err != nil {
				return nil, err
			}
			if row, err = u.Save(sys); ent.IsNotFound(err) {
				return nil, errRolloutChanged
			}
			return []string{id}, err
		})
		switch {
		case errors.Is(err, errRolloutChanged) && attempt < 3:
			continue
		case errors.Is(err, errRolloutChanged):
			return nil, connect.NewError(connect.CodeAborted, err)
		case err != nil:
			return nil, storeError(err)
		}
		return r.rolloutOf(sys, row)
	}
}

// errRolloutChanged means a rollout changed between reading and updating it.
var errRolloutChanged = errors.New("apisvc: the rollout changed meanwhile; try again")

// callerID is the user who calls, "" for none.
func callerID(ctx context.Context) string {
	if c := api.CallerFrom(ctx); c != nil {
		return c.UserID
	}
	return ""
}

func rolloutActive() error {
	return withReason(connect.NewError(connect.CodeFailedPrecondition,
		errors.New("apisvc: another rollout runs or is paused; cancel it or let it complete first")), ReasonRolloutActive)
}

func stateError(what string) error {
	return withReason(connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: "+what)), ReasonRolloutState)
}

// rolloutAgent is an agent a rollout updates: its kind, the version it last connected with and
// whether it announced the capability ota.
type rolloutAgent struct {
	kind    rollouttarget.AgentKind
	version string
	ota     bool
}

// rolloutAgents are the agents a new rollout updates, by ID, with the version each last connected
// with.
func rolloutAgents(ctx context.Context, tx *ent.Tx) (map[string]rolloutAgent, error) {
	out := map[string]rolloutAgent{}
	cons, err := tx.Connector.Query().Where(connector.DecommissionedAtIsNil(), connector.BuiltIn(false)).IDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range cons {
		out[id] = rolloutAgent{kind: rollouttarget.AgentKindConnector}
	}
	gws, err := tx.Gateway.Query().Where(gateway.DecommissionedAtIsNil(), gateway.BuiltIn(false), gateway.SpiffeIDNEQ("")).IDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range gws {
		out[id] = rolloutAgent{kind: rollouttarget.AgentKindGateway}
	}
	sessions, err := tx.AgentSession.Query().
		Select(agentsession.FieldID, agentsession.FieldAgentVersion, agentsession.FieldCapabilities).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		if a, ok := out[s.ID]; ok {
			a.version, a.ota = s.AgentVersion, slices.Contains(s.Capabilities, agentproto.CapOTA)
			out[s.ID] = a
		}
	}
	return out, nil
}

// agentNames are the names and orgs of the targets' agents, by agent ID.
func agentNames(ctx context.Context, c *ent.Client, rows []*ent.RolloutTarget) (map[string][2]string, error) {
	var cons, gws []string
	for _, t := range rows {
		if t.AgentKind == rollouttarget.AgentKindConnector {
			cons = append(cons, t.AgentID)
		} else {
			gws = append(gws, t.AgentID)
		}
	}
	out := map[string][2]string{}
	cs, err := c.Connector.Query().Where(connector.IDIn(cons...)).Select(connector.FieldID, connector.FieldName, connector.FieldOrgID).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range cs {
		out[x.ID] = [2]string{x.Name, x.OrgID}
	}
	gs, err := c.Gateway.Query().Where(gateway.IDIn(gws...)).Select(gateway.FieldID, gateway.FieldName, gateway.FieldOrgID).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range gs {
		out[x.ID] = [2]string{x.Name, x.OrgID}
	}
	return out, nil
}

func (r *Releases) rolloutOf(ctx context.Context, row *ent.Rollout) (*rpmgrv1.Rollout, error) {
	out, err := r.rolloutsOf(ctx, []*ent.Rollout{row})
	if err != nil {
		return nil, err
	}
	return out[0], nil
}

// rolloutsOf are rollouts as the API shows them, with their release's version and how many of
// their agents are in each state.
func (r *Releases) rolloutsOf(ctx context.Context, rows []*ent.Rollout) ([]*rpmgrv1.Rollout, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	c := r.DB.ReadClient()
	ids, relIDs := make([]string, len(rows)), make([]string, len(rows))
	for i, x := range rows {
		ids[i], relIDs[i] = x.ID, x.ReleaseID
	}
	rels, err := c.Release.Query().Where(entrelease.IDIn(relIDs...)).Select(entrelease.FieldID, entrelease.FieldVersion).All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	versions := map[string]string{}
	for _, x := range rels {
		versions[x.ID] = x.Version
	}
	var counts []struct {
		RolloutID string              `json:"rollout_id"`
		State     rollouttarget.State `json:"state"`
		Count     int                 `json:"count"`
	}
	if err := c.RolloutTarget.Query().Where(rollouttarget.RolloutIDIn(ids...)).
		GroupBy(rollouttarget.FieldRolloutID, rollouttarget.FieldState).Aggregate(ent.Count()).Scan(ctx, &counts); err != nil {
		return nil, storeError(err)
	}
	byRollout := map[string]*rpmgrv1.RolloutCounts{}
	for _, id := range ids {
		byRollout[id] = &rpmgrv1.RolloutCounts{}
	}
	for _, x := range counts {
		n, rc := int32(x.Count), byRollout[x.RolloutID] //nolint:gosec // G115: one per agent
		switch x.State {
		case rollouttarget.StatePending:
			rc.Pending = n
		case rollouttarget.StateOffered:
			rc.Offered = n
		case rollouttarget.StateStaged:
			rc.Staged = n
		case rollouttarget.StateUpdated:
			rc.Updated = n
		case rollouttarget.StateRolledBack:
			rc.RolledBack = n
		case rollouttarget.StateRefused:
			rc.Refused = n
		case rollouttarget.StateSkipped:
			rc.Skipped = n
		case rollouttarget.StateStalled:
			rc.Stalled = n
		}
	}
	out := make([]*rpmgrv1.Rollout, len(rows))
	for i, x := range rows {
		out[i] = &rpmgrv1.Rollout{Id: x.ID, ReleaseId: x.ReleaseID, Version: versions[x.ReleaseID], Stage: rolloutStages[x.Stage],
			Percentage: int32(x.Percentage), State: rolloutStates[x.State], PauseReason: x.PauseReason, Counts: byRollout[x.ID], //nolint:gosec // G115: 0 to 100
			CreateUserId: x.CreatedBy, CreateTime: timestamppb.New(x.CreatedAt), UpdateUserId: x.UpdatedBy,
			UpdateTime: timestamppb.New(x.UpdatedAt), Etag: etagOf(x.Version), Mode: rolloutModes[x.Mode]}
	}
	return out, nil
}
