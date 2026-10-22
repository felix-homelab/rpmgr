// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/release"
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
	ReasonRolloutActive      = "ROLLOUT_ACTIVE"
	ReasonReleaseNewer       = "RELEASE_NEWER_THAN_CONTROLLER"
	ReasonReleaseNotMirrored = "RELEASE_NOT_MIRRORED"
	ReasonRolloutState       = "ROLLOUT_STATE"
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
)

// CreateRollout implements ReleaseService. Every connector and enrolled gateway that is not
// decommissioned and not built in gets a target; built-in agents run in the controller's process
// and update with it.
func (r *Releases) CreateRollout(ctx context.Context, req *connect.Request[rpmgrv1.CreateRolloutRequest]) (
	*connect.Response[rpmgrv1.CreateRolloutResponse], error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	m := req.Msg
	var row *ent.Rollout
	err := store.WriteTx(sys, r.DB, func(tx *ent.Tx) error {
		rel, err := tx.Release.Get(sys, m.GetReleaseId())
		if err != nil {
			return err
		}
		switch {
		case !release.Releasable(r.Version):
			return withReason(connect.NewError(connect.CodeFailedPrecondition,
				errors.New("apisvc: a development build of the controller runs no rollout")), ReasonReleaseNewer)
		case compareVersions(rel.Version, r.Version) > 0:
			return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
				"apisvc: release %s is newer than the controller's %s; upgrade the controller first", rel.Version, r.Version)), ReasonReleaseNewer)
		case rel.MirroredAt == nil:
			return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
				"apisvc: the mirror does not hold release %s yet", rel.Version)), ReasonReleaseNotMirrored)
		}
		if n, err := tx.Rollout.Query().Where(rollout.Active(true)).Count(sys); err != nil || n > 0 {
			return errors.Join(err, errIf(n > 0, rolloutActive()))
		}
		agents, err := rolloutAgents(sys, tx)
		if err != nil {
			return err
		}
		for _, id := range m.GetCanaryAgentIds() {
			if _, ok := agents[id]; !ok {
				return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
					"apisvc: canary agent %s is not a connector or enrolled gateway that a rollout updates", id))
			}
		}
		row, err = tx.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy(api.CallerFrom(ctx).UserID).Save(sys)
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
	})
	if store.IsUniqueViolation(err) {
		err = rolloutActive() // another rollout was created at the same time
	}
	if err != nil {
		return nil, storeError(err)
	}
	out, err := r.rolloutOf(sys, row)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.CreateRolloutResponse{Rollout: out}), nil
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
	names, err := agentNames(sys, c, rows)
	if err != nil {
		return nil, storeError(err)
	}
	for _, t := range rows {
		n := names[t.AgentID]
		out.RolloutTargets = append(out.RolloutTargets, &rpmgrv1.RolloutTarget{Id: t.ID, RolloutId: t.RolloutID, AgentId: t.AgentID,
			AgentKind: agentKinds[t.AgentKind], AgentName: n[0], OrgId: n[1], Canary: t.Canary, Bucket: int32(t.Bucket), //nolint:gosec // G115: 0 to 99
			State: targetStates[t.State], Reason: t.Reason, VersionBefore: t.VersionBefore, UpdateTime: timestamppb.New(t.UpdatedAt)})
	}
	return connect.NewResponse(out), nil
}

// AdvanceRollout implements ReleaseService: a running rollout moves to a higher percentage or to
// all agents; a paused one is resumed first.
func (r *Releases) AdvanceRollout(ctx context.Context, req *connect.Request[rpmgrv1.AdvanceRolloutRequest]) (
	*connect.Response[rpmgrv1.AdvanceRolloutResponse], error) {
	m := req.Msg
	out, err := r.change(ctx, m.GetRolloutId(), m.GetEtag(), []rollout.State{rollout.StateRunning}, func(cur *ent.Rollout, u *ent.RolloutUpdateOne) error {
		switch {
		case cur.Stage == rollout.StageAll:
			return stateError("the rollout reaches every agent already")
		case m.GetAll():
			u.SetStage(rollout.StageAll).SetPercentage(100)
		case int(m.GetPercentage()) <= cur.Percentage:
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: the rollout is at %d %%; the next stage must be higher", cur.Percentage))
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
// caller as the one who changed it.
func (r *Releases) change(ctx context.Context, id, etag string, from []rollout.State, set func(*ent.Rollout, *ent.RolloutUpdateOne) error) (
	*rpmgrv1.Rollout, error) {
	sys := store.CarryTxHook(r.Sys, ctx)
	var row *ent.Rollout
	err := store.WriteTx(sys, r.DB, func(tx *ent.Tx) error {
		cur, err := tx.Rollout.Get(sys, id)
		if err != nil {
			return err
		}
		if etag != "" && etag != etagOf(cur.Version) {
			now, err := r.rolloutOf(sys, cur)
			if err != nil {
				return err
			}
			return api.CheckEtag(etag, cur.Version, now)
		}
		if !slices.Contains(from, cur.State) {
			return stateError(fmt.Sprintf("the rollout is %s", cur.State))
		}
		u := cur.Update().SetUpdatedBy(api.CallerFrom(ctx).UserID)
		if err := set(cur, u); err != nil {
			return err
		}
		row, err = u.Save(sys)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return r.rolloutOf(sys, row)
}

func rolloutActive() error {
	return withReason(connect.NewError(connect.CodeFailedPrecondition,
		errors.New("apisvc: another rollout runs or is paused; cancel it or let it complete first")), ReasonRolloutActive)
}

func stateError(what string) error {
	return withReason(connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: "+what)), ReasonRolloutState)
}

// rolloutAgent is an agent a rollout updates.
type rolloutAgent struct {
	kind    rollouttarget.AgentKind
	version string
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
	sessions, err := tx.AgentSession.Query().Select(agentsession.FieldID, agentsession.FieldAgentVersion).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		if a, ok := out[s.ID]; ok {
			a.version = s.AgentVersion
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
			UpdateTime: timestamppb.New(x.UpdatedAt), Etag: etagOf(x.Version)}
	}
	return out, nil
}
