// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

// The rollout job's timing (docs/03-connections.md, "Timeouts, keepalive and backoff"): it looks
// at the running rollout every 30 s; an agent that reports nothing for 30 min counts as stalled;
// a gateway is offered its release only after its drain period.
const (
	RolloutEvery       = 30 * time.Second
	RolloutStallAfter  = 30 * time.Minute
	rolloutDrainPeriod = 60 * time.Second
)

// rolloutSystem is the actor the job records when it changes a rollout.
const rolloutSystem = "system"

// RolloutOptions configure the rollout job.
type RolloutOptions struct {
	DB     *store.DB
	Now    func() time.Time
	Logger *slog.Logger
}

// RolloutJob offers a running rollout's release to its current stage and follows each agent
// (docs/04-security.md, "Over-the-air updates"; D121): the canaries, then the agents of the
// percentage, then all. A gateway drains before it is offered the release, one at a time per
// gateway group. A rollback or an agent that stops reporting pauses the rollout until an Instance
// Admin resumes or cancels it; the end of the last stage completes it.
func RolloutJob(o RolloutOptions) lease.Job {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return lease.Job{Name: "rollouts", Reason: "offer and follow a staged rollout", Every: RolloutEvery,
		Run: func(ctx context.Context, _ lease.Lease) error { return runRollout(ctx, o) }}
}

// runRollout advances the active rollout one step.
func runRollout(ctx context.Context, o RolloutOptions) error {
	now := o.Now()
	c := o.DB.ReadClient()
	if err := releaseDrains(ctx, c, o); err != nil {
		return err
	}
	ro, err := c.Rollout.Query().Where(rollout.Active(true)).WithRelease().Only(ctx)
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	targets, err := c.RolloutTarget.Query().Where(rollouttarget.RolloutID(ro.ID)).Order(ent.Asc(rollouttarget.FieldAgentID)).All(ctx)
	if err != nil {
		return err
	}
	// Targets already in flight go first: a gateway that finishes frees its group for the next
	// one in the same run.
	slices.SortStableFunc(targets, func(a, b *ent.RolloutTarget) int {
		switch {
		case a.State == rollouttarget.StatePending && b.State != rollouttarget.StatePending:
			return 1
		case a.State != rollouttarget.StatePending && b.State == rollouttarget.StatePending:
			return -1
		}
		return 0
	})
	agents, err := readRolloutFacts(ctx, c, now, targets)
	if err != nil {
		return err
	}
	plan := &rolloutPlan{now: now, version: ro.Edges.Release.Version, busyGroups: map[string]string{}}
	if ro.State == rollout.StateRunning {
		for _, t := range targets {
			if t.AgentKind == rollouttarget.AgentKindGateway && (inFlight(t.State) || t.DrainStartedAt != nil) {
				plan.busyGroups[agents[t.AgentID].group] = t.AgentID
			}
		}
	}
	for _, t := range targets {
		plan.consider(ro, t, agents[t.AgentID])
	}
	reason := plan.pauseReason()
	remaining := 0
	for _, t := range targets {
		if !terminal(plan.stateOf(t)) {
			remaining++
		}
	}
	complete := ro.State == rollout.StateRunning && reason == "" && ro.Stage == rollout.StageAll && remaining == 0
	return plan.apply(ctx, o, ro, reason, complete)
}

// releaseDrains enables the gateways a rollout drained once that rollout is no longer running:
// paused by an Instance Admin or the job, cancelled, or completed (D121). It also cleans up a
// drain a crash or a takeover left behind.
func releaseDrains(ctx context.Context, c *ent.Client, o RolloutOptions) error {
	rows, err := c.RolloutTarget.Query().Where(rollouttarget.DrainStartedAtNotNil()).WithRollout().All(ctx)
	if err != nil {
		return err
	}
	var clear []*ent.RolloutTarget
	var enable []string
	for _, t := range rows {
		if t.Edges.Rollout.State == rollout.StateRunning {
			continue
		}
		clear = append(clear, t)
		if t.AgentKind == rollouttarget.AgentKindGateway {
			enable = append(enable, t.AgentID)
		}
	}
	if len(clear) == 0 {
		return nil
	}
	_, err = store.ConfigTx(ctx, o.DB, func(tx *ent.Tx) ([]string, error) {
		changed := make([]string, 0, len(clear))
		for _, t := range clear {
			if _, err := tx.RolloutTarget.UpdateOneID(t.ID).ClearDrainStartedAt().Save(ctx); err != nil {
				return nil, err
			}
			changed = append(changed, t.ID)
		}
		for _, id := range enable {
			if _, err := tx.Gateway.UpdateOneID(id).SetEnabled(true).Save(ctx); err != nil {
				return nil, err
			}
			changed = append(changed, id)
		}
		return changed, nil
	})
	if err != nil {
		return fmt.Errorf("controller: releasing drained gateways: %w", err)
	}
	return nil
}

// rolloutFacts is what the job knows of one agent: whether it has a live session, the version it
// last connected with, and for a gateway whether it is enabled and in which group.
type rolloutFacts struct {
	live    bool
	version string
	enabled bool
	group   string
}

// readRolloutFacts reads the agents of the targets. A target whose agent row is gone counts as
// offline, which is what the purge of a decommissioned agent leaves behind.
func readRolloutFacts(ctx context.Context, c *ent.Client, now time.Time, targets []*ent.RolloutTarget) (map[string]rolloutFacts, error) {
	out := map[string]rolloutFacts{}
	var ids, gws []string
	for _, t := range targets {
		ids = append(ids, t.AgentID)
		if t.AgentKind == rollouttarget.AgentKindGateway {
			gws = append(gws, t.AgentID)
		}
	}
	sessions, err := c.AgentSession.Query().Where(agentsession.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		out[s.ID] = rolloutFacts{live: schema.AgentSessionLive(s.DisconnectedAt, s.LastSeenAt, now), version: s.AgentVersion}
	}
	gateways, err := c.Gateway.Query().Where(gateway.IDIn(gws...)).
		Select(gateway.FieldID, gateway.FieldEnabled, gateway.FieldGatewayGroupID).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range gateways {
		f := out[g.ID]
		f.enabled, f.group = g.Enabled, g.GatewayGroupID
		out[g.ID] = f
	}
	return out, nil
}

// rolloutPlan is the change one run makes: the targets' new states and the gateways to enable or
// disable.
type rolloutPlan struct {
	now        time.Time
	version    string
	updates    []rolloutTargetUpdate
	enable     []string // gateways the job drained, whose target is now at rest
	disable    []string // gateways to drain before they are offered the release
	busyGroups map[string]string
	pause      string // why this run pauses the rollout
}

// rolloutTargetUpdate is a target's new state. drainAt is set to start a drain; clearDrain ends
// one the job started. Without either, drain_started_at is left as it is.
type rolloutTargetUpdate struct {
	target     *ent.RolloutTarget
	state      rollouttarget.State
	reason     string
	drainAt    *time.Time
	clearDrain bool
}

// consider decides what to do with one target. An agent that is offline, or that declined the
// release, is skipped and never blocks the stage; a rollback or a silent agent pauses the rollout;
// everything else waits for the agent.
func (p *rolloutPlan) consider(ro *ent.Rollout, t *ent.RolloutTarget, f rolloutFacts) {
	if terminal(t.State) {
		p.finishDrain(t)
		// A rollback or a refusal the agent reported since the rollout last changed pauses it; one
		// an Instance Admin has already seen and resumed past does not pause it again.
		if pausedByAgent(t.State) && t.UpdatedAt.After(ro.UpdatedAt) {
			p.pause = p.pauseReasonOf(t.State, t.AgentID)
		}
		return
	}
	if ro.State != rollout.StateRunning {
		p.finishDrain(t)
		return
	}
	if !rolloutInStage(ro, t) {
		return
	}
	switch t.State {
	case rollouttarget.StatePending:
		switch {
		case !f.live:
			p.set(t, rollouttarget.StateSkipped, "the agent is offline")
		case f.version == p.version:
			p.set(t, rollouttarget.StateUpdated, "")
		case t.AgentKind == rollouttarget.AgentKindGateway:
			p.drain(t, f)
		default:
			p.set(t, rollouttarget.StateOffered, "")
		}
	case rollouttarget.StateOffered, rollouttarget.StateStaged:
		if f.version == p.version {
			p.set(t, rollouttarget.StateUpdated, "")
		} else if p.now.Sub(t.UpdatedAt) >= RolloutStallAfter {
			p.set(t, rollouttarget.StateStalled, "the agent reported nothing for 30 minutes")
			p.pause = p.pauseReasonOf(rollouttarget.StateStalled, t.AgentID)
		}
	}
	if terminal(p.stateOf(t)) && p.busyGroups[f.group] == t.AgentID {
		delete(p.busyGroups, f.group)
	}
}

// drain schedules a gateway's drain before its update, and offers the release once the drain
// period has passed. A gateway the job did not disable was disabled by an operator; it is skipped,
// because the job must not enable it again.
func (p *rolloutPlan) drain(t *ent.RolloutTarget, f rolloutFacts) {
	switch {
	case !f.enabled && t.DrainStartedAt == nil:
		p.set(t, rollouttarget.StateSkipped, "the gateway is disabled")
	case t.DrainStartedAt != nil && (!f.enabled && p.now.Sub(*t.DrainStartedAt) < rolloutDrainPeriod):
		// Still draining.
	case p.busyGroups[f.group] != "" && p.busyGroups[f.group] != t.AgentID:
		// Another gateway of the group is updating; this one waits its turn.
	case f.enabled && t.DrainStartedAt == nil:
		at := p.now
		p.updates = append(p.updates, rolloutTargetUpdate{target: t, state: rollouttarget.StatePending,
			reason: "the gateway drains before its update", drainAt: &at})
		p.disable = append(p.disable, t.AgentID)
		p.busyGroups[f.group] = t.AgentID
	default:
		// The drain ended; the offer may go out while the gateway is still disabled.
		p.set(t, rollouttarget.StateOffered, "")
		p.busyGroups[f.group] = t.AgentID
	}
}

// finishDrain re-enables a gateway the job drained and clears the mark. A gateway an operator
// disabled has no mark and is left alone.
func (p *rolloutPlan) finishDrain(t *ent.RolloutTarget) {
	if t.DrainStartedAt == nil {
		return
	}
	p.updates = append(p.updates, rolloutTargetUpdate{target: t, state: t.State, reason: t.Reason, clearDrain: true})
	p.enable = append(p.enable, t.AgentID)
}

// set records a target's new state. A target at rest ends the drain the job started for it.
func (p *rolloutPlan) set(t *ent.RolloutTarget, state rollouttarget.State, reason string) {
	u := rolloutTargetUpdate{target: t, state: state, reason: reason}
	if terminal(state) && t.DrainStartedAt != nil {
		u.clearDrain = true
		p.enable = append(p.enable, t.AgentID)
	}
	p.updates = append(p.updates, u)
}

// stateOf is a target's state after the plan.
func (p *rolloutPlan) stateOf(t *ent.RolloutTarget) rollouttarget.State {
	for _, u := range p.updates {
		if u.target.ID == t.ID {
			return u.state
		}
	}
	return t.State
}

// pauseReason is why the rollout must pause, or "".
func (p *rolloutPlan) pauseReason() string { return p.pause }

// pauseReasonOf is the reason to pause after an agent reached state.
func (p *rolloutPlan) pauseReasonOf(state rollouttarget.State, agent string) string {
	switch state {
	case rollouttarget.StateRolledBack:
		return fmt.Sprintf("the updater rolled the release back on %s", agent)
	case rollouttarget.StateStalled:
		return fmt.Sprintf("%s reported nothing for %s", agent, RolloutStallAfter)
	case rollouttarget.StateRefused:
		return fmt.Sprintf("the updater refused the release on %s", agent)
	}
	return ""
}

// pausedByAgent reports whether a target's state is one an agent reports and that pauses a
// rollout (D121): a rollback, or an updater that refused the release or could not roll back.
func pausedByAgent(s rollouttarget.State) bool {
	return s == rollouttarget.StateRolledBack || s == rollouttarget.StateStalled || s == rollouttarget.StateRefused
}

// apply writes the plan in one configuration transaction, so the snapshots compile once more and
// the agents see their offers. It also pauses or completes the rollout.
func (p *rolloutPlan) apply(ctx context.Context, o RolloutOptions, ro *ent.Rollout, pause string, complete bool) error {
	if len(p.updates) == 0 && len(p.disable) == 0 && pause == "" && !complete && ro.State == rollout.StateRunning {
		return nil
	}
	_, err := store.ConfigTx(ctx, o.DB, func(tx *ent.Tx) ([]string, error) {
		changed := make([]string, 0, len(p.updates)+len(p.disable))
		for _, u := range p.updates {
			upd := tx.RolloutTarget.UpdateOneID(u.target.ID).SetState(u.state).SetReason(u.reason)
			switch {
			case u.drainAt != nil:
				upd.SetDrainStartedAt(*u.drainAt)
			case u.clearDrain:
				upd.ClearDrainStartedAt()
			}
			if _, err := upd.Save(ctx); err != nil {
				return nil, err
			}
			changed = append(changed, u.target.ID)
		}
		for _, id := range p.disable {
			if _, err := tx.Gateway.UpdateOneID(id).SetEnabled(false).Save(ctx); err != nil {
				return nil, err
			}
			changed = append(changed, id)
		}
		for _, id := range p.enable {
			if _, err := tx.Gateway.UpdateOneID(id).SetEnabled(true).Save(ctx); err != nil {
				return nil, err
			}
			changed = append(changed, id)
		}
		switch {
		case complete:
			if _, err := tx.Rollout.UpdateOneID(ro.ID).SetState(rollout.StateCompleted).
				SetUpdatedBy(rolloutSystem).Save(ctx); err != nil {
				return nil, err
			}
			changed = append(changed, ro.ID)
		case pause != "":
			if _, err := tx.Rollout.UpdateOneID(ro.ID).SetState(rollout.StatePaused).SetPauseReason(pause).
				SetUpdatedBy(rolloutSystem).Save(ctx); err != nil {
				return nil, err
			}
			changed = append(changed, ro.ID)
		}
		return changed, nil
	})
	if err != nil {
		return fmt.Errorf("controller: rollout %s: %w", ro.ID, err)
	}
	if pause != "" {
		o.Logger.Warn("paused a rollout", "rollout", ro.ID, "reason", pause)
	}
	return nil
}

// rolloutInStage reports whether a target is part of the rollout's current stage: the canaries,
// then every agent whose bucket is below the percentage, then every agent.
func rolloutInStage(ro *ent.Rollout, t *ent.RolloutTarget) bool {
	switch ro.Stage {
	case rollout.StageCanary:
		return t.Canary
	case rollout.StagePercentage:
		return t.Canary || t.Bucket < ro.Percentage
	default:
		return true
	}
}

// terminal reports whether a target's state is at rest for the rest of the rollout.
func terminal(s rollouttarget.State) bool {
	switch s {
	case rollouttarget.StateUpdated, rollouttarget.StateRolledBack, rollouttarget.StateRefused,
		rollouttarget.StateSkipped, rollouttarget.StateStalled:
		return true
	}
	return false
}

// inFlight reports whether a gateway target holds its group's turn.
func inFlight(s rollouttarget.State) bool {
	return s == rollouttarget.StateOffered || s == rollouttarget.StateStaged
}

// recordUpdate records what an agent reports about the release it was offered (docs/04-security.md,
// "Over-the-air updates", step 7): the phase of its own staging and the root updater's outcome.
// It applies to the agent's target in the running rollout only; a report about another version,
// or for an agent without a target, changes nothing.
func (s *Sessions) recordUpdate(id pki.Identity, u *agentv1.UpdateState) {
	err := store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		t, err := tx.RolloutTarget.Query().
			Where(rollouttarget.AgentID(id.ID), rollouttarget.HasRolloutWith(rollout.StateEQ(rollout.StateRunning))).
			WithRollout(func(q *ent.RolloutQuery) { q.WithRelease() }).Only(s.sys)
		if ent.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if terminal(t.State) {
			return nil
		}
		state, reason, ok := rolloutUpdateState(t.State, u, t.Edges.Rollout.Edges.Release.Version)
		if !ok || (state == t.State && reason == t.Reason) {
			return nil
		}
		return tx.RolloutTarget.UpdateOneID(t.ID).SetState(state).SetReason(reason).Exec(s.sys)
	})
	if err != nil && s.sys.Err() == nil {
		s.log.Error("cannot record an agent's update state", "agent", id.ID, "error", err)
	}
}

// rolloutUpdateState maps an agent's update state to its target's state. ok is false for a report
// that says nothing about the offered release's progress.
func rolloutUpdateState(cur rollouttarget.State, u *agentv1.UpdateState, version string) (
	state rollouttarget.State, reason string, ok bool) {
	if up := u.GetUpdater(); up != nil && up.GetVersion() == version {
		switch up.GetResult() {
		case agentv1.UpdaterResult_UPDATER_RESULT_UPDATED:
			return rollouttarget.StateUpdated, "", true
		case agentv1.UpdaterResult_UPDATER_RESULT_ROLLED_BACK:
			return rollouttarget.StateRolledBack, textOr(up.GetReason(), "the updater rolled the release back"), true
		case agentv1.UpdaterResult_UPDATER_RESULT_ROLLBACK_FAILED:
			return rollouttarget.StateStalled, textOr(up.GetReason(), "the updater could not put the previous binary back"), true
		case agentv1.UpdaterResult_UPDATER_RESULT_REFUSED:
			return rollouttarget.StateRefused, textOr(up.GetReason(), "the updater refused the release"), true
		}
	}
	if u.GetVersion() != version {
		return cur, "", false
	}
	switch u.GetPhase() {
	case agentv1.UpdatePhase_UPDATE_PHASE_AVAILABLE:
		return rollouttarget.StateSkipped, textOr(u.GetDetail(), "the local policy says auto_update: notify"), true
	case agentv1.UpdatePhase_UPDATE_PHASE_DECLINED:
		return rollouttarget.StateSkipped, textOr(u.GetDetail(), "the agent declined the release"), true
	case agentv1.UpdatePhase_UPDATE_PHASE_DOWNLOADING:
		return cur, u.GetDetail(), true
	case agentv1.UpdatePhase_UPDATE_PHASE_STAGED:
		return rollouttarget.StateStaged, u.GetDetail(), true
	case agentv1.UpdatePhase_UPDATE_PHASE_FAILED:
		k := cur
		if k == rollouttarget.StatePending {
			k = rollouttarget.StateOffered
		}
		return k, textOr(u.GetDetail(), "the agent failed to stage the release and retries"), true
	}
	return cur, "", false
}

// textOr is s, or fallback when s is empty.
func textOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
