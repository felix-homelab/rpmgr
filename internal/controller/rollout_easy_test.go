// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// easyRollout creates the one active rollout as an easy rollout with the agents queued in order.
func (e *rolloutJobEnv) easyRollout(agents ...string) *ent.Rollout {
	e.t.Helper()
	ro := e.db.Client().Rollout.Create().SetReleaseID(e.rel.ID).SetMode(rollout.ModeEasy).SetCreatedBy("usr_admin").
		SetUpdatedAt(e.now).SaveX(e.sys) // on the job's clock, which counts failures since the last change
	e.enqueue(ro, agents...)
	return ro
}

// enqueue adds agents to the end of an easy rollout's queue, as Update does.
func (e *rolloutJobEnv) enqueue(ro *ent.Rollout, agents ...string) {
	e.t.Helper()
	in := make([]store.RolloutAgent, 0, len(agents))
	for _, a := range agents {
		kind := rollouttarget.AgentKindConnector
		if strings.HasPrefix(a, "gw_") {
			kind = rollouttarget.AgentKindGateway
		}
		in = append(in, store.RolloutAgent{ID: a, Kind: kind, VersionBefore: "0.1.0"})
	}
	_, err := store.ConfigTx(e.sys, e.db, func(tx *ent.Tx) ([]string, error) {
		_, err := store.QueueRolloutTargets(e.sys, tx, ro.ID, in)
		return []string{ro.ID}, err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// states are the agents' target states, in the order given.
func (e *rolloutJobEnv) states(agents ...string) []rollouttarget.State {
	e.t.Helper()
	out := make([]rollouttarget.State, 0, len(agents))
	for _, a := range agents {
		out = append(out, e.target(a).State)
	}
	return out
}

func (e *rolloutJobEnv) expect(want []rollouttarget.State, agents ...string) {
	e.t.Helper()
	got := e.states(agents...)
	for i := range want {
		if got[i] != want[i] {
			e.t.Errorf("the queue's states are %v, want %v", got, want)
			return
		}
	}
}

func (e *rolloutJobEnv) rolloutState(ro *ent.Rollout) *ent.Rollout {
	e.t.Helper()
	return e.db.Client().Rollout.GetX(e.sys, ro.ID)
}

// fail marks an agent's target as an agent reports a failure.
func (e *rolloutJobEnv) fail(agent string, state rollouttarget.State) {
	e.t.Helper()
	e.now = e.now.Add(time.Second)
	e.db.Client().RolloutTarget.UpdateOne(e.target(agent)).SetState(state).SetReason("it failed").SetUpdatedAt(e.now).ExecX(e.sys)
}

// silence makes an offered agent's last report older than the stall time; the store stamps
// updated_at with the wall clock, and the job's clock is the environment's.
func (e *rolloutJobEnv) silence(agent string, d time.Duration) {
	e.t.Helper()
	e.db.Client().RolloutTarget.UpdateOne(e.target(agent)).SetUpdatedAt(e.now.Add(-d)).ExecX(e.sys)
}

const (
	pending  = rollouttarget.StatePending
	offered  = rollouttarget.StateOffered
	updated  = rollouttarget.StateUpdated
	skipped  = rollouttarget.StateSkipped
	stalled  = rollouttarget.StateStalled
	rolledBk = rollouttarget.StateRolledBack
	refused  = rollouttarget.StateRefused
)

// TestEasyRollout_OneAtATime (D129): an easy rollout offers its release to one agent of its queue
// at a time, in the order of the queue, the next once the previous one runs it, and completes once
// every agent has had its turn.
func TestEasyRollout_OneAtATime(t *testing.T) {
	e := newRolloutJobEnv(t)
	// Queued against the order of their IDs, so that the queue, not the ID, decides.
	c, b, a := e.connector("c", "0.1.0", true), e.connector("b", "0.1.0", true), e.connector("a", "0.1.0", true)
	ro := e.easyRollout(a, b, c)

	e.run()
	e.expect([]rollouttarget.State{offered, pending, pending}, a, b, c)
	e.run()
	e.expect([]rollouttarget.State{offered, pending, pending}, a, b, c)

	e.setVersion(a, "0.2.0")
	e.run()
	e.expect([]rollouttarget.State{updated, offered, pending}, a, b, c)
	e.setVersion(b, "0.2.0")
	e.run()
	e.expect([]rollouttarget.State{updated, updated, offered}, a, b, c)
	if got := e.rolloutState(ro); got.State != rollout.StateRunning {
		t.Fatalf("the rollout is %s before its last agent is done", got.State)
	}
	e.setVersion(c, "0.2.0")
	e.run()
	if got := e.rolloutState(ro); got.State != rollout.StateCompleted || got.Active {
		t.Errorf("the rollout is %s active=%v, want completed", got.State, got.Active)
	}
}

// TestEasyRollout_SkipsAtOnce: agents that are offline at their turn, or that already run the
// release, are passed in the same run, so the next agent gets its turn without waiting; an agent
// whose policy declines the release is skipped and the queue moves on.
func TestEasyRollout_SkipsAtOnce(t *testing.T) {
	e := newRolloutJobEnv(t)
	off := e.connector("off", "0.1.0", false)
	done := e.connector("done", "0.2.0", true)
	notify := e.connector("notify", "0.1.0", true)
	last := e.connector("last", "0.1.0", true)
	ro := e.easyRollout(off, done, notify, last)

	e.run()
	e.expect([]rollouttarget.State{skipped, updated, offered, pending}, off, done, notify, last)
	if r := e.target(off).Reason; r == "" {
		t.Error("the offline agent was skipped without a reason")
	}
	rec := controller.NewUpdateRecorder(e.db, e.sys)
	rec.RecordUpdate(pki.Identity{ID: notify, Org: e.org},
		&agentv1.UpdateState{Version: "0.2.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_AVAILABLE})
	e.run()
	e.expect([]rollouttarget.State{skipped, updated, skipped, offered}, off, done, notify, last)
	if got := e.rolloutState(ro); got.State != rollout.StateRunning {
		t.Errorf("a declined offer changed the rollout to %s", got.State)
	}
}

// TestEasyRollout_FailureMovesOn (D129): a rollback, a refusal and a stall each mark their agent
// and the queue continues; an agent that updates in between starts the count of failures afresh,
// and a queue that ends in fewer failures in a row than the limit completes with them recorded.
func TestEasyRollout_FailureMovesOn(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b, c, d := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true),
		e.connector("c", "0.1.0", true), e.connector("d", "0.1.0", true)
	ro := e.easyRollout(a, b, c, d)

	e.run()
	e.fail(a, rolledBk)
	e.run()
	e.expect([]rollouttarget.State{rolledBk, offered, pending, pending}, a, b, c, d)
	e.fail(b, refused)
	e.run()
	e.expect([]rollouttarget.State{rolledBk, refused, offered, pending}, a, b, c, d)
	e.setVersion(c, "0.2.0")
	e.run()
	e.expect([]rollouttarget.State{rolledBk, refused, updated, offered}, a, b, c, d)

	// d stalls: the third failure, but not in a row.
	e.silence(d, controller.RolloutStallAfter)
	e.run()
	e.expect([]rollouttarget.State{rolledBk, refused, updated, stalled}, a, b, c, d)
	got := e.rolloutState(ro)
	if got.State != rollout.StateCompleted {
		t.Errorf("the rollout is %s %q, want completed with its failures recorded", got.State, got.PauseReason)
	}
}

// TestEasyRollout_FailuresInRowPause (D129): the third failure in a row pauses the rollout before
// the next agent is offered the release; resuming continues the queue, and the failures already
// seen do not pause it again.
func TestEasyRollout_FailuresInRowPause(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b, c, d := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true),
		e.connector("c", "0.1.0", true), e.connector("d", "0.1.0", true)
	ro := e.easyRollout(a, b, c, d)

	e.run()
	e.fail(a, rolledBk)
	e.run()
	e.fail(b, refused)
	e.run()
	e.silence(c, controller.RolloutStallAfter)
	e.run() // c stalls: the third failure in a row
	e.expect([]rollouttarget.State{rolledBk, refused, stalled, pending}, a, b, c, d)
	got := e.rolloutState(ro)
	if got.State != rollout.StatePaused || !strings.Contains(got.PauseReason, "3 agents in a row") {
		t.Fatalf("the rollout is %s %q, want paused after 3 failures in a row", got.State, got.PauseReason)
	}
	e.run()
	e.expect([]rollouttarget.State{rolledBk, refused, stalled, pending}, a, b, c, d)

	// An Instance Admin resumes it: the queue continues with d, and stays running.
	e.now = e.now.Add(time.Minute)
	e.db.Client().Rollout.UpdateOneID(ro.ID).SetState(rollout.StateRunning).SetPauseReason("").ExecX(e.sys)
	e.run()
	e.expect([]rollouttarget.State{rolledBk, refused, stalled, offered}, a, b, c, d)
	if got := e.rolloutState(ro); got.State != rollout.StateRunning {
		t.Errorf("the resumed rollout is %s %q, want running", got.State, got.PauseReason)
	}
}

// TestEasyRollout_StalledAgentUpdatesLater (D129): a stalled agent does not hold the queue, and
// counts as updated once it runs the release, whether the job sees its version or the agent
// reports the updater's outcome.
func TestEasyRollout_StalledAgentUpdatesLater(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b, c := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true), e.connector("c", "0.1.0", true)
	e.easyRollout(a, b, c)

	e.run()
	e.silence(a, controller.RolloutStallAfter-time.Second)
	e.run()
	e.expect([]rollouttarget.State{offered, pending}, a, b)
	e.silence(a, controller.RolloutStallAfter)
	e.run()
	e.expect([]rollouttarget.State{stalled, offered, pending}, a, b, c)

	e.setVersion(a, "0.2.0")
	e.run()
	e.expect([]rollouttarget.State{updated, offered}, a, b)

	// b stalls too, then its updater reports success.
	e.silence(b, controller.RolloutStallAfter)
	e.run()
	e.expect([]rollouttarget.State{stalled, offered}, b, c)
	rec := controller.NewUpdateRecorder(e.db, e.sys)
	id := pki.Identity{ID: b, Org: e.org}
	rec.RecordUpdate(id, &agentv1.UpdateState{Version: "0.2.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_STAGED})
	if s := e.target(b).State; s != stalled {
		t.Errorf("a stalled agent's staging report changed it to %s", s)
	}
	rec.RecordUpdate(id, &agentv1.UpdateState{Updater: &agentv1.UpdaterOutcome{
		Result: agentv1.UpdaterResult_UPDATER_RESULT_UPDATED, Version: "0.2.0"}})
	if s := e.target(b).State; s != updated {
		t.Errorf("a stalled agent whose updater reports success is %s, want updated", s)
	}
}

// TestEasyRollout_AgentGoesOffline: an agent that drops its session while it updates keeps its
// turn, since its restart drops the session, and is updated when it comes back on the release.
func TestEasyRollout_AgentGoesOffline(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true)
	e.easyRollout(a, b)
	e.run()
	e.db.Client().AgentSession.UpdateOneID(a).SetDisconnectedAt(e.now).ExecX(e.sys)
	e.now = e.now.Add(time.Minute)
	e.run()
	e.expect([]rollouttarget.State{offered, pending}, a, b)
	e.db.Client().AgentSession.UpdateOneID(a).ClearDisconnectedAt().SetAgentVersion("0.2.0").SetLastSeenAt(e.now).ExecX(e.sys)
	e.run()
	e.expect([]rollouttarget.State{updated, offered}, a, b)
}

// TestEasyRollout_AgentJoins (D129): an agent added while the rollout runs takes its turn after
// the agents queued before it, also once the queue had come to rest in that run.
func TestEasyRollout_AgentJoins(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true)
	ro := e.easyRollout(a)
	e.run()
	e.enqueue(ro, b)
	e.run()
	e.expect([]rollouttarget.State{offered, pending}, a, b)
	e.setVersion(a, "0.2.0")
	e.run()
	e.expect([]rollouttarget.State{updated, offered}, a, b)
	if got := e.rolloutState(ro); got.State != rollout.StateRunning {
		t.Errorf("the rollout is %s while an agent that joined updates", got.State)
	}
}

// TestEasyRollout_WaitsForMirror (D125): while the mirror does not hold the release, the agent
// whose turn it is waits, and nobody behind it is offered anything.
func TestEasyRollout_WaitsForMirror(t *testing.T) {
	e := newRolloutJobEnv(t)
	e.db.Client().Release.UpdateOne(e.rel).ClearMirroredAt().ExecX(e.sys)
	a, b := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true)
	e.easyRollout(a, b)
	e.run()
	e.expect([]rollouttarget.State{pending, pending}, a, b)
	e.db.Client().Release.UpdateOne(e.rel).SetMirroredAt(e.now).ExecX(e.sys)
	e.run()
	e.expect([]rollouttarget.State{offered, pending}, a, b)
}

// TestEasyRollout_GatewayDrains: a gateway in the queue drains before its offer and is enabled
// again once it is done, and the agent after it waits for it.
func TestEasyRollout_GatewayDrains(t *testing.T) {
	e := newRolloutJobEnv(t)
	gw := e.gateway("gw_00000000000000000000000001", "gw1", 1, true, true, "0.1.0")
	con := e.connector("con", "0.1.0", true)
	e.easyRollout(gw, con)
	e.run()
	if enabled := e.db.Client().Gateway.GetX(e.sys, gw).Enabled; enabled {
		t.Fatal("the gateway was not disabled to drain")
	}
	e.expect([]rollouttarget.State{pending, pending}, gw, con)
	e.now = e.now.Add(controller.RolloutDrainPeriod)
	e.run()
	e.expect([]rollouttarget.State{offered, pending}, gw, con)
	e.setVersion(gw, "0.2.0")
	e.run()
	e.expect([]rollouttarget.State{updated, offered}, gw, con)
	if enabled, at := e.db.Client().Gateway.GetX(e.sys, gw).Enabled, e.target(gw).DrainStartedAt; !enabled || at != nil {
		t.Errorf("the gateway is enabled=%v, drain %v, want enabled without a drain", enabled, at)
	}
}

// TestEasyRollout_Cancel: cancelling stops the queue; the outcome of the install that was under way
// is still recorded, and nobody else is offered the release.
func TestEasyRollout_Cancel(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true)
	ro := e.easyRollout(a, b)
	e.run()
	e.db.Client().Rollout.UpdateOneID(ro.ID).SetState(rollout.StateCancelled).ExecX(e.sys)
	controller.NewUpdateRecorder(e.db, e.sys).RecordUpdate(pki.Identity{ID: a, Org: e.org},
		&agentv1.UpdateState{Updater: &agentv1.UpdaterOutcome{Result: agentv1.UpdaterResult_UPDATER_RESULT_UPDATED, Version: "0.2.0"}})
	e.setVersion(a, "0.2.0")
	e.run()
	e.expect([]rollouttarget.State{updated, pending}, a, b)
	if got := e.rolloutState(ro); got.State != rollout.StateCancelled {
		t.Errorf("the cancelled rollout is %s", got.State)
	}
}

// TestEasyRollout_PausedByAdmin: a paused easy rollout offers the release to nobody, and records
// what the agent under way reports.
func TestEasyRollout_PausedByAdmin(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true)
	ro := e.easyRollout(a, b)
	e.run()
	e.db.Client().Rollout.UpdateOneID(ro.ID).SetState(rollout.StatePaused).ExecX(e.sys)
	controller.NewUpdateRecorder(e.db, e.sys).RecordUpdate(pki.Identity{ID: a, Org: e.org},
		&agentv1.UpdateState{Updater: &agentv1.UpdaterOutcome{Result: agentv1.UpdaterResult_UPDATER_RESULT_UPDATED, Version: "0.2.0"}})
	e.run()
	e.expect([]rollouttarget.State{updated, pending}, a, b)
	if got := e.rolloutState(ro); got.State != rollout.StatePaused {
		t.Errorf("the paused rollout is %s", got.State)
	}
}
