// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// rolloutJobEnv is a fleet, a release and one rollout for the job's tests.
type rolloutJobEnv struct {
	t     *testing.T
	db    *store.DB
	sys   context.Context
	org   string
	group string
	rel   *ent.Release
	now   time.Time
}

func newRolloutJobEnv(t *testing.T) *rolloutJobEnv {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	e := &rolloutJobEnv{t: t, db: db, sys: sys, org: storetest.Org(t, db, "org-a"), now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	c := db.Client()
	e.group = c.GatewayGroup.Create().SetOrgID(e.org).SetName("eu").SaveX(sys).ID
	e.rel = c.Release.Create().SetVersion("0.2.0").SetChannel("stable").SetManifestSeq(1).
		SetManifest([]byte(`{"seq":1,"version":"0.2.0"}`)).SetSignature([]byte("sig")).
		SetSigningKeyStatement([]byte("statement")).SetStatementSignature([]byte("sig")).SetSource("upload").SaveX(sys)
	return e
}

// connector adds a connector whose agent runs version and, if live, has a live session.
func (e *rolloutJobEnv) connector(name, version string, live bool) string {
	e.t.Helper()
	c := e.db.Client()
	con := c.Connector.Create().SetOrgID(e.org).SetName(name).SetSpiffeID("spiffe://t/" + name).SetPubkeySha256("k").SaveX(e.sys)
	e.session(con.ID, version, live)
	return con.ID
}

// gateway adds an enabled gateway of the environment's group and its session.
func (e *rolloutJobEnv) gateway(id, name string, slot int, enabled, live bool, version string) string {
	e.t.Helper()
	c := e.db.Client()
	gw := c.Gateway.Create().SetOrgID(e.org).SetGatewayGroupID(e.group).SetName(name).SetSlot(slot).
		SetTunnelEndpoints([]string{name + ".example:443"}).SetSpiffeID("spiffe://t/" + name).SetEnabled(enabled)
	if id != "" {
		gw.SetID(id)
	}
	row := gw.SaveX(e.sys)
	if row.ID != id && id != "" {
		e.t.Fatalf("gateway ID %s, want %s", row.ID, id)
	}
	e.session(row.ID, version, live)
	return row.ID
}

func (e *rolloutJobEnv) session(id, version string, live bool) {
	e.t.Helper()
	cs := e.db.Client().AgentSession.Create().SetID(id).SetOrgID(e.org).SetSessionEpoch(1).SetControllerNode("ctn_1").
		SetAgentVersion(version).SetLastSeenAt(e.now)
	if !live {
		cs.SetDisconnectedAt(e.now)
	}
	cs.SaveX(e.sys)
}

// setVersion records that the agent reconnected running version.
func (e *rolloutJobEnv) setVersion(id, version string) {
	e.t.Helper()
	e.db.Client().AgentSession.UpdateOneID(id).SetAgentVersion(version).SetLastSeenAt(e.now).ExecX(e.sys)
}

// rollout creates the one active rollout, with a target for each agent.
func (e *rolloutJobEnv) rollout(stage rollout.Stage, percentage int, canaries []string, agents map[string]rollouttarget.AgentKind) *ent.Rollout {
	e.t.Helper()
	c := e.db.Client()
	ro := c.Rollout.Create().SetReleaseID(e.rel.ID).SetCreatedBy("usr_admin").SetStage(stage).SetPercentage(percentage).SaveX(e.sys)
	for id, kind := range agents {
		t := c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(id).SetAgentKind(kind).
			SetBucket(store.RolloutBucket(id)).SetVersionBefore("0.1.0")
		for _, canary := range canaries {
			if canary == id {
				t.SetCanary(true)
			}
		}
		t.SaveX(e.sys)
	}
	return ro
}

// run runs one step of the job at the environment's clock.
func (e *rolloutJobEnv) run() {
	e.t.Helper()
	err := controller.RunRollout(e.sys, controller.RolloutOptions{DB: e.db, Now: func() time.Time { return e.now },
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *rolloutJobEnv) target(agent string) *ent.RolloutTarget {
	e.t.Helper()
	return e.db.Client().RolloutTarget.Query().Where(rollouttarget.AgentID(agent)).OnlyX(e.sys)
}

func (e *rolloutJobEnv) activeRollout() *ent.Rollout {
	e.t.Helper()
	return e.db.Client().Rollout.Query().Where(rollout.Active(true)).OnlyX(e.sys)
}

// TestRolloutJob_Stages (docs/04-security.md, "Over-the-air updates"; D121): the job offers the
// release to the canary agents only, skips an agent that is offline, waits for the agent to
// report the new version, offers the rest when the rollout reaches all, and completes when every
// target is at rest.
func TestRolloutJob_Stages(t *testing.T) {
	e := newRolloutJobEnv(t)
	canary := e.connector("canary", "0.1.0", true)
	offline := e.connector("offline", "0.1.0", false)
	rest := e.connector("rest", "0.1.0", true)
	ro := e.rollout(rollout.StageCanary, 0, []string{canary, offline}, map[string]rollouttarget.AgentKind{
		canary: rollouttarget.AgentKindConnector, offline: rollouttarget.AgentKindConnector, rest: rollouttarget.AgentKindConnector,
	})

	e.run()
	if s := e.target(canary).State; s != rollouttarget.StateOffered {
		t.Errorf("the canary is %s, want offered", s)
	}
	if s, reason := e.target(offline).State, e.target(offline).Reason; s != rollouttarget.StateSkipped || reason == "" {
		t.Errorf("the offline agent is %s %q, want skipped with a reason", s, reason)
	}
	if s := e.target(rest).State; s != rollouttarget.StatePending {
		t.Errorf("an agent outside the canary stage is %s, want pending", s)
	}

	// The canary runs the new version; the job records it and does not offer the next stage
	// until an Instance Admin advances the rollout.
	e.setVersion(canary, "0.2.0")
	e.run()
	if s := e.target(canary).State; s != rollouttarget.StateUpdated {
		t.Errorf("the canary is %s, want updated", s)
	}
	if s := e.target(rest).State; s != rollouttarget.StatePending {
		t.Errorf("before advancing, an agent outside the stage is %s, want pending", s)
	}

	e.db.Client().Rollout.UpdateOneID(ro.ID).SetStage(rollout.StageAll).SetPercentage(100).ExecX(e.sys)
	e.run()
	if s := e.target(rest).State; s != rollouttarget.StateOffered {
		t.Errorf("after advancing, the rest is %s, want offered", s)
	}

	e.setVersion(rest, "0.2.0")
	e.run()
	if s := e.target(rest).State; s != rollouttarget.StateUpdated {
		t.Errorf("the rest is %s, want updated", s)
	}
	got := e.db.Client().Rollout.GetX(e.sys, ro.ID)
	if got.State != rollout.StateCompleted || got.Active {
		t.Errorf("the rollout is %s active=%v, want completed and inactive", got.State, got.Active)
	}
}

// TestRolloutJob_Percentage: a percentage stage takes every agent whose bucket is below the
// percentage, and the canaries too.
func TestRolloutJob_Percentage(t *testing.T) {
	e := newRolloutJobEnv(t)
	agents := map[string]rollouttarget.AgentKind{}
	var low, high string
	for i := 0; i < 20; i++ {
		id := e.connector(string(rune('a'+i)), "0.1.0", true)
		agents[id] = rollouttarget.AgentKindConnector
		if store.RolloutBucket(id) < 50 && low == "" {
			low = id
		}
		if store.RolloutBucket(id) >= 50 && high == "" {
			high = id
		}
	}
	e.rollout(rollout.StagePercentage, 50, nil, agents)
	e.run()
	if s := e.target(low).State; s != rollouttarget.StateOffered {
		t.Errorf("an agent below the percentage is %s, want offered", s)
	}
	if s := e.target(high).State; s != rollouttarget.StatePending {
		t.Errorf("an agent above the percentage is %s, want pending", s)
	}
}

// TestRolloutJob_RollbackPauses: a rollback pauses the rollout with a reason and offers nothing
// more; a resume does not pause it again for the same target.
func TestRolloutJob_RollbackPauses(t *testing.T) {
	e := newRolloutJobEnv(t)
	a, b := e.connector("a", "0.1.0", true), e.connector("b", "0.1.0", true)
	ro := e.rollout(rollout.StageCanary, 0, []string{a}, map[string]rollouttarget.AgentKind{
		a: rollouttarget.AgentKindConnector, b: rollouttarget.AgentKindConnector})
	e.run()
	e.db.Client().RolloutTarget.UpdateOne(e.target(a)).SetState(rollouttarget.StateRolledBack).
		SetReason("the new binary never became ready").ExecX(e.sys)
	e.run()
	got := e.db.Client().Rollout.GetX(e.sys, ro.ID)
	if got.State != rollout.StatePaused || got.PauseReason == "" {
		t.Fatalf("the rollout is %s %q, want paused with a reason", got.State, got.PauseReason)
	}
	if s := e.target(b).State; s != rollouttarget.StatePending {
		t.Errorf("a paused rollout offered another agent: %s", s)
	}

	// An Instance Admin resumes it; the same rolled-back target must not pause it again.
	e.now = e.now.Add(time.Minute)
	e.db.Client().Rollout.UpdateOneID(ro.ID).SetState(rollout.StateRunning).SetPauseReason("").ExecX(e.sys)
	e.run()
	if got := e.db.Client().Rollout.GetX(e.sys, ro.ID); got.State != rollout.StateRunning {
		t.Errorf("the resumed rollout is %s, want running", got.State)
	}
}

// TestRolloutJob_StallPauses: an agent that reports nothing for 30 minutes is stalled and the
// rollout pauses.
func TestRolloutJob_StallPauses(t *testing.T) {
	e := newRolloutJobEnv(t)
	a := e.connector("a", "0.1.0", true)
	ro := e.rollout(rollout.StageCanary, 0, []string{a}, map[string]rollouttarget.AgentKind{a: rollouttarget.AgentKindConnector})
	e.run()
	e.db.Client().RolloutTarget.UpdateOne(e.target(a)).SetUpdatedAt(e.now.Add(-31 * time.Minute)).ExecX(e.sys)
	e.run()
	if s := e.target(a).State; s != rollouttarget.StateStalled {
		t.Errorf("the silent agent is %s, want stalled", s)
	}
	if got := e.db.Client().Rollout.GetX(e.sys, ro.ID); got.State != rollout.StatePaused {
		t.Errorf("the rollout is %s, want paused", got.State)
	}
}

// TestRolloutJob_GatewayDrain (D121): a gateway is drained before it is offered the release, one
// gateway per group at a time, and enabled again once its target is done.
func TestRolloutJob_GatewayDrain(t *testing.T) {
	e := newRolloutJobEnv(t)
	g1 := e.gateway("gw_00000000000000000000000001", "gw1", 1, true, true, "0.1.0")
	g2 := e.gateway("gw_00000000000000000000000002", "gw2", 2, true, true, "0.1.0")
	ro := e.rollout(rollout.StageCanary, 0, []string{g1, g2}, map[string]rollouttarget.AgentKind{
		g1: rollouttarget.AgentKindGateway, g2: rollouttarget.AgentKindGateway})

	e.run()
	if enabled := e.db.Client().Gateway.GetX(e.sys, g1).Enabled; enabled {
		t.Error("the first gateway was not disabled to drain")
	}
	if s, at := e.target(g1).State, e.target(g1).DrainStartedAt; s != rollouttarget.StatePending || at == nil {
		t.Errorf("the first gateway is %s, drain %v, want pending with a drain start", s, at)
	}
	if enabled := e.db.Client().Gateway.GetX(e.sys, g2).Enabled; !enabled {
		t.Error("a second gateway of the group was drained at the same time")
	}

	e.now = e.now.Add(controller.RolloutDrainPeriod - time.Second)
	e.run()
	if s := e.target(g1).State; s != rollouttarget.StatePending {
		t.Errorf("during the drain the first gateway is %s, want pending", s)
	}
	e.now = e.now.Add(2 * time.Second)
	e.run()
	if s := e.target(g1).State; s != rollouttarget.StateOffered {
		t.Errorf("after the drain the first gateway is %s, want offered", s)
	}
	if enabled := e.db.Client().Gateway.GetX(e.sys, g2).Enabled; !enabled {
		t.Error("the second gateway of the group was drained while the first still updates")
	}

	e.setVersion(g1, "0.2.0")
	e.run()
	if s := e.target(g1).State; s != rollouttarget.StateUpdated {
		t.Errorf("the first gateway is %s, want updated", s)
	}
	if enabled, at := e.db.Client().Gateway.GetX(e.sys, g1).Enabled, e.target(g1).DrainStartedAt; !enabled || at != nil {
		t.Errorf("the gateway is enabled=%v, drain %v, want enabled without a drain", enabled, at)
	}
	// The second gateway gets its turn after the first.
	if enabled := e.db.Client().Gateway.GetX(e.sys, g2).Enabled; enabled {
		t.Error("the second gateway never drained after the first finished")
	}
	if e.db.Client().Rollout.GetX(e.sys, ro.ID).State != rollout.StateRunning {
		t.Error("the rollout ended before the second gateway was done")
	}
}

// TestRolloutJob_AdminDisabledGateway: a gateway an operator disabled is skipped, never enabled
// again, and does not block a stage.
func TestRolloutJob_AdminDisabledGateway(t *testing.T) {
	e := newRolloutJobEnv(t)
	gw := e.gateway("gw_00000000000000000000000001", "gw1", 1, false, true, "0.1.0")
	ro := e.rollout(rollout.StageAll, 100, nil, map[string]rollouttarget.AgentKind{gw: rollouttarget.AgentKindGateway})
	e.run()
	if s, reason := e.target(gw).State, e.target(gw).Reason; s != rollouttarget.StateSkipped || reason == "" {
		t.Errorf("the disabled gateway is %s %q, want skipped with a reason", s, reason)
	}
	if enabled := e.db.Client().Gateway.GetX(e.sys, gw).Enabled; enabled {
		t.Error("the rollout enabled a gateway an operator disabled")
	}
	if got := e.db.Client().Rollout.GetX(e.sys, ro.ID); got.State != rollout.StateCompleted {
		t.Errorf("the rollout is %s, want completed", got.State)
	}
}

// TestRolloutJob_CancelledCleansDrain: a cancelled rollout enables the gateways it drained, and
// changes no other target.
func TestRolloutJob_CancelledCleansDrain(t *testing.T) {
	e := newRolloutJobEnv(t)
	gw := e.gateway("gw_00000000000000000000000001", "gw1", 1, true, true, "0.1.0")
	ro := e.rollout(rollout.StageCanary, 0, []string{gw}, map[string]rollouttarget.AgentKind{gw: rollouttarget.AgentKindGateway})
	e.run()
	e.db.Client().Rollout.UpdateOneID(ro.ID).SetState(rollout.StateCancelled).ExecX(e.sys)
	e.run()
	if enabled, at := e.db.Client().Gateway.GetX(e.sys, gw).Enabled, e.target(gw).DrainStartedAt; !enabled || at != nil {
		t.Errorf("the cancelled rollout left the gateway enabled=%v, drain %v", enabled, at)
	}
	if s := e.target(gw).State; s != rollouttarget.StatePending {
		t.Errorf("the cancelled rollout changed the target to %s", s)
	}
}

// TestRollout_AgentReports (docs/04-security.md, "Over-the-air updates", step 7): what an agent
// reports about the offered release becomes its target's state: staging, a rollback with its
// reason (which pauses the rollout), a policy that declines it, and reports about another version
// change nothing.
func TestRollout_AgentReports(t *testing.T) {
	e := newRolloutJobEnv(t)
	a := e.connector("a", "0.1.0", true)
	ro := e.rollout(rollout.StageCanary, 0, []string{a}, map[string]rollouttarget.AgentKind{a: rollouttarget.AgentKindConnector})
	e.run()
	rec := controller.NewUpdateRecorder(e.db, e.sys)
	id := pki.Identity{ID: a, Org: e.org}
	report := func(u *agentv1.UpdateState) { rec.RecordUpdate(id, u) }

	report(&agentv1.UpdateState{Version: "0.2.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_STAGED, Detail: "staged"})
	if s, reason := e.target(a).State, e.target(a).Reason; s != rollouttarget.StateStaged || reason != "staged" {
		t.Errorf("a staged report: %s %q", s, reason)
	}
	// A report about another version changes nothing.
	report(&agentv1.UpdateState{Version: "0.1.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_STAGED})
	if s := e.target(a).State; s != rollouttarget.StateStaged {
		t.Errorf("a report about another version changed the target to %s", s)
	}

	report(&agentv1.UpdateState{Updater: &agentv1.UpdaterOutcome{Result: agentv1.UpdaterResult_UPDATER_RESULT_ROLLED_BACK,
		Version: "0.2.0", Reason: "the service did not become ready"}})
	if s, reason := e.target(a).State, e.target(a).Reason; s != rollouttarget.StateRolledBack || reason != "the service did not become ready" {
		t.Errorf("a rollback report: %s %q", s, reason)
	}
	e.run()
	if got := e.db.Client().Rollout.GetX(e.sys, ro.ID); got.State != rollout.StatePaused {
		t.Errorf("the rollout is %s, want paused after the rollback", got.State)
	}
}

// TestRolloutUpdateState: the states an agent can report, including a policy that declines the
// release and a staging failure that is retried.
func TestRolloutUpdateState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cur   rollouttarget.State
		in    *agentv1.UpdateState
		state rollouttarget.State
		ok    bool
	}{
		{"updated", rollouttarget.StateStaged, &agentv1.UpdateState{Updater: &agentv1.UpdaterOutcome{
			Result: agentv1.UpdaterResult_UPDATER_RESULT_UPDATED, Version: "0.2.0"}}, rollouttarget.StateUpdated, true},
		{"rollback failed", rollouttarget.StateOffered, &agentv1.UpdateState{Updater: &agentv1.UpdaterOutcome{
			Result: agentv1.UpdaterResult_UPDATER_RESULT_ROLLBACK_FAILED, Version: "0.2.0"}}, rollouttarget.StateStalled, true},
		{"refused", rollouttarget.StateStaged, &agentv1.UpdateState{Updater: &agentv1.UpdaterOutcome{
			Result: agentv1.UpdaterResult_UPDATER_RESULT_REFUSED, Version: "0.2.0"}}, rollouttarget.StateRefused, true},
		{"notify", rollouttarget.StateOffered, &agentv1.UpdateState{Version: "0.2.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_AVAILABLE},
			rollouttarget.StateSkipped, true},
		{"declined", rollouttarget.StateOffered, &agentv1.UpdateState{Version: "0.2.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_DECLINED},
			rollouttarget.StateSkipped, true},
		{"downloading", rollouttarget.StateOffered, &agentv1.UpdateState{Version: "0.2.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_DOWNLOADING},
			rollouttarget.StateOffered, true},
		{"failed", rollouttarget.StateOffered, &agentv1.UpdateState{Version: "0.2.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_FAILED},
			rollouttarget.StateOffered, true},
		{"another version", rollouttarget.StateOffered, &agentv1.UpdateState{Version: "0.1.0", Phase: agentv1.UpdatePhase_UPDATE_PHASE_STAGED},
			rollouttarget.StateOffered, false},
		{"nothing", rollouttarget.StateOffered, &agentv1.UpdateState{}, rollouttarget.StateOffered, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _, ok := controller.RolloutUpdateState(tc.cur, tc.in, "0.2.0")
			if state != tc.state || ok != tc.ok {
				t.Errorf("got %s ok=%v, want %s ok=%v", state, ok, tc.state, tc.ok)
			}
		})
	}
}
