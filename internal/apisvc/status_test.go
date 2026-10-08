// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// TestApplyStatus (docs/07-api.md, "Writes and apply status"): a revision's status is derived
// over the org's online agents: an agent that runs it or a later revision applied it, one whose
// newest snapshot was rejected rejected it, with its reasons, one that did not answer for 30 s
// timed out, others are pending, also those of an older database epoch; offline agents are
// listed apart and do not hold the state; WatchApplyStatus streams the changes and ends at the
// final state.
func TestApplyStatus(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	epoch := e.db.Client().Instance.GetX(e.sys, 1).DbEpoch
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	live := func(id string) {
		e.db.Client().AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").
			SetConnectedAt(e.clock).SetLastSeenAt(e.clock).ExecX(e.sys)
	}
	state := func(id string, edit func(*ent.AgentStateCreate)) {
		c := e.db.Client().AgentState.Create().SetID(id).SetOrgID(org)
		edit(c)
		c.ExecX(e.sys)
	}
	pushedAt := e.clock.Add(-time.Second)
	live(gw.GetId())
	state(gw.GetId(), func(c *ent.AgentStateCreate) {
		c.SetAppliedDbEpoch(epoch).SetAppliedSeq(12).SetPushedDbEpoch(epoch).SetPushedSeq(12).SetPushedHash([]byte("h12")).SetAppliedHash([]byte("h12")).
			SetPushedAt(pushedAt)
	})
	slow := e.addConnector(t, org, "slow", nil).ID
	live(slow)
	state(slow, func(c *ent.AgentStateCreate) {
		c.SetAppliedDbEpoch(epoch).SetAppliedSeq(9).SetAppliedHash([]byte("h9")).SetPushedDbEpoch(epoch).SetPushedSeq(10).SetPushedHash([]byte("h10")).
			SetPushedAt(pushedAt)
	})
	bad := e.addConnector(t, org, "bad", nil).ID
	live(bad)
	state(bad, func(c *ent.AgentStateCreate) {
		c.SetAppliedDbEpoch(epoch).SetAppliedSeq(9).SetPushedDbEpoch(epoch).SetPushedSeq(10).SetPushedHash([]byte("h10b")).SetPushedAt(pushedAt).
			SetRejectedDbEpoch(epoch).SetRejectedSeq(10).SetRejectedHash([]byte("h10b")).
			SetLastRejection([]map[string]string{{"resource_id": "rt_1", "message": "port 5432 is also the port of rt_2"}})
	})
	away := e.addConnector(t, org, "away", nil).ID
	e.db.Client().AgentSession.Create().SetID(away).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(e.clock.Add(-time.Hour)).
		SetLastSeenAt(e.clock.Add(-time.Hour)).SetDisconnectedAt(e.clock.Add(-time.Hour)).ExecX(e.sys)
	never := e.addConnector(t, org, "never", nil).ID
	e.addConnector(t, org, "retired", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(e.clock) })

	get := func(seq int64, db string) *rpmgrv1.ApplyStatus {
		t.Helper()
		r, err := ada.st.GetApplyStatus(ctx, connect.NewRequest(&rpmgrv1.GetApplyStatusRequest{OrgId: org, Revision: &rpmgrv1.Revision{DbEpoch: db, Seq: seq}}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetApplyStatus()
	}
	st := get(10, epoch)
	if st.GetState() != rpmgrv1.ApplyState_APPLY_STATE_REJECTED || st.GetAgentsTotal() != 3 || st.GetAgentsApplied() != 1 || len(st.GetAgents()) != 2 ||
		len(st.GetOffline()) != 2 {
		t.Fatalf("a rejected revision: %v", st)
	}
	for _, a := range st.GetAgents() {
		switch a.GetAgentId() {
		case slow:
			if a.GetState() != rpmgrv1.ApplyState_APPLY_STATE_PENDING {
				t.Errorf("the slow agent: %v", a)
			}
		case bad:
			if a.GetState() != rpmgrv1.ApplyState_APPLY_STATE_REJECTED || len(a.GetErrors()) != 1 || a.GetErrors()[0].GetResourceId() != "rt_1" {
				t.Errorf("the rejecting agent: %v", a)
			}
		default:
			t.Errorf("an unexpected agent: %v", a)
		}
	}
	for _, o := range st.GetOffline() {
		if o.GetAgentId() == away && o.GetLastSeenTime() == nil || o.GetAgentId() == never && o.GetLastSeenTime() != nil {
			t.Errorf("an offline agent: %v", o)
		}
	}
	if st := get(9, epoch); st.GetState() != rpmgrv1.ApplyState_APPLY_STATE_APPLIED || st.GetAgentsApplied() != 3 {
		t.Fatalf("a revision every online agent applied: %v", st)
	}
	if st := get(9, "another-epoch"); st.GetState() != rpmgrv1.ApplyState_APPLY_STATE_PENDING || st.GetAgentsApplied() != 0 {
		t.Fatalf("a revision of another database epoch: %v", st)
	}

	// The rejecting agent applies a later snapshot; the slow one stays silent past 30 s.
	e.db.Client().AgentState.UpdateOneID(bad).SetAppliedSeq(11).SetAppliedHash([]byte("h11")).SetPushedSeq(11).SetPushedHash([]byte("h11")).ExecX(e.sys)
	if st := get(10, epoch); st.GetState() != rpmgrv1.ApplyState_APPLY_STATE_PENDING {
		t.Fatalf("after the rejecting agent moved on: %v", st)
	}
	e.clock = e.clock.Add(31 * time.Second)
	e.db.Client().AgentSession.Update().SetLastSeenAt(e.clock).ExecX(e.sys)
	if st := get(10, epoch); st.GetState() != rpmgrv1.ApplyState_APPLY_STATE_APPLY_TIMEOUT {
		t.Fatalf("an agent silent for 31 s: %v", st)
	}

	// A watch sees the slow agent apply it, and ends.
	e.db.Client().AgentState.UpdateOneID(slow).SetPushedAt(e.clock).ExecX(e.sys)
	stream, err := ada.st.WatchApplyStatus(ctx, connect.NewRequest(&rpmgrv1.WatchApplyStatusRequest{OrgId: org,
		Revision: &rpmgrv1.Revision{DbEpoch: epoch, Seq: 10}}))
	if err != nil {
		t.Fatal(err)
	}
	var seen []rpmgrv1.ApplyState
	for stream.Receive() {
		seen = append(seen, stream.Msg().GetApplyStatus().GetState())
		if len(seen) == 1 {
			e.db.Client().AgentState.UpdateOneID(slow).SetAppliedSeq(10).SetAppliedHash([]byte("h10")).ExecX(e.sys)
		}
	}
	if err := stream.Err(); err != nil || len(seen) != 2 || seen[0] != rpmgrv1.ApplyState_APPLY_STATE_PENDING ||
		seen[1] != rpmgrv1.ApplyState_APPLY_STATE_APPLIED {
		t.Fatalf("the watch saw %v (%v)", seen, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := vwr.st.GetApplyStatus(ctx, connect.NewRequest(&rpmgrv1.GetApplyStatusRequest{OrgId: org,
		Revision: &rpmgrv1.Revision{DbEpoch: epoch, Seq: 10}})); err != nil {
		t.Fatalf("a Viewer reads: %v", err)
	}
}
