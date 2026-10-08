// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
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

// TestWriteApplyStatus: every write that returns a revision returns its apply status too, at once
// by default; with Rpmgr-Wait-Applied it answers once the revision is applied, or when the wait
// is over with the state then; a malformed wait does not wait.
func TestWriteApplyStatus(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	epoch := e.db.Client().Instance.GetX(e.sys, 1).DbEpoch
	// No agent is online: nothing holds the revision.
	gw, err := ada.gw.CreateGateway(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayRequest{OrgId: org,
		Gateway: &rpmgrv1.Gateway{GatewayGroupId: group, Name: "gw1", TunnelEndpoints: []string{"gw1.example.com:443"}}}))
	if err != nil || gw.Msg.GetApplyStatus().GetState() != rpmgrv1.ApplyState_APPLY_STATE_APPLIED || gw.Msg.GetApplyStatus().GetAgentsTotal() != 0 {
		t.Fatalf("a write without online agents: %v %v", gw, err)
	}
	id := gw.Msg.GetGateway().GetId()
	e.db.Client().AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(e.clock).
		SetLastSeenAt(e.clock).ExecX(e.sys)
	e.db.Client().AgentState.Create().SetID(id).SetOrgID(org).SetAppliedDbEpoch(epoch).SetAppliedSeq(1).ExecX(e.sys)
	update := func(name, wait string) (*connect.Response[rpmgrv1.UpdateGatewayResponse], time.Duration, error) {
		req := connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: id, Name: name},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}}})
		if wait != "" {
			req.Header().Set(api.WaitHeader, wait)
		}
		start := time.Now()
		r, err := ada.gw.UpdateGateway(ctx, req)
		return r, time.Since(start), err
	}
	r, _, err := update("gw-a", "")
	if err != nil || r.Msg.GetApplyStatus().GetState() != rpmgrv1.ApplyState_APPLY_STATE_PENDING || r.Msg.GetApplyStatus().GetAgentsTotal() != 1 {
		t.Fatalf("a write the online gateway has not applied: %v %v", r, err)
	}
	if r, took, err := update("gw-b", "300ms"); err != nil || r.Msg.GetApplyStatus().GetState() != rpmgrv1.ApplyState_APPLY_STATE_PENDING ||
		took < 300*time.Millisecond {
		t.Fatalf("a wait that ends pending: %v after %v (%v)", r, took, err)
	}
	if r, took, err := update("gw-c", "bogus"); err != nil || took > 250*time.Millisecond || r.Msg.GetApplyStatus() == nil {
		t.Fatalf("a malformed wait: %v after %v (%v)", r, took, err)
	}
	go func() {
		time.Sleep(400 * time.Millisecond)
		e.db.Client().AgentState.UpdateOneID(id).SetAppliedSeq(1 << 40).ExecX(e.sys)
	}()
	r, took, err := update("gw-d", "5s")
	if err != nil || r.Msg.GetApplyStatus().GetState() != rpmgrv1.ApplyState_APPLY_STATE_APPLIED || r.Msg.GetApplyStatus().GetAgentsApplied() != 1 ||
		took < 400*time.Millisecond || took > 4*time.Second {
		t.Fatalf("a wait the gateway's apply ends: %v after %v (%v)", r, took, err)
	}
}

// events opens a WatchEvents stream and delivers its events on a channel until stop.
func events(t *testing.T, b *browser, org, token string) (<-chan *rpmgrv1.WatchEventsResponse, func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := b.st.WatchEvents(ctx, connect.NewRequest(&rpmgrv1.WatchEventsRequest{OrgId: org, ResumeToken: token}))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, done := make(chan *rpmgrv1.WatchEventsResponse, 16), make(chan error, 1)
	go func() {
		defer close(out)
		for stream.Receive() {
			out <- stream.Msg()
		}
		done <- stream.Err()
	}()
	t.Cleanup(cancel)
	// stop ends the stream from the client's side; an error is any other end.
	return out, func() error {
		cancel()
		if err := <-done; code(err) != connect.CodeCanceled {
			return err
		}
		return nil
	}
}

func next(t *testing.T, ch <-chan *rpmgrv1.WatchEventsResponse) *rpmgrv1.WatchEventsResponse {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("the stream ended")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return nil
}

// TestWatchEvents (docs/07-api.md, "Events and streaming"): the stream sends one event per
// revision of the org, in order, with what it changed and a resume token, and not another org's;
// a client that reconnects with its last token gets what it missed; a token of another database
// epoch gets a reset first; a token WatchEvents did not give is refused.
func TestWatchEvents(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	ch, stop := events(t, ada, org, "")
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := bob.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: orgB,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "b"}})); err != nil {
		t.Fatal(err)
	}
	pool, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20001}}))
	if err != nil {
		t.Fatal(err)
	}
	first, second := next(t, ch), next(t, ch)
	if !slices.Equal(first.GetChangedResources(), []string{gw.GetId()}) || !slices.Equal(second.GetChangedResources(), []string{pool.Msg.GetPortPool().GetId()}) ||
		second.GetRevision().GetSeq() <= first.GetRevision().GetSeq() || first.GetActor() == "" || first.GetResumeToken() == "" || first.GetReset_() {
		t.Fatalf("the org's events: %v, %v", first, second)
	}
	if err := stop(); err != nil {
		t.Fatalf("the stream ended with %v", err)
	}

	// Missed while disconnected, and delivered on resuming.
	missed, err := createGateway(ada, org, group, "gw2", "gw2.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	ch, stop = events(t, ada, org, second.GetResumeToken())
	if ev := next(t, ch); !slices.Equal(ev.GetChangedResources(), []string{missed.GetId()}) {
		t.Fatalf("the missed event: %v", ev)
	}
	_ = stop()

	other := base64.RawURLEncoding.EncodeToString([]byte("another-epoch/3"))
	ch, stop = events(t, ada, org, other)
	if ev := next(t, ch); !ev.GetReset_() || len(ev.GetChangedResources()) != 0 || ev.GetResumeToken() == "" {
		t.Fatalf("a token of another epoch: %v", ev)
	}
	_ = stop()

	stream, err := ada.st.WatchEvents(ctx, connect.NewRequest(&rpmgrv1.WatchEventsRequest{OrgId: org, ResumeToken: "not-a-token!"}))
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a malformed token: %v", err)
	}
}
