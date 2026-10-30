// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// addAlert stores an alert of org ("" for an instance alert) in state.
func (e *env) addAlert(org, kind, subject string, state alert.State) string {
	c := e.db.Client().Alert.Create().SetKind(kind).SetSubjectType("gateway").SetSubjectID("gw_"+subject).
		SetSubjectName(subject).SetState(state).SetSince(time.Unix(1_700_000_000, 0))
	if org != "" {
		c.SetOrgID(org)
	}
	if state != alert.StatePending {
		c.SetFiredAt(time.Unix(1_700_000_300, 0))
	}
	if state == alert.StateResolved {
		c.SetResolvedAt(time.Unix(1_700_000_600, 0))
	}
	return c.SaveX(e.sys).ID
}

func alertIDs(as []*rpmgrv1.Alert) []string {
	var ids []string
	for _, a := range as {
		ids = append(ids, a.GetId())
	}
	return ids
}

// TestListAlerts (#960): the firing alerts of the org, with their subject and since; resolved and
// pending ones are not in the default list but are with their state; another org's alerts and the
// instance's are never listed; an org without alerts gets an empty list; paging and a forged
// token behave as in the other lists.
func TestListAlerts(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	other := storetest.Org(t, e.db, "org-b")

	l, err := ada.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: org}))
	if err != nil || len(l.Msg.GetAlerts()) != 0 || l.Msg.GetNextPageToken() != "" {
		t.Fatalf("no alerts: %v %v", l, err)
	}

	first := e.addAlert(org, "agent_offline", "edge-1", alert.StateFiring)
	second := e.addAlert(org, "clock_skew", "edge-2", alert.StateFiring)
	pending := e.addAlert(org, "agent_offline", "edge-3", alert.StatePending)
	resolved := e.addAlert(org, "agent_offline", "edge-4", alert.StateResolved)
	e.addAlert(other, "agent_offline", "theirs", alert.StateFiring)
	e.addAlert("", "revocation_log_on_host", "instance", alert.StateFiring)

	l, err = ada.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	got := l.Msg.GetAlerts()
	if len(got) != 2 || got[0].GetId() != first || got[1].GetId() != second {
		t.Fatalf("the default list is the two firing alerts of the org: %v", alertIDs(got))
	}
	a := got[0]
	if a.GetKind() != "agent_offline" || a.GetSubjectType() != "gateway" || a.GetSubjectName() != "edge-1" ||
		a.GetState() != rpmgrv1.AlertState_ALERT_STATE_FIRING || a.GetSince().AsTime().Unix() != 1_700_000_000 ||
		a.GetFiredAt() == nil || a.GetResolvedAt() != nil {
		t.Errorf("the alert: %v", a)
	}

	for state, want := range map[rpmgrv1.AlertState]string{
		rpmgrv1.AlertState_ALERT_STATE_PENDING:  pending,
		rpmgrv1.AlertState_ALERT_STATE_RESOLVED: resolved,
	} {
		r, err := ada.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: org, State: state}))
		if err != nil || len(r.Msg.GetAlerts()) != 1 || r.Msg.GetAlerts()[0].GetId() != want || r.Msg.GetAlerts()[0].GetState() != state {
			t.Errorf("state %v: %v %v", state, r, err)
		}
	}

	p1, err := ada.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: org, PageSize: 1}))
	if err != nil || len(p1.Msg.GetAlerts()) != 1 || p1.Msg.GetNextPageToken() == "" {
		t.Fatalf("page 1: %v %v", p1, err)
	}
	p2, err := ada.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: org, PageSize: 1, PageToken: p1.Msg.GetNextPageToken()}))
	if err != nil || len(p2.Msg.GetAlerts()) != 1 || p2.Msg.GetAlerts()[0].GetId() != second || p2.Msg.GetNextPageToken() != "" {
		t.Fatalf("page 2: %v %v", p2, err)
	}
	bad := []*rpmgrv1.ListAlertsRequest{
		{OrgId: org, PageToken: "forged"},
		{OrgId: org, PageSize: -1},
		{OrgId: org, State: rpmgrv1.AlertState(99)},
		{},
	}
	for _, r := range bad {
		if _, err := ada.st.ListAlerts(ctx, connect.NewRequest(r)); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%v: %v", r, err)
		}
	}

	// An alert that resolves leaves the default list.
	e.db.Client().Alert.UpdateOneID(first).SetState(alert.StateResolved).SetResolvedAt(time.Now()).ExecX(e.sys)
	l, _ = ada.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: org}))
	if ids := alertIDs(l.Msg.GetAlerts()); len(ids) != 1 || ids[0] != second {
		t.Errorf("after resolving: %v", ids)
	}
}

// TestListAlerts_Roles (#960): a Viewer reads the org's alerts as an Owner does, and nobody reads
// another org's; the instance alerts are for the Instance Admin only.
func TestListAlerts_Roles(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	other := storetest.Org(t, e.db, "org-b")
	mine := e.addAlert(org, "agent_offline", "edge-1", alert.StateFiring)
	theirs := e.addAlert(other, "agent_offline", "theirs", alert.StateFiring)
	inst := e.addAlert("", "revocation_log_on_host", "instance", alert.StateFiring)

	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	viewer, _ := e.join(t, ada, org, "viewer@example.com", "viewer")
	l, err := viewer.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: org}))
	if err != nil || len(l.Msg.GetAlerts()) != 1 || l.Msg.GetAlerts()[0].GetId() != mine {
		t.Fatalf("a Viewer lists: %v %v", l, err)
	}
	if _, err := viewer.st.ListAlerts(ctx, connect.NewRequest(&rpmgrv1.ListAlertsRequest{OrgId: other})); code(err) == 0 {
		t.Errorf("a member of one org lists the alerts of another (%s)", theirs)
	}
	if _, err := viewer.st.ListInstanceAlerts(ctx, connect.NewRequest(&rpmgrv1.ListInstanceAlertsRequest{})); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer lists the instance alerts: %v", err)
	}
	bob, _ := e.addOwner(t, org, "bob@example.com")
	if _, err := bob.st.ListInstanceAlerts(ctx, connect.NewRequest(&rpmgrv1.ListInstanceAlertsRequest{})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an org Owner lists the instance alerts: %v", err)
	}

	il, err := ada.st.ListInstanceAlerts(ctx, connect.NewRequest(&rpmgrv1.ListInstanceAlertsRequest{}))
	if err != nil || len(il.Msg.GetAlerts()) != 1 || il.Msg.GetAlerts()[0].GetId() != inst {
		t.Fatalf("the Instance Admin lists: %v %v", il, err)
	}
	if il.Msg.GetAlerts()[0].GetKind() != "revocation_log_on_host" {
		t.Errorf("the instance alert: %v", il.Msg.GetAlerts()[0])
	}
	e.db.Client().Alert.UpdateOneID(inst).SetState(alert.StateResolved).SetResolvedAt(time.Now()).ExecX(e.sys)
	il, _ = ada.st.ListInstanceAlerts(ctx, connect.NewRequest(&rpmgrv1.ListInstanceAlertsRequest{}))
	if len(il.Msg.GetAlerts()) != 0 {
		t.Errorf("a resolved instance alert is listed: %v", il.Msg.GetAlerts())
	}
	if _, err := ada.st.ListInstanceAlerts(ctx, connect.NewRequest(&rpmgrv1.ListInstanceAlertsRequest{PageToken: "forged"})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a forged page token: %v", err)
	}
}
