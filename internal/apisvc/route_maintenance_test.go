// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentstate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
)

// TestRouteMaintenance (D88): an http route is created in maintenance or switched into it with
// its message. Switching keeps its hostnames as they are, so it works while its domain is not
// verified, which a hostname change does not.
// The message is at most 500 characters, with line feeds as its only control characters and no
// bidirectional embedding, override or isolate, and other route types have no maintenance.
func TestRouteMaintenance(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	claim := e.verified(t, org, "example.com", true)
	web := httpRoute("web", group, "app.example.com")
	web.GetHttp().Maintenance, web.GetHttp().MaintenanceMessage = true, "Back at 18:00.\nSorry."
	got, err := createRoute(ada, org, web, "")
	if err != nil || !got.GetHttp().GetMaintenance() || got.GetHttp().GetMaintenanceMessage() != "Back at 18:00.\nSorry." {
		t.Fatalf("a route created in maintenance: %v %v", got, err)
	}
	state := func(id string) rpmgrv1.RouteState {
		t.Helper()
		r, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetRoute().GetStatus().GetState()
	}
	// No gateway can answer for it: the group has none (TestRouteStatus_Maintenance has them).
	if s := state(got.GetId()); s != rpmgrv1.RouteState_ROUTE_STATE_UNAVAILABLE {
		t.Fatalf("status %v without a gateway, want unavailable", s)
	}

	// update sends the route as it is with change applied, as the API validates the whole message.
	update := func(id string, mask []string, change func(r *rpmgrv1.Route)) (*rpmgrv1.Route, error) {
		read, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
		if err != nil {
			return nil, err
		}
		in := read.Msg.GetRoute()
		in.Status = nil
		change(in)
		r, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: in, UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRoute(), nil
	}
	hostnames := e.db.Client().RouteHostname.Query().Where(routehostname.RouteID(got.GetId())).IDsX(e.sys)
	// The domain claim lapses: maintenance still switches, a hostname change is refused.
	e.db.Client().Domain.UpdateOneID(claim).SetStatus(domain.StatusPending).ExecX(e.sys)
	up, err := update(got.GetId(), []string{"http.maintenance"}, func(r *rpmgrv1.Route) { r.GetHttp().Maintenance = false })
	if err != nil || up.GetHttp().GetMaintenance() || up.GetHttp().GetMaintenanceMessage() != "Back at 18:00.\nSorry." ||
		up.GetHttp().GetHostnames()[0] != "app.example.com" {
		t.Fatalf("out of maintenance: %v %v", up, err)
	}
	up, err = update(got.GetId(), []string{"http.maintenance", "http.maintenance_message"}, func(r *rpmgrv1.Route) {
		r.GetHttp().Maintenance, r.GetHttp().MaintenanceMessage = true, strings.Repeat("é", 500)
	})
	if err != nil || !up.GetHttp().GetMaintenance() || up.GetHttp().GetMaintenanceMessage() != strings.Repeat("é", 500) {
		t.Fatalf("back into maintenance with 500 characters: %v %v", up, err)
	}
	if again := e.db.Client().RouteHostname.Query().Where(routehostname.RouteID(got.GetId())).IDsX(e.sys); len(again) != 1 || again[0] != hostnames[0] {
		t.Fatalf("hostname rows %v, want %v kept", again, hostnames)
	}
	if _, err := update(got.GetId(), []string{"http.maintenance", "http.path_prefix"}, func(r *rpmgrv1.Route) {
		r.GetHttp().Maintenance, r.GetHttp().PathPrefix = false, "/x"
	}); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("maintenance with a path change under a lapsed claim: %v", err)
	}
	e.db.Client().Domain.UpdateOneID(claim).SetStatus(domain.StatusVerified).ExecX(e.sys)

	for name, msg := range map[string]string{
		"501 characters":           strings.Repeat("a", 501),
		"a carriage return":        "back\r\nsoon",
		"a tab":                    "back\tsoon",
		"an escape character":      "back \x1b[31msoon",
		"DEL":                      "back\x7f",
		"a C1 control (CSI)":       "back \u009b31msoon",
		"NEL":                      "back\u0085soon",
		"a right-to-left override": "back \u202esoon",
		"an isolate":               "back \u2067soon\u2069",
	} {
		if _, err := update(got.GetId(), []string{"http.maintenance_message"}, func(r *rpmgrv1.Route) { r.GetHttp().MaintenanceMessage = msg }); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Marks for right-to-left text, which turn nothing around, and other scripts pass.
	if up, err := update(got.GetId(), []string{"http.maintenance_message"}, func(r *rpmgrv1.Route) {
		r.GetHttp().MaintenanceMessage = "\u05e9\u05dc\u05d5\u05dd\u200f 18:00 – zurück um 18 Uhr"
	}); err != nil || !strings.HasSuffix(up.GetHttp().GetMaintenanceMessage(), "18 Uhr") {
		t.Fatalf("right-to-left marks: %v %v", up, err)
	}

	// Other route types have no maintenance.
	db, err := createRoute(ada, org, passthroughRoute("db", group, "db.example.com"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, PortPool: &rpmgrv1.PortPool{
		GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	ssh, err := createRoute(ada, org, tcpRoute("ssh", group, 0), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{db.GetId(), ssh.GetId()} {
		if r, err := update(id, []string{"http.maintenance"}, func(r *rpmgrv1.Route) {}); code(err) != connect.CodeInvalidArgument {
			t.Errorf("maintenance of %s: %v %v", id, r, err)
		}
	}
}

// runNewest makes agents online, with the org's newest revision applied.
func runNewest(t *testing.T, e *env, org string, ids ...string) {
	t.Helper()
	c := e.db.Client()
	epoch := c.Instance.GetX(e.sys, 1).DbEpoch
	seq := c.ConfigRevision.Query().Order(ent.Desc(configrevision.FieldID)).FirstX(e.sys).ID
	for _, id := range ids {
		_, _ = c.AgentSession.Delete().Where(agentsession.ID(id)).Exec(e.sys)
		_, _ = c.AgentState.Delete().Where(agentstate.ID(id)).Exec(e.sys)
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(e.clock).
			SetLastSeenAt(e.clock).ExecX(e.sys)
		c.AgentState.Create().SetID(id).SetOrgID(org).SetAppliedDbEpoch(epoch).SetAppliedSeq(seq).SetAppliedHash([]byte("h")).
			SetPushedDbEpoch(epoch).SetPushedSeq(seq).SetPushedHash([]byte("h")).SetPushedAt(e.clock).ExecX(e.sys)
	}
}

// TestRouteStatus_Maintenance (docs/06-data-model.md, "Derived route status"): an http route in
// maintenance is maintenance while an online gateway of its group reports it ready, whatever its
// targets are, and otherwise unavailable, as with no gateway, every gateway offline or reporting
// it not ready; disabled, error and pending come first.
func TestRouteStatus_Maintenance(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	e.verified(t, org, "example.com", true)
	var gws []string
	for _, name := range []string{"gw1", "gw2"} {
		gw, err := createGateway(ada, org, group, name, name+".example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		gws = append(gws, gw.GetId())
	}
	empty, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "empty"}}))
	if err != nil {
		t.Fatal(err)
	}
	create := func(name, group string) string {
		r := httpRoute(name, group, name+".example.com")
		r.GetHttp().Maintenance = true
		got, err := createRoute(ada, org, r, "")
		if err != nil {
			t.Fatal(err)
		}
		return got.GetId()
	}
	web, lone := create("web", group), create("lone", empty.Msg.GetGatewayGroup().GetId())
	runNewest(t, e, org, gws...)
	status := func(id string) *rpmgrv1.RouteStatus {
		t.Helper()
		r, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetRoute().GetStatus()
	}
	const (
		maintenance = rpmgrv1.RouteState_ROUTE_STATE_MAINTENANCE
		unavailable = rpmgrv1.RouteState_ROUTE_STATE_UNAVAILABLE
	)
	if st := status(web); st.GetState() != maintenance || st.GetGatewaysTotal() != 2 || st.GetTargetsTotal() != 0 {
		t.Fatalf("online gateways, no target: %v", st)
	}
	list, err := ada.rt.ListRoutes(ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list.Msg.GetRoutes() {
		if want := map[string]rpmgrv1.RouteState{web: maintenance, lone: unavailable}[r.GetId()]; r.GetStatus().GetState() != want {
			t.Errorf("listed %s: %v, want %v", r.GetName(), r.GetStatus().GetState(), want)
		}
	}

	// One gateway reports it not ready, the other is offline: no one answers.
	c.ResourceStatus.Create().SetOrgID(org).SetAgentID(gws[0]).SetResourceID(web).SetReason("NOT_READY_REASON_ENVIRONMENT").
		SetDetail("certificate not loaded").SetSince(e.clock).ExecX(e.sys)
	c.AgentSession.UpdateOneID(gws[1]).SetDisconnectedAt(e.clock).ExecX(e.sys)
	if st := status(web); st.GetState() != unavailable {
		t.Fatalf("no gateway answers: %v", st)
	}
	c.AgentSession.UpdateOneID(gws[1]).ClearDisconnectedAt().ExecX(e.sys)
	if st := status(web); st.GetState() != maintenance || st.GetGatewaysServing() != 0 {
		t.Fatalf("one gateway answers again: %v", st)
	}

	// A change not applied yet is pending; one a gateway rejected is an error; disabled is disabled.
	r, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: &rpmgrv1.Route{Id: web, Description: "docs"},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"description"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if st := status(web); st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_PENDING {
		t.Fatalf("a change not applied: %v", st)
	}
	seq := r.Msg.GetRevision().GetSeq()
	epoch := c.Instance.GetX(e.sys, 1).DbEpoch
	c.AgentState.UpdateOneID(gws[1]).SetPushedSeq(seq).SetPushedHash([]byte("new")).SetPushedAt(e.clock).SetRejectedDbEpoch(epoch).
		SetRejectedSeq(seq).SetRejectedHash([]byte("new")).SetLastRejection([]map[string]string{{"resource_id": web, "message": "no"}}).ExecX(e.sys)
	c.AgentState.UpdateOneID(gws[0]).SetAppliedSeq(seq).SetAppliedHash([]byte("new")).SetPushedSeq(seq).SetPushedHash([]byte("new")).ExecX(e.sys)
	if st := status(web); st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_ERROR {
		t.Fatalf("a rejected change: %v", st)
	}
	if _, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: &rpmgrv1.Route{Id: web},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}})); err != nil {
		t.Fatal(err)
	}
	if st := status(web); st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_DISABLED {
		t.Fatalf("disabled in maintenance: %v", st)
	}
}
