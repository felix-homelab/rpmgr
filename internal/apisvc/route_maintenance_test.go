// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
)

// TestRouteMaintenance (D88): an http route is created in maintenance or switched into it with
// its message, and its status says so unless it is disabled. Switching keeps its hostnames as
// they are, so it works while its domain is not verified, which a hostname change does not.
// The message is at most 500 characters, with line feeds as its only control characters, and
// other route types have no maintenance.
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
	if s := state(got.GetId()); s != rpmgrv1.RouteState_ROUTE_STATE_MAINTENANCE {
		t.Fatalf("status %v, want maintenance", s)
	}
	list, err := ada.rt.ListRoutes(ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org}))
	if err != nil || list.Msg.GetRoutes()[0].GetStatus().GetState() != rpmgrv1.RouteState_ROUTE_STATE_MAINTENANCE {
		t.Fatalf("the list: %v %v", list, err)
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
	if s := state(got.GetId()); s == rpmgrv1.RouteState_ROUTE_STATE_MAINTENANCE {
		t.Fatal("still maintenance")
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

	// Disabled wins over maintenance.
	if _, err := update(got.GetId(), []string{"enabled"}, func(r *rpmgrv1.Route) { r.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if s := state(got.GetId()); s != rpmgrv1.RouteState_ROUTE_STATE_DISABLED {
		t.Fatalf("disabled in maintenance: %v", s)
	}

	for name, msg := range map[string]string{
		"501 characters":      strings.Repeat("a", 501),
		"a carriage return":   "back\r\nsoon",
		"a tab":               "back\tsoon",
		"an escape character": "back \x1b[31msoon",
		"DEL":                 "back\x7f",
	} {
		if _, err := update(got.GetId(), []string{"http.maintenance_message"}, func(r *rpmgrv1.Route) { r.GetHttp().MaintenanceMessage = msg }); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
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
