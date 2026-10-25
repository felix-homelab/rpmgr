// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
)

// TestRouteStatus (docs/06-data-model.md, "Derived route status"): a route is ready when every
// enabled target's connector is online and reports it ready, and every enabled gateway of its group
// is online, reports it ready and has a data session with the connector of a ready target;
// degraded when only some are; unavailable when no target is ready or no gateway serves it;
// pending while an online agent of it has not applied its latest change, its own or a target's;
// error when one rejected that; disabled when it is not enabled. Offline agents hold nothing, and
// another route's change leaves a route alone.
func TestRouteStatus(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	epoch := c.Instance.GetX(e.sys, 1).DbEpoch
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	var gws []string
	for _, name := range []string{"gw1", "gw2"} {
		gw, err := createGateway(ada, org, group, name, name+".example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		gws = append(gws, gw.GetId())
	}
	c1, c2 := e.addConnector(t, org, "c1", nil).ID, e.addConnector(t, org, "c2", nil).ID
	route := func(rt *rpmgrv1.Route) string {
		got, err := createRoute(ada, org, rt, "")
		if err != nil {
			t.Fatal(err)
		}
		return got.GetId()
	}
	pg, other := route(tcpRoute("pg", group, 20001)), route(tcpRoute("other", group, 20002))
	offID := route(tcpRoute("off", group, 20003))
	if _, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: &rpmgrv1.Route{Id: offID},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}})); err != nil {
		t.Fatal(err)
	}
	var targets []*rpmgrv1.RouteTarget
	for _, tg := range []struct{ route, connector string }{{pg, c1}, {pg, c2}, {other, c1}} {
		r, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: tg.route,
			Target: addressTarget(tg.connector, "10.0.0.5", 5432)}))
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, r.Msg.GetTarget())
	}

	// Every agent is online, runs the newest revision and has its data sessions.
	newest := func() int64 { return c.ConfigRevision.Query().Order(ent.Desc(configrevision.FieldID)).FirstX(e.sys).ID }
	applied := newest()
	for _, id := range append(slices.Clone(gws), c1, c2) {
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(e.clock).
			SetLastSeenAt(e.clock).ExecX(e.sys)
		c.AgentState.Create().SetID(id).SetOrgID(org).SetAppliedDbEpoch(epoch).SetAppliedSeq(applied).SetAppliedHash([]byte("h")).
			SetPushedDbEpoch(epoch).SetPushedSeq(applied).SetPushedHash([]byte("h")).SetPushedAt(e.clock).ExecX(e.sys)
		for _, gw := range gws {
			if id == c1 || id == c2 {
				c.DataSession.Create().SetOrgID(org).SetGatewayID(gw).SetConnectorID(id).SetTransport("quic").SetEstablishedAt(e.clock).
					SetReportedAt(e.clock).ExecX(e.sys)
			}
		}
	}
	status := func(id string) *rpmgrv1.RouteStatus {
		t.Helper()
		r, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetRoute().GetStatus()
	}
	notServing := func(st *rpmgrv1.RouteStatus) map[string]string {
		out := map[string]string{}
		for _, n := range st.GetNotServing() {
			out[n.GetId()] = n.GetReason()
		}
		return out
	}
	const (
		ready       = rpmgrv1.RouteState_ROUTE_STATE_READY
		degraded    = rpmgrv1.RouteState_ROUTE_STATE_DEGRADED
		unavailable = rpmgrv1.RouteState_ROUTE_STATE_UNAVAILABLE
		pending     = rpmgrv1.RouteState_ROUTE_STATE_PENDING
	)
	if st := status(pg); st.GetState() != ready || st.GetTargetsTotal() != 2 || st.GetTargetsReady() != 2 || st.GetGatewaysTotal() != 2 ||
		st.GetGatewaysServing() != 2 || len(st.GetNotServing()) != 0 {
		t.Fatalf("every agent serves it: %v", st)
	}
	list, err := ada.rt.ListRoutes(ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list.Msg.GetRoutes() {
		want := map[string]rpmgrv1.RouteState{pg: ready, other: ready, offID: rpmgrv1.RouteState_ROUTE_STATE_DISABLED}[r.GetId()]
		if r.GetStatus().GetState() != want {
			t.Errorf("listed route %s: %v, want %v", r.GetName(), r.GetStatus(), want)
		}
	}

	// A connector's local policy blocks its target, then a gateway goes offline.
	c.ResourceStatus.Create().SetOrgID(org).SetAgentID(c2).SetResourceID(pg).SetReason("NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY").
		SetDetail("10.0.0.5:5432").SetSince(e.clock).ExecX(e.sys)
	st := status(pg)
	if st.GetState() != degraded || st.GetTargetsReady() != 1 || len(st.GetNotServing()) != 1 || st.GetNotServing()[0].GetId() != targets[1].GetId() ||
		st.GetNotServing()[0].GetReason() != "BLOCKED_BY_LOCAL_POLICY" || st.GetNotServing()[0].GetDetail() != "10.0.0.5:5432" {
		t.Fatalf("a blocked target: %v", st)
	}
	c.AgentSession.UpdateOneID(gws[1]).SetDisconnectedAt(e.clock).ExecX(e.sys)
	if st := status(pg); st.GetState() != degraded || st.GetGatewaysServing() != 1 || notServing(st)[gws[1]] != "OFFLINE" {
		t.Fatalf("an offline gateway: %v", st)
	}
	// Without a data session to the ready target's connector, the other gateway serves nothing.
	c.DataSession.Delete().Where(datasession.GatewayID(gws[0]), datasession.ConnectorID(c1)).ExecX(e.sys)
	if st := status(pg); st.GetState() != unavailable || st.GetGatewaysServing() != 0 || notServing(st)[gws[0]] != "NO_DATA_SESSION" {
		t.Fatalf("no data session: %v", st)
	}
	c.AgentSession.UpdateOneID(c1).SetDisconnectedAt(e.clock).ExecX(e.sys)
	if st := status(pg); st.GetState() != unavailable || st.GetTargetsReady() != 0 || notServing(st)[targets[0].GetId()] != "OFFLINE" ||
		notServing(st)[gws[0]] != "" {
		t.Fatalf("no ready target: %v", st)
	}
	c.AgentSession.Update().Where(agentsession.IDIn(gws[1], c1)).ClearDisconnectedAt().ExecX(e.sys)
	c.ResourceStatus.Delete().Where(resourcestatus.AgentID(c2)).ExecX(e.sys)
	if st := status(pg); st.GetState() != ready || st.GetGatewaysServing() != 2 {
		t.Fatalf("back online, the first gateway through the second connector: %v", st)
	}

	// A change of a target is pending on its connector and the gateways, but not for the route
	// that it does not touch; a rejection of it is an error.
	r, err := ada.rt.UpdateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteTargetRequest{Target: &rpmgrv1.RouteTarget{Id: targets[1].GetId(),
		Weight: 5}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"weight"}}}))
	if err != nil {
		t.Fatal(err)
	}
	seq := r.Msg.GetRevision().GetSeq()
	if st := status(pg); st.GetState() != pending {
		t.Fatalf("a change not applied yet: %v", st)
	}
	if st := status(other); st.GetState() == pending {
		t.Fatalf("another route's change: %v", st)
	}
	push := func(id string, edit func(*ent.AgentStateUpdateOne)) {
		u := c.AgentState.UpdateOneID(id).SetPushedSeq(seq).SetPushedHash([]byte("new")).SetPushedAt(e.clock)
		edit(u)
		u.ExecX(e.sys)
	}
	for _, id := range append(slices.Clone(gws), c1, c2) {
		push(id, func(u *ent.AgentStateUpdateOne) { u.SetAppliedSeq(seq).SetAppliedHash([]byte("new")) })
	}
	push(gws[0], func(u *ent.AgentStateUpdateOne) {
		u.SetAppliedSeq(applied).SetAppliedHash([]byte("h")).SetRejectedDbEpoch(epoch).SetRejectedSeq(seq).SetRejectedHash([]byte("new")).
			SetLastRejection([]map[string]string{{"resource_id": pg, "message": "port 20001 is taken"}})
	})
	st = status(pg)
	if st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_ERROR || len(st.GetRejections()) != 1 || st.GetRejections()[0].GetAgentId() != gws[0] ||
		len(st.GetRejections()[0].GetErrors()) != 1 || st.GetRejections()[0].GetErrors()[0].GetMessage() != "port 20001 is taken" {
		t.Fatalf("a rejected change: %v", st)
	}
	// An offline agent that has not applied it holds nothing.
	c.AgentSession.UpdateOneID(gws[0]).SetDisconnectedAt(e.clock).ExecX(e.sys)
	if st := status(pg); st.GetState() != degraded || len(st.GetRejections()) != 0 || st.GetGatewaysServing() != 1 {
		t.Fatalf("the rejecting gateway offline: %v", st)
	}
	c.AgentSession.UpdateOneID(gws[0]).ClearDisconnectedAt().ExecX(e.sys)

	// With fewer revisions read than the agents are behind, a change not read counts as the oldest
	// one read: the agents that did not apply that are pending.
	push(gws[0], func(u *ent.AgentStateUpdateOne) { u.SetAppliedSeq(seq).SetAppliedHash([]byte("new")) })
	for _, name := range []string{"x1", "x2"} {
		if _, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
			GatewayGroup: &rpmgrv1.GatewayGroup{Name: name}})); err != nil {
			t.Fatal(err)
		}
	}
	if st := status(pg); st.GetState() != ready {
		t.Fatalf("after unrelated changes: %v", st)
	}
	apisvc.SetStatusWindow(t, 1)
	if st := status(pg); st.GetState() != pending {
		t.Fatalf("behind more revisions than read: %v", st)
	}
}

// TestRouteStatus_CapabilityMissing (D113): an online gateway or connector whose control session
// lacks a capability the route needs is listed with CAPABILITY_MISSING and the capabilities, and
// neither serves the route nor counts as a ready target; reconnecting with the capability, or a
// route that uses no gated feature, clears it.
func TestRouteStatus_CapabilityMissing(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	epoch := c.Instance.GetX(e.sys, 1).DbEpoch
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	var gws []string
	for _, name := range []string{"gw1", "gw2"} {
		gw, err := createGateway(ada, org, group, name, name+".example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		gws = append(gws, gw.GetId())
	}
	c1, c2 := e.addConnector(t, org, "c1", nil).ID, e.addConnector(t, org, "c2", nil).ID
	var ids []string
	for _, rt := range []struct {
		name string
		port uint32
	}{{"gated", 20001}, {"plain", 20002}} {
		r, err := createRoute(ada, org, tcpRoute(rt.name, group, rt.port), "")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.GetId())
	}
	gated, plain := ids[0], ids[1]
	targets := map[string]string{} // connector → target of the gated route
	for _, route := range ids {
		for _, con := range []string{c1, c2} {
			r, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: route,
				Target: addressTarget(con, "10.0.0.5", 5432)}))
			if err != nil {
				t.Fatal(err)
			}
			if route == gated {
				targets[con] = r.Msg.GetTarget().GetId()
			}
		}
	}
	for _, g := range []struct {
		kind pki.Kind
		cap  string
	}{{pki.KindGateway, "test.gw"}, {pki.KindConnector, "test.conn"}} {
		t.Cleanup(routes.Register(routes.Gate{Capability: g.cap, Kind: g.kind,
			Uses: func(_ context.Context, _ *ent.Client, id string) (bool, error) { return id == gated, nil }}))
	}

	// Every agent applied the newest revision and reports no resource of the gated route as not
	// ready: what an agent without the capability reports, as its snapshot of that revision holds
	// neither the route nor a reference to it, so it applies without a rejection and knows of no
	// route to report (internal/routes, TestCompile_GatedSnapshotsValidate).
	applied := c.ConfigRevision.Query().Order(ent.Desc(configrevision.FieldID)).FirstX(e.sys).ID
	caps := map[string][]string{gws[0]: {"tunnel.quic", "test.gw"}, gws[1]: {"tunnel.quic"}, c1: {"test.conn"}, c2: nil}
	for _, id := range []string{gws[0], gws[1], c1, c2} {
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(e.clock).
			SetLastSeenAt(e.clock).SetCapabilities(caps[id]).ExecX(e.sys)
		c.AgentState.Create().SetID(id).SetOrgID(org).SetAppliedDbEpoch(epoch).SetAppliedSeq(applied).SetAppliedHash([]byte("h")).
			SetPushedDbEpoch(epoch).SetPushedSeq(applied).SetPushedHash([]byte("h")).SetPushedAt(e.clock).ExecX(e.sys)
	}
	for _, gw := range gws {
		for _, con := range []string{c1, c2} {
			c.DataSession.Create().SetOrgID(org).SetGatewayID(gw).SetConnectorID(con).SetTransport("quic").SetEstablishedAt(e.clock).
				SetReportedAt(e.clock).ExecX(e.sys)
		}
	}
	status := func(id string) *rpmgrv1.RouteStatus {
		t.Helper()
		r, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetRoute().GetStatus()
	}
	missing := func(st *rpmgrv1.RouteStatus) map[string]string {
		out := map[string]string{}
		for _, n := range st.GetNotServing() {
			if n.GetReason() == routes.CapabilityMissing {
				out[n.GetId()] = n.GetDetail()
			}
		}
		return out
	}

	st := status(gated)
	if want := map[string]string{gws[1]: "test.gw", targets[c2]: "test.conn"}; !maps.Equal(missing(st), want) {
		t.Fatalf("missing capabilities: %v, want %v", st.GetNotServing(), want)
	}
	if st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_DEGRADED || st.GetGatewaysServing() != 1 || st.GetTargetsReady() != 1 {
		t.Fatalf("the gated route: %v", st)
	}
	if st := status(plain); st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_READY || len(st.GetNotServing()) != 0 {
		t.Fatalf("a route without a gated feature: %v", st)
	}
	// Offline comes first: an offline agent's capabilities are not known.
	c.AgentSession.UpdateOneID(gws[1]).SetDisconnectedAt(e.clock).ExecX(e.sys)
	if st := status(gated); missing(st)[gws[1]] != "" {
		t.Fatalf("an offline gateway: %v", st.GetNotServing())
	}
	// Both reconnect with the capability.
	c.AgentSession.UpdateOneID(gws[1]).ClearDisconnectedAt().SetSessionEpoch(2).SetCapabilities([]string{"tunnel.quic", "test.gw"}).ExecX(e.sys)
	c.AgentSession.UpdateOneID(c2).SetSessionEpoch(2).SetCapabilities([]string{"test.conn"}).ExecX(e.sys)
	if st := status(gated); st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_READY || len(st.GetNotServing()) != 0 {
		t.Fatalf("after reconnecting with the capabilities: %v", st)
	}
}

// TestRouteStatus_HeaderMatchNote: a gateway without http.header-match is named with what its
// clients meet, as it sends a route's requests to another route of the hostname (03, "Versioning
// and capabilities"); other capabilities are named alone.
func TestRouteStatus_HeaderMatchNote(t *testing.T) {
	got := apisvc.CapabilityMissingFor("gw_1", []string{"http.header-match"})
	if got.GetId() != "gw_1" || got.GetReason() != routes.CapabilityMissing ||
		!strings.HasPrefix(got.GetDetail(), "http.header-match; this gateway sends the route's requests to a route of the same hostname") {
		t.Errorf("header matches: %v", got)
	}
	if got := apisvc.CapabilityMissingFor("gw_1", []string{"route.limits"}); got.GetDetail() != "route.limits" {
		t.Errorf("another capability: %q", got.GetDetail())
	}
}
