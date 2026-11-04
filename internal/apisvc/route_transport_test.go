// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
)

// TestRouteStatus_TargetTransports (docs/03-connections.md, "Transport selection"): a route's
// status says, per target and per gateway, the transport of the sessions that have the route
// ready, and the level that pins it. Two targets on two connectors show their own; a connector
// that holds QUIC and HTTP/2 sessions shows each route only the transport it is ready on; gateways
// differ; a gateway of an earlier release, which does not report the routes, is unknown; a target
// that does not serve, a connector that is offline and a gateway that is offline show none.
func TestRouteStatus_TargetTransports(t *testing.T) {
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
	conA, conB := e.addConnector(t, org, "con-a", nil), e.addConnector(t, org, "con-b", nil)
	routeOf := func(name string, port uint32) string {
		got, err := createRoute(ada, org, tcpRoute(name, group, port), "")
		if err != nil {
			t.Fatal(err)
		}
		return got.GetId()
	}
	one, two := routeOf("one", 20001), routeOf("two", 20002)
	target := func(route string, con *ent.Connector) string {
		r, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: route,
			Target: addressTarget(con.ID, "10.0.0.5", 5432)}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetTarget().GetId()
	}
	oneA, oneB, twoA := target(one, conA), target(one, conB), target(two, conA)

	applied := c.ConfigRevision.Query().Order(ent.Desc(configrevision.FieldID)).FirstX(e.sys).ID
	for _, id := range []string{gws[0], gws[1], conA.ID, conB.ID} {
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(e.clock).
			SetLastSeenAt(e.clock).ExecX(e.sys)
		c.AgentState.Create().SetID(id).SetOrgID(org).SetAppliedDbEpoch(epoch).SetAppliedSeq(applied).SetAppliedHash([]byte("h")).
			SetPushedDbEpoch(epoch).SetPushedSeq(applied).SetPushedHash([]byte("h")).SetPushedAt(e.clock).ExecX(e.sys)
	}
	session := func(gw, con, transport string, routes []string) {
		cr := c.DataSession.Create().SetOrgID(org).SetGatewayID(gw).SetConnectorID(con).SetTransport(datasession.Transport(transport)).
			SetEstablishedAt(e.clock).SetReportedAt(e.clock)
		if routes != nil {
			cr.SetReadyRoutes(routes)
		}
		cr.ExecX(e.sys)
	}
	// con-a holds QUIC and HTTP/2 sessions to both gateways: route one is ready on QUIC, route two,
	// pinned to h2, on HTTP/2 only. con-b reaches gw1 over QUIC and gw2 over HTTP/2 for route one.
	for _, gw := range gws {
		session(gw, conA.ID, "quic", []string{one})
		session(gw, conA.ID, "h2", []string{two})
	}
	session(gws[0], conB.ID, "quic", []string{one})
	session(gws[1], conB.ID, "h2", []string{one})

	const (
		quic = rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC
		h2   = rpmgrv1.DataTransport_DATA_TRANSPORT_H2
		none = rpmgrv1.DataTransport_DATA_TRANSPORT_UNSPECIFIED
	)
	transports := func(route string) map[string]string {
		t.Helper()
		r, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: route}))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, tt := range r.Msg.GetRoute().GetStatus().GetTargetTransports() {
			s := tt.GetPinnedBy().String()
			for _, g := range tt.GetGateways() {
				s += fmt.Sprintf(" %s=%s", map[string]string{gws[0]: "gw1", gws[1]: "gw2"}[g.GetGatewayId()], g.GetTransport())
			}
			out[tt.GetTargetId()] = s
		}
		return out
	}
	check := func(what string, got map[string]string, want map[string]string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %v, want %v", what, got, want)
		}
		for k, w := range want {
			if got[k] != w {
				t.Errorf("%s: target %s is %q, want %q", what, k, got[k], w)
			}
		}
	}
	q, h := quic.String(), h2.String()
	pin := func(p rpmgrv1.TransportPin) string { return p.String() }
	auto := pin(rpmgrv1.TransportPin_TRANSPORT_PIN_UNSPECIFIED)

	// Two targets on two connectors, each with its own transport, and con-b's per gateway.
	check("route one", transports(one), map[string]string{
		oneA: auto + " gw1=" + q + " gw2=" + q,
		oneB: auto + " gw1=" + q + " gw2=" + h})
	// The connector that holds both sessions shows route two the HTTP/2 one only, and says who pins it.
	c.Route.UpdateOneID(two).SetTransport(route.TransportH2).ExecX(e.sys)
	check("route two", transports(two), map[string]string{
		twoA: pin(rpmgrv1.TransportPin_TRANSPORT_PIN_ROUTE) + " gw1=" + h + " gw2=" + h})
	// A pin of the connector, then of the instance default, is named as well; auto never is.
	c.Route.UpdateOneID(two).ClearTransport().ExecX(e.sys)
	c.Connector.UpdateOneID(conA.ID).SetTransport(connector.TransportH2).ExecX(e.sys)
	check("connector pin", transports(two), map[string]string{
		twoA: pin(rpmgrv1.TransportPin_TRANSPORT_PIN_CONNECTOR) + " gw1=" + h + " gw2=" + h})
	c.Connector.UpdateOneID(conA.ID).SetTransport(connector.TransportAuto).ExecX(e.sys)
	check("connector auto", transports(two), map[string]string{twoA: auto + " gw1=" + h + " gw2=" + h})

	// A gateway of an earlier release does not report the routes: unknown, not an error and not
	// the session's own transport.
	c.DataSession.Delete().ExecX(e.sys)
	session(gws[0], conB.ID, "quic", nil)
	session(gws[1], conB.ID, "h2", []string{one})
	check("old gateway", transports(one), map[string]string{
		oneA: auto,
		oneB: auto + " gw1=" + none.String() + " gw2=" + h})

	// The target switches transport (a fallback): the next report names the new one.
	c.DataSession.Delete().ExecX(e.sys)
	session(gws[0], conB.ID, "quic", []string{one})
	session(gws[1], conB.ID, "quic", []string{one})
	check("before the switch", transports(one), map[string]string{
		oneA: auto,
		oneB: auto + " gw1=" + q + " gw2=" + q})
	c.DataSession.Delete().ExecX(e.sys)
	session(gws[0], conB.ID, "h2", []string{one})
	session(gws[1], conB.ID, "h2", []string{one})
	check("after the switch", transports(one), map[string]string{
		oneA: auto,
		oneB: auto + " gw1=" + h + " gw2=" + h})

	// A pin that cannot be established: the connector reports the route not ready, so the target
	// shows no transport, with the reason in not_serving.
	c.ResourceStatus.Create().SetOrgID(org).SetAgentID(conB.ID).SetResourceID(one).SetReason("NOT_READY_REASON_TRANSPORT_UNAVAILABLE").
		SetDetail("quic").SetSince(e.clock).ExecX(e.sys)
	check("transport unavailable", transports(one), map[string]string{oneA: auto, oneB: auto})
	c.ResourceStatus.Delete().ExecX(e.sys)

	// An offline connector shows none, though its sessions are still recorded.
	c.AgentSession.UpdateOneID(conB.ID).SetDisconnectedAt(e.clock).ExecX(e.sys)
	check("offline connector", transports(one), map[string]string{oneA: auto, oneB: auto})
	c.AgentSession.UpdateOneID(conB.ID).ClearDisconnectedAt().ExecX(e.sys)

	// A gateway that is offline reported a while ago: what it said is stale, so it is left out.
	c.AgentSession.UpdateOneID(gws[1]).SetDisconnectedAt(e.clock).ExecX(e.sys)
	check("offline gateway", transports(one), map[string]string{oneA: auto, oneB: auto + " gw1=" + h})

	// A target the route no longer has is not listed.
	c.RouteTarget.DeleteOneID(oneB).ExecX(e.sys)
	check("removed target", transports(one), map[string]string{oneA: auto})
}
