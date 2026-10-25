// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// TestGateways_WSSHostname (#639): an Admin sets a gateway's WSS hostname on create or update: a
// name under a verified domain of the org, no wildcard, no route hostname of the group nor one a
// wildcard covers, and no other gateway's; an empty name removes it.
func TestGateways_WSSHostname(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	set := func(id, name string) (*rpmgrv1.Gateway, error) {
		t.Helper()
		cur, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: id}))
		if err != nil {
			t.Fatal(err)
		}
		in := cur.Msg.GetGateway()
		in.WssHostname = name
		res, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: in, Etag: in.GetEtag(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"wss_hostname"}}}))
		if err != nil {
			return nil, err
		}
		return res.Msg.GetGateway(), nil
	}
	if _, err := set(gw.GetId(), "tunnel.example.com"); reason(err) != apisvc.ReasonDomainNotVerified {
		t.Fatalf("a name under no verified domain: %v", err)
	}
	e.verified(t, org, "example.com", true)
	if _, err := set(gw.GetId(), "*.example.com"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a wildcard: %v", err)
	}
	web, err := createRoute(ada, org, httpRoute("web", group, "web.example.com"), "")
	if err != nil {
		t.Fatal(err)
	}
	// A wildcard route hostname needs an uploaded certificate through the API; the rule under test
	// is the store's.
	if _, err := store.ConfigTx(e.sys, e.db, func(tx *ent.Tx) ([]string, error) {
		_, err := routes.AddHostname(e.sys, tx, web.GetId(), "*.apps.example.com", "")
		return []string{web.GetId()}, err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := set(gw.GetId(), "t.apps.example.com"); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a name a wildcard route hostname covers: %v", err)
	}
	got, err := set(gw.GetId(), "Tunnel.Example.com")
	if err != nil || got.GetWssHostname() != "tunnel.example.com" {
		t.Fatalf("set: %v %v", got, err)
	}
	read, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gw.GetId()}))
	if err != nil || read.Msg.GetGateway().GetWssHostname() != "tunnel.example.com" {
		t.Fatalf("read: %v %v", read, err)
	}
	if _, err := createGateway(ada, org, group, "gw2", "gw2.example.com:443"); err != nil {
		t.Fatal(err)
	}
	gw3, err := ada.gw.CreateGateway(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayRequest{OrgId: org,
		Gateway: &rpmgrv1.Gateway{GatewayGroupId: group, Name: "gw3", TunnelEndpoints: []string{"gw3.example.com:443"}, WssHostname: "tunnel.example.com"}}))
	if code(err) != connect.CodeAlreadyExists {
		t.Fatalf("another gateway's name on create: %v %v", gw3, err)
	}
	gw3, err = ada.gw.CreateGateway(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayRequest{OrgId: org,
		Gateway: &rpmgrv1.Gateway{GatewayGroupId: group, Name: "gw3", TunnelEndpoints: []string{"gw3.example.com:443"}, WssHostname: "gw3-wss.example.com"}}))
	if err != nil || gw3.Msg.GetGateway().GetWssHostname() != "gw3-wss.example.com" {
		t.Fatalf("a name on create: %v %v", gw3, err)
	}
	if got, err := set(gw.GetId(), ""); err != nil || got.GetWssHostname() != "" {
		t.Fatalf("removed: %v %v", got, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	in := gw3.Msg.GetGateway()
	in.WssHostname = ""
	if _, err := vwr.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: in, Etag: in.GetEtag(),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"wss_hostname"}}})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer removes a WSS hostname: %v", err)
	}
}

// TestRoutes_WSSTransport (#639): routes and connectors take the transport wss and show it; a value
// the API does not define is refused; a connector whose session lacks tunnel.wss is
// transport_unavailable: wss for a route on wss, and one with it is not.
func TestRoutes_WSSTransport(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	bad := tcpRoute("bad", group, 20001)
	bad.Transport = rpmgrv1.DataTransport(9)
	if _, err := createRoute(ada, org, bad, ""); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("an undefined transport: %v", err)
	}
	in := tcpRoute("db", group, 20002)
	in.Transport = rpmgrv1.DataTransport_DATA_TRANSPORT_WSS
	r, err := createRoute(ada, org, in, "")
	if err != nil || r.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_WSS {
		t.Fatalf("a route on wss: %v %v", r, err)
	}
	old, current := e.addConnector(t, org, "old", nil).ID, e.addConnector(t, org, "current", nil).ID
	targets := map[string]string{}
	for _, con := range []string{old, current} {
		res, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: r.GetId(),
			Target: addressTarget(con, "10.0.0.5", 5432)}))
		if err != nil {
			t.Fatal(err)
		}
		targets[con] = res.Msg.GetTarget().GetId()
	}
	runNewest(t, e, org, old, current)
	c.AgentSession.UpdateOneID(old).SetCapabilities([]string{agentproto.CapTunnelQUIC, agentproto.CapTunnelH2}).ExecX(e.sys)
	c.AgentSession.UpdateOneID(current).SetCapabilities([]string{agentproto.CapTunnelQUIC, agentproto.CapTunnelH2, agentproto.CapTunnelWSS}).ExecX(e.sys)
	got, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: r.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]*rpmgrv1.RouteNotServing{}
	for _, n := range got.Msg.GetRoute().GetStatus().GetNotServing() {
		reasons[n.GetId()] = n
	}
	if n := reasons[targets[old]]; n.GetReason() != "TRANSPORT_UNAVAILABLE" || n.GetDetail() != "wss" {
		t.Fatalf("the target of a connector without tunnel.wss: %v", reasons)
	}
	if n := reasons[targets[current]]; n != nil {
		t.Fatalf("the target of a connector with tunnel.wss: %v", n)
	}
	if st := got.Msg.GetRoute().GetStatus(); st.GetTargetsReady() != 1 {
		t.Fatalf("ready targets %d, want 1", st.GetTargetsReady())
	}

	con, err := ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: current}))
	if err != nil {
		t.Fatal(err)
	}
	cin := con.Msg.GetConnector()
	cin.Transport = rpmgrv1.DataTransport_DATA_TRANSPORT_WSS
	upd, err := ada.con.UpdateConnector(ctx, connect.NewRequest(&rpmgrv1.UpdateConnectorRequest{Connector: cin, Etag: cin.GetEtag(),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"transport"}}}))
	if err != nil || upd.Msg.GetConnector().GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_WSS {
		t.Fatalf("a connector on wss: %v %v", upd, err)
	}
}
