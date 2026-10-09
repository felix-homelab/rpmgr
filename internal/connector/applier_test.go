// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"strings"
	"sync/atomic"
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/policy"
)

func routeResource(id string, transport agentv1.TransportPolicy, targets ...*agentv1.Target) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_ConnectorRoute{ConnectorRoute: &agentv1.ConnectorRoute{
		Type: "tcp", Transport: transport, Targets: targets}}}
}

func udpRouteResource(id string, targets ...*agentv1.Target) *agentv1.Resource {
	r := routeResource(id, agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO, targets...)
	r.GetConnectorRoute().Type = "udp"
	return r
}

func gatewayResource(id string, endpoints []string, routes ...string) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_ConnectorGateway{ConnectorGateway: &agentv1.ConnectorGateway{
		TunnelEndpoints: endpoints, Routes: routes}}}
}

func addrTarget(host string, port uint32) *agentv1.Target {
	return &agentv1.Target{Id: "tg_1", Host: host, Port: port, ProxyProtocol: "none", Weight: 1}
}

// TestApplier_Validate: what a connector snapshot may hold.
func TestApplier_Validate(t *testing.T) {
	a := connector.NewApplier(nil, nil)
	auto := agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO
	ok := &agentv1.Snapshot{Resources: []*agentv1.Resource{
		routeResource("rt_1", auto, addrTarget("10.0.0.5", 5432), &agentv1.Target{Id: "tg_2", UnixPath: "/run/db.sock", ProxyProtocol: "v2"}),
		udpRouteResource("rt_2", addrTarget("10.0.0.53", 53), &agentv1.Target{Id: "tg_2", Host: "10.0.0.54", Port: 53}),
		gatewayResource("gw_1", []string{"gw1.example:443", "[2001:db8::1]:443"}, "rt_1", "rt_2"),
	}}
	if errs := a.Validate(ok); len(errs) != 0 {
		t.Fatalf("a valid snapshot: %v", errs)
	}
	snap := func(rs ...*agentv1.Resource) *agentv1.Snapshot { return &agentv1.Snapshot{Resources: rs} }
	for _, tc := range []struct {
		name string
		snap *agentv1.Snapshot
		want string
	}{
		{"a gateway's resource", snap(&agentv1.Resource{Id: "rt_1", Kind: &agentv1.Resource_GatewayTcpRoute{GatewayTcpRoute: &agentv1.GatewayTCPRoute{Port: 1}}}), "does not run"},
		{"an unknown route type", snap(&agentv1.Resource{Id: "rt_1", Kind: &agentv1.Resource_ConnectorRoute{ConnectorRoute: &agentv1.ConnectorRoute{
			Type: "smtp", Transport: auto, Targets: []*agentv1.Target{addrTarget("10.0.0.5", 25)}}}}), "not served"},
		{"no transport", snap(routeResource("rt_1", agentv1.TransportPolicy_TRANSPORT_POLICY_UNSPECIFIED, addrTarget("10.0.0.5", 1))), "transport"},
		{"no targets", snap(routeResource("rt_1", auto)), "without targets"},
		{"no port", snap(routeResource("rt_1", auto, addrTarget("10.0.0.5", 0))), "host and a port"},
		{"port 65536", snap(routeResource("rt_1", auto, addrTarget("10.0.0.5", 65536))), "host and a port"},
		{"no host", snap(routeResource("rt_1", auto, addrTarget("", 22))), "host and a port"},
		{"socket and address", snap(routeResource("rt_1", auto, &agentv1.Target{Id: "tg", UnixPath: "/s", Host: "h", Port: 1})), "both"},
		{"relative socket", snap(routeResource("rt_1", auto, &agentv1.Target{Id: "tg", UnixPath: "run/s"})), "clean absolute"},
		{"PROXY v3", snap(routeResource("rt_1", auto, &agentv1.Target{Id: "tg", Host: "h", Port: 1, ProxyProtocol: "v3"})), "PROXY"},
		{"a udp socket target", snap(udpRouteResource("rt_1", &agentv1.Target{Id: "tg", UnixPath: "/run/dns.sock"})), "not a socket path"},
		{"a udp PROXY header", snap(udpRouteResource("rt_1", &agentv1.Target{Id: "tg", Host: "h", Port: 53, ProxyProtocol: "v2"})), "no PROXY protocol"},
		{"gateway without endpoints", snap(gatewayResource("gw_1", nil)), "without tunnel endpoints"},
		{"endpoint without a port", snap(gatewayResource("gw_1", []string{"gw1.example"})), "not host:port"},
		{"endpoint port 0", snap(gatewayResource("gw_1", []string{"gw1.example:0"})), "not host:port"},
		{"unknown route", snap(gatewayResource("gw_1", []string{"gw1.example:443"}, "rt_9")), "not in the snapshot"},
	} {
		errs := a.Validate(tc.snap)
		if len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
}

// TestApplier_Apply: a snapshot's routes and gateways reach the targets and the data sessions: a
// stream through the gateway reaches the route's target; a route the local policy blocks is
// reported; a later snapshot without the gateway retires its session.
func TestApplier_Apply(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	svc := startService(t, echoService)
	var cur atomic.Pointer[policy.Policy]
	cur.Store(allowLoopback(t, svc.port()))
	var m *connector.Sessions
	targets := connector.NewTargets(connector.TargetsOptions{Policy: cur.Load, OnHealth: func(h *tunnelv1.RouteHealth) { m.SetReady(h) }})
	m = newConnectorWith(t, w, targets.Handle)
	a := connector.NewApplier(targets, m)
	quic := agentv1.TransportPolicy_TRANSPORT_POLICY_QUIC
	st := a.Apply(t.Context(), &agentv1.Snapshot{Resources: []*agentv1.Resource{
		routeResource("rt_1", quic, addrTarget("127.0.0.1", uint32(svc.port()))),
		routeResource("rt_blocked", quic, addrTarget("127.0.0.1", 1)),
		gatewayResource(id.ID, []string{g.addr}, "rt_1", "rt_blocked"),
	}}, agent.Changes{})
	if len(st) != 1 || st[0].GetResourceId() != "rt_blocked" || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY {
		t.Fatalf("status %v", st)
	}
	eventually(t, "no stream through the gateway", func() bool { return echo(t, g.sessions.Load(), "rt_1") == nil })

	a.Apply(t.Context(), &agentv1.Snapshot{Resources: []*agentv1.Resource{routeResource("rt_1", quic, addrTarget("127.0.0.1", uint32(svc.port())))}},
		agent.Changes{})
	eventually(t, "the removed gateway's session stays", func() bool { return len(g.sessions.Load().Count()) == 0 })
}
