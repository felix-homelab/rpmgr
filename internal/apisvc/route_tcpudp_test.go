// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portallocation"
)

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func tcpUDPRoute(name, group string, port uint32) *rpmgrv1.Route {
	return &rpmgrv1.Route{Name: name, GatewayGroupId: group, Spec: &rpmgrv1.Route_TcpUdp{TcpUdp: &rpmgrv1.TCPUDPRouteSpec{Port: port}}}
}

// TestTCPUDPRoutes (D83): a tcp_udp route takes one port number from both protocols' pools, free in
// both, with both timeouts, their defaults when not set; a port outside either protocol's pools or
// taken in either is refused, the taken one naming its route; each protocol's quota counts; a port
// change moves both, and a timeout an update clears is the default again; its targets are
// addresses without a PROXY header; deleting it, or decommissioning its only connector (D78),
// frees both ports.
func TestTCPUDPRoutes(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	for _, p := range []*rpmgrv1.PortPool{{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009},
		{GatewayGroupId: group, Protocol: udp, PortFrom: 20005, PortTo: 20014}} {
		if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, PortPool: p})); err != nil {
			t.Fatal(err)
		}
	}
	held := func(id string) []string {
		var out []string
		for _, a := range e.db.Client().PortAllocation.Query().Where(portallocation.RouteID(id)).Order(portallocation.ByProtocol()).AllX(e.sys) {
			out = append(out, string(a.Protocol)+":"+strconv.Itoa(a.Port))
		}
		return out
	}
	dns, err := createRoute(ada, org, tcpUDPRoute("dns", group, 20005), "")
	if s := dns.GetTcpUdp(); err != nil || s.GetPort() != 20005 || s.GetIdleTimeoutSeconds() != 3600 || s.GetFlowIdleTimeoutSeconds() != 60 {
		t.Fatalf("an explicit port: %v %v", dns, err)
	}
	if got := strings.Join(held(dns.GetId()), " "); got != "tcp:20005 udp:20005" {
		t.Fatalf("the route holds %s", got)
	}
	if _, err := createRoute(ada, org, udpRoute("ntp", group, 20006), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := createRoute(ada, org, tcpRoute("pg", group, 20007), ""); err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	noFlowIdle := tcpUDPRoute("z", group, 0)
	noFlowIdle.GetTcpUdp().FlowIdleTimeoutSeconds = &zero
	for name, c := range map[string]struct {
		rt     *rpmgrv1.Route
		code   connect.Code
		reason string
		text   string
	}{
		"a port of the TCP pools only": {tcpUDPRoute("x", group, 20001), connect.CodeFailedPrecondition, apisvc.ReasonPortNotInPool, ""},
		"a port of the UDP pools only": {tcpUDPRoute("x", group, 20012), connect.CodeFailedPrecondition, apisvc.ReasonPortNotInPool, ""},
		"a port a udp route holds":     {tcpUDPRoute("x", group, 20006), connect.CodeAlreadyExists, "", `route "ntp"`},
		"a port a tcp route holds":     {tcpUDPRoute("x", group, 20007), connect.CodeAlreadyExists, "", `route "pg"`},
		"a zero flow idle time":        {noFlowIdle, connect.CodeInvalidArgument, "", ""},
	} {
		_, err := createRoute(ada, org, c.rt, "")
		if code(err) != c.code || c.reason != "" && reason(err) != c.reason || !strings.Contains(errText(err), c.text) {
			t.Errorf("%s: %v, want %v %s %s", name, err, c.code, c.reason, c.text)
		}
	}
	game, err := createRoute(ada, org, tcpUDPRoute("game", group, 0), "")
	if p := game.GetTcpUdp().GetPort(); err != nil || p != 20008 && p != 20009 {
		t.Fatalf("a random port, free in both: %v %v", game, err)
	}
	free := 40017 - game.GetTcpUdp().GetPort() // the other of 20008 and 20009

	update := func(id string, mask []string, in *rpmgrv1.Route) (*rpmgrv1.Route, error) {
		in.Id = id
		r, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: in, UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRoute(), nil
	}
	moved := tcpUDPRoute("", "", free)
	moved.GetTcpUdp().IdleTimeoutSeconds = &zero
	up, err := update(dns.GetId(), []string{"tcp_udp.port", "tcp_udp.idle_timeout_seconds"}, moved)
	if s := up.GetTcpUdp(); err != nil || s.GetPort() != free || s.GetIdleTimeoutSeconds() != 0 || s.GetFlowIdleTimeoutSeconds() != 60 {
		t.Fatalf("a new port and no idle timeout: %v %v", up, err)
	}
	if got, want := strings.Join(held(dns.GetId()), " "), "tcp:"+strconv.Itoa(int(free))+" udp:"+strconv.Itoa(int(free)); got != want {
		t.Fatalf("after the move the route holds %s, want %s", got, want)
	}
	if n := e.db.Client().PortAllocation.Query().Where(portallocation.Port(20005)).CountX(e.sys); n != 0 {
		t.Fatalf("the old port is still held %d times", n)
	}
	if _, err := update(dns.GetId(), []string{"tcp_udp.port"}, tcpUDPRoute("", "", 20006)); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a move to a port taken for UDP: %v", err)
	}
	if got, want := strings.Join(held(dns.GetId()), " "), "tcp:"+strconv.Itoa(int(free))+" udp:"+strconv.Itoa(int(free)); got != want {
		t.Fatalf("a refused move changed the ports: %s", got)
	}
	up, err = update(dns.GetId(), []string{"tcp_udp.idle_timeout_seconds", "tcp_udp.flow_idle_timeout_seconds"}, tcpUDPRoute("", "", 0))
	if s := up.GetTcpUdp(); err != nil || s.GetIdleTimeoutSeconds() != 3600 || s.GetFlowIdleTimeoutSeconds() != 60 || s.GetPort() != free {
		t.Fatalf("cleared timeouts: %v %v", up, err)
	}
	if _, err := update(dns.GetId(), []string{"tcp.port"}, tcpRoute("", "", 20002)); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a tcp_udp route changed as a tcp route: %v", err)
	}

	nas := e.addConnector(t, org, "nas", nil).ID
	add := func(tg *rpmgrv1.RouteTarget) error {
		_, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: dns.GetId(), Target: tg}))
		return err
	}
	socket := &rpmgrv1.RouteTarget{ConnectorId: nas, Address: &rpmgrv1.RouteTarget_UnixPath{UnixPath: "/run/dns.sock"}}
	if err := add(socket); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a socket target: %v", err)
	}
	proxied := addressTarget(nas, "10.0.0.53", 53)
	proxied.ProxyProtocol = rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_V1
	if err := add(proxied); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a PROXY header: %v", err)
	}
	if err := add(addressTarget(nas, "10.0.0.53", 53)); err != nil {
		t.Fatalf("an address target: %v", err)
	}

	// The UDP quota counts the UDP ports of dns, game and ntp.
	if _, err := ada.gw.SetPortQuota(ctx, connect.NewRequest(&rpmgrv1.SetPortQuotaRequest{OrgId: org, GatewayGroupId: group, Protocol: udp,
		MaxPorts: 3})); err != nil {
		t.Fatal(err)
	}
	if _, err := createRoute(ada, org, tcpUDPRoute("third", group, 0), ""); reason(err) != apisvc.ReasonQuotaReached {
		t.Fatalf("over the UDP quota: %v", err)
	}
	if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: game.GetId()})); err != nil {
		t.Fatal(err)
	}
	if got := held(game.GetId()); len(got) != 0 {
		t.Fatalf("a deleted route holds %v", got)
	}
	if _, err := ada.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: nas})); err != nil {
		t.Fatal(err)
	}
	if got := held(dns.GetId()); len(got) != 0 {
		t.Fatalf("the route of a decommissioned connector holds %v", got)
	}
}
