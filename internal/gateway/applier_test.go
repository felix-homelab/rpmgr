// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

func tcpResource(id string, port uint32, connectors ...string) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayTcpRoute{GatewayTcpRoute: &agentv1.GatewayTCPRoute{
		Port: port, IdleTimeoutSeconds: 3600, Connectors: connectors}}}
}

func gatewaySnapshot(seq uint64, rs ...*agentv1.Resource) *agentv1.Snapshot {
	return &agentv1.Snapshot{Revision: &agentv1.Revision{Seq: seq}, Resources: rs}
}

// TestApplier_Validate: a gateway snapshot holds only tcp routes on valid, distinct ports with
// connector IDs.
func TestApplier_Validate(t *testing.T) {
	a, _ := gateway.NewApplier()
	if errs := a.Validate(gatewaySnapshot(1, tcpResource("rt_1", 5432, "con_1"), tcpResource("rt_2", 6379, "con_1", "con_2"))); len(errs) != 0 {
		t.Fatalf("a valid snapshot: %v", errs)
	}
	for _, tc := range []struct {
		name string
		snap *agentv1.Snapshot
		want string
	}{
		{"a connector's resource", gatewaySnapshot(1, &agentv1.Resource{Id: "rt_1", Kind: &agentv1.Resource_ConnectorRoute{ConnectorRoute: &agentv1.ConnectorRoute{}}}), "does not run"},
		{"no kind", gatewaySnapshot(1, &agentv1.Resource{Id: "rt_1"}), "does not run"},
		{"port 0", gatewaySnapshot(1, tcpResource("rt_1", 0)), "not a TCP port"},
		{"port 65536", gatewaySnapshot(1, tcpResource("rt_1", 65536)), "not a TCP port"},
		{"a port twice", gatewaySnapshot(1, tcpResource("rt_1", 5432), tcpResource("rt_2", 5432)), "also the port of rt_1"},
		{"an empty connector", gatewaySnapshot(1, tcpResource("rt_1", 5432, "con_1", "")), "empty connector"},
	} {
		errs := a.Validate(tc.snap)
		if len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
}

// TestApplier_Apply: the snapshot's routes listen, its assignment admits exactly its connectors,
// its revision goes into StreamOpen, and a connector dropped from it loses its data sessions.
func TestApplier_Apply(t *testing.T) {
	a, assign := gateway.NewApplier()
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	routes := gateway.NewTCPRoutes(gateway.TCPOptions{Host: "127.0.0.1", Sessions: m, Revision: a.Revision})
	t.Cleanup(routes.Close)
	a.Bind(routes, nil, m)
	if assign.Known(cid("con_1")) || a.Revision() != nil {
		t.Fatal("known before any snapshot")
	}
	p1, p2 := freePort(t), freePort(t)
	st := a.Apply(t.Context(), gatewaySnapshot(7, tcpResource("rt_1", uint32(p1), cid("con_1")), tcpResource("rt_2", uint32(p2), cid("con_1"), cid("con_2"))),
		agent.Changes{})
	if len(st) != 0 {
		t.Fatal(st)
	}
	if !assign.Known(cid("con_2")) || assign.Known(cid("con_3")) || len(assign.Connectors("rt_2")) != 2 || a.Revision().GetSeq() != 7 {
		t.Fatalf("assignment after the snapshot: %v %v rev %v", assign.Connectors("rt_1"), assign.Connectors("rt_2"), a.Revision())
	}
	for _, p := range []uint16{p1, p2} {
		// Without a data session the gateway resets the connection, sometimes before Dial returns.
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p))))
		if err != nil && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("port %d: %v", p, err)
		}
		if c != nil {
			_ = c.Close()
		}
	}

	c := start(t, m, connectorID("con_2"), hello("rt_2"))
	a.Apply(t.Context(), gatewaySnapshot(8, tcpResource("rt_1", uint32(p1), cid("con_1"))), agent.Changes{})
	if err := c.serveErr(t); err == nil {
		t.Fatal("the dropped connector's session ended without an error")
	}
	if assign.Known(cid("con_2")) || a.Revision().GetSeq() != 8 {
		t.Fatal("the dropped connector is still known")
	}
}
