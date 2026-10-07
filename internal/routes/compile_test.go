// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// fleet is a gateway group with a gateway, three connectors and four routes.
type fleet struct {
	*env
	gateway              string
	c1, c2, c3           string
	r1, rOff, rOther, r4 string
}

func newFleet(t *testing.T, db *store.DB) *fleet {
	t.Helper()
	e := newEnv(t, db)
	f := &fleet{env: e}
	c := db.Client()
	sys := e.sys
	f.gateway = c.Gateway.Create().SetOrgID(e.orgA).SetGatewayGroupID(e.groupA).SetName("gw1").SetSlot(1).
		SetTunnelEndpoints([]string{"gw1.example:443"}).SaveX(sys).ID
	conn := func(name string, enabled bool) string {
		return c.Connector.Create().SetOrgID(e.orgA).SetName(name).SetSpiffeID("spiffe://x/" + name).SetPubkeySha256(name).
			SetEnabled(enabled).SaveX(sys).ID
	}
	f.c1, f.c2, f.c3 = conn("c1", true), conn("c2", true), conn("c3", false)
	if err := e.pool(t, e.orgA, e.groupA, routes.TCP, 20000, 20099); err != nil {
		t.Fatal(err)
	}
	otherGroup := c.GatewayGroup.Create().SetOrgID(e.orgA).SetName("us").SaveX(sys).ID
	if err := e.pool(t, e.orgA, otherGroup, routes.TCP, 20000, 20099); err != nil {
		t.Fatal(err)
	}
	tcpRoute := func(name, group string, port int, enabled bool) string {
		r := c.Route.Create().SetOrgID(e.orgA).SetName(name).SetType("tcp").SetGatewayGroupID(group).SetEnabled(enabled).SaveX(sys)
		if err := e.tx(t, func(tx *ent.Tx) error {
			a, err := routes.Allocate(sys, tx, e.orgA, group, routes.TCP, port)
			if err != nil {
				return err
			}
			return tx.RouteTCP.Create().SetOrgID(e.orgA).SetRouteID(r.ID).SetPortAllocationID(a.ID).Exec(sys)
		}); err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	target := func(route, con string, priority int) {
		c.RouteTarget.Create().SetOrgID(e.orgA).SetRouteID(route).SetConnectorID(con).SetKind("address").SetHost("10.0.0.5").
			SetPort(5432).SetPriority(priority).SetProxyProtocol("v2").ExecX(sys)
	}
	f.r1 = tcpRoute("db", e.groupA, 20001, true)
	target(f.r1, f.c1, 1)
	target(f.r1, f.c2, 0)
	target(f.r1, f.c3, 0)
	f.rOff = tcpRoute("off", e.groupA, 20002, false)
	target(f.rOff, f.c1, 0)
	f.rOther = tcpRoute("elsewhere", otherGroup, 20001, true)
	target(f.rOther, f.c1, 0)
	// A tcp route without its port yet.
	f.r4 = c.Route.Create().SetOrgID(e.orgA).SetName("half").SetType("tcp").SetGatewayGroupID(e.groupA).SaveX(sys).ID
	return f
}

func (f *fleet) compile(t *testing.T, kind pki.Kind, id string) []*agentv1.Resource {
	t.Helper()
	c := &snapshot.Compiler{Sources: routes.Sources()}
	snap, err := c.Compile(f.sys, f.db, snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: f.orgA, Kind: kind, ID: id}})
	if err != nil {
		t.Fatal(err)
	}
	return snap.GetResources()
}

func TestCompile_GatewayTCP(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		rs := f.compile(t, pki.KindGateway, f.gateway)
		if len(rs) != 1 || rs[0].GetId() != f.r1 {
			t.Fatalf("resources %v, want only the enabled route of the group with a port", rs)
		}
		g := rs[0].GetGatewayTcpRoute()
		want := []string{f.c1, f.c2}
		slices.Sort(want)
		if g.GetPort() != 20001 || g.GetIdleTimeoutSeconds() != 3600 || !slices.Equal(g.GetConnectors(), want) {
			t.Fatalf("route %v: want port 20001 and the enabled connectors %v", g, want)
		}
		// A decommissioned gateway gets nothing.
		db.Client().Gateway.UpdateOneID(f.gateway).SetDecommissionedAt(time.Now()).ExecX(f.sys)
		if rs := f.compile(t, pki.KindGateway, f.gateway); len(rs) != 0 {
			t.Fatalf("a decommissioned gateway: %v", rs)
		}
	})
}

func TestCompile_ConnectorRoutes(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		rs := f.compile(t, pki.KindConnector, f.c1)
		ids := []string{f.r1, f.rOther}
		slices.Sort(ids)
		if len(rs) != 2 || rs[0].GetId() != ids[0] || rs[1].GetId() != ids[1] {
			t.Fatalf("resources %v, want the two enabled routes with a target on c1", rs)
		}
		for _, r := range rs {
			cr := r.GetConnectorRoute()
			if cr.GetType() != "tcp" || len(cr.GetTargets()) != 1 || cr.GetTargets()[0].GetProxyProtocol() != "v2" ||
				cr.GetTransport() != agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO {
				t.Fatalf("route %v", cr)
			}
		}
		if rs := f.compile(t, pki.KindConnector, f.c3); len(rs) != 0 {
			t.Fatalf("a disabled connector: %v", rs)
		}
		if rs := f.compile(t, pki.KindGateway, f.c1); len(rs) != 0 {
			t.Fatalf("a connector compiled as a gateway: %v", rs)
		}

		transport := func() agentv1.TransportPolicy {
			t.Helper()
			for _, r := range f.compile(t, pki.KindConnector, f.c1) {
				if r.GetId() == f.r1 {
					return r.GetConnectorRoute().GetTransport()
				}
			}
			t.Fatal("route r1 missing")
			return 0
		}
		if _, err := settings.UpdateInstance(f.sys, db, &rpmgrv1.InstanceSettings{DefaultTransport: rpmgrv1.TransportPolicy_TRANSPORT_POLICY_H2.Enum()},
			&fieldmaskpb.FieldMask{Paths: []string{"default_transport"}}, 0); err != nil {
			t.Fatal(err)
		}
		if got := transport(); got != agentv1.TransportPolicy_TRANSPORT_POLICY_H2 {
			t.Fatalf("the instance default: %s", got)
		}
		db.Client().Connector.UpdateOneID(f.c1).SetTransport("quic").ExecX(f.sys)
		if got := transport(); got != agentv1.TransportPolicy_TRANSPORT_POLICY_QUIC {
			t.Fatalf("the connector's transport: %s", got)
		}
		db.Client().Route.UpdateOneID(f.r1).SetTransport("auto").ExecX(f.sys)
		if got := transport(); got != agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO {
			t.Fatalf("the route's transport: %s", got)
		}
	})
}

// TestCompile_TargetOrder: a connector's targets of a route come by priority, then ID.
func TestCompile_TargetOrder(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	f := newFleet(t, db)
	c := db.Client()
	for _, p := range []int{5, 0, 2} {
		c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(f.r1).SetConnectorID(f.c2).SetKind("unix").SetUnixPath("/run/a.sock").
			SetPriority(p).ExecX(f.sys)
	}
	for _, r := range f.compile(t, pki.KindConnector, f.c2) {
		ts := r.GetConnectorRoute().GetTargets()
		if !slices.IsSortedFunc(ts, func(x, y *agentv1.Target) int { return int(x.GetPriority()) - int(y.GetPriority()) }) || len(ts) != 4 {
			t.Fatalf("targets %v", ts)
		}
	}
}
