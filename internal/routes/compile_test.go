// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
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

// routesOf keeps the ConnectorRoute resources.
func routesOf(rs []*agentv1.Resource) []*agentv1.Resource {
	return slices.DeleteFunc(rs, func(r *agentv1.Resource) bool { return r.GetConnectorRoute() == nil })
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

// TestCompile_GatewayUDP: a gateway gets the enabled udp routes of its group that have a port,
// with their flow idle timeout and serving connectors; a connector gets the enabled ones it serves.
func TestCompile_GatewayUDP(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		if err := f.pool(t, f.orgA, f.groupA, routes.UDP, 20000, 20099); err != nil {
			t.Fatal(err)
		}
		udpRoute := func(name string, port int, enabled bool, idle int) string {
			r := c.Route.Create().SetOrgID(f.orgA).SetName(name).SetType("udp").SetGatewayGroupID(f.groupA).SetEnabled(enabled).SaveX(f.sys)
			if err := f.tx(t, func(tx *ent.Tx) error {
				a, err := routes.Allocate(f.sys, tx, f.orgA, f.groupA, routes.UDP, port)
				if err != nil {
					return err
				}
				create := tx.RouteUDP.Create().SetOrgID(f.orgA).SetRouteID(r.ID).SetPortAllocationID(a.ID)
				if idle > 0 {
					create.SetFlowIdleTimeoutSeconds(idle)
				}
				return create.Exec(f.sys)
			}); err != nil {
				t.Fatal(err)
			}
			c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(r.ID).SetConnectorID(f.c2).SetKind("address").SetHost("10.0.0.53").
				SetPort(53).ExecX(f.sys)
			return r.ID
		}
		dns := udpRoute("dns", 20001, true, 0) // the same number as the tcp route's port
		game := udpRoute("game", 20002, true, 300)
		udpRoute("udp-off", 20003, false, 0)
		c.Route.Create().SetOrgID(f.orgA).SetName("half-udp").SetType("udp").SetGatewayGroupID(f.groupA).ExecX(f.sys)

		got := map[string]*agentv1.GatewayUDPRoute{}
		for _, r := range f.compile(t, pki.KindGateway, f.gateway) {
			if u := r.GetGatewayUdpRoute(); u != nil {
				got[r.GetId()] = u
			}
		}
		if len(got) != 2 || got[dns].GetPort() != 20001 || got[dns].GetFlowIdleTimeoutSeconds() != 60 ||
			got[game].GetPort() != 20002 || got[game].GetFlowIdleTimeoutSeconds() != 300 || !slices.Equal(got[dns].GetConnectors(), []string{f.c2}) {
			t.Fatalf("udp routes %v", got)
		}
		var udp []string
		for _, r := range routesOf(f.compile(t, pki.KindConnector, f.c2)) {
			if cr := r.GetConnectorRoute(); cr.GetType() == "udp" {
				if len(cr.GetTargets()) != 1 || cr.GetTargets()[0].GetPort() != 53 {
					t.Fatalf("udp route %v", r)
				}
				udp = append(udp, r.GetId())
			}
		}
		want := []string{dns, game}
		slices.Sort(want)
		if !slices.Equal(udp, want) {
			t.Fatalf("the connector's udp routes %v, want the enabled %v", udp, want)
		}
		db.Client().Gateway.UpdateOneID(f.gateway).SetEnabled(false).ExecX(f.sys)
		if rs := f.compile(t, pki.KindGateway, f.gateway); len(rs) != 0 {
			t.Fatalf("a disabled gateway: %v", rs)
		}
	})
}

func TestCompile_ConnectorRoutes(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		rs := routesOf(f.compile(t, pki.KindConnector, f.c1))
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
	for _, r := range routesOf(f.compile(t, pki.KindConnector, f.c2)) {
		ts := r.GetConnectorRoute().GetTargets()
		if !slices.IsSortedFunc(ts, func(x, y *agentv1.Target) int { return int(x.GetPriority()) - int(y.GetPriority()) }) || len(ts) != 4 {
			t.Fatalf("targets %v", ts)
		}
	}
}

// TestCompile_ConnectorGateways: a connector gets the enabled gateways of its routes' groups, with
// those routes and their effective transports; decommissioned and disabled gateways are left out.
func TestCompile_ConnectorGateways(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		otherGroup := c.Route.GetX(f.sys, f.rOther).GatewayGroupID
		gw2 := c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(otherGroup).SetName("gw2").SetSlot(1).
			SetTunnelEndpoints([]string{"gw2.example:443", "[2001:db8::2]:443"}).SaveX(f.sys).ID
		c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetName("gone").SetSlot(2).
			SetTunnelEndpoints([]string{"gone.example:443"}).SetDecommissionedAt(time.Now()).ExecX(f.sys)
		c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetName("off").SetSlot(3).
			SetTunnelEndpoints([]string{"off.example:443"}).SetEnabled(false).ExecX(f.sys)

		gateways := func(con string) map[string]*agentv1.ConnectorGateway {
			t.Helper()
			out := map[string]*agentv1.ConnectorGateway{}
			for _, r := range f.compile(t, pki.KindConnector, con) {
				if g := r.GetConnectorGateway(); g != nil {
					out[r.GetId()] = g
				}
			}
			return out
		}
		got := gateways(f.c1)
		if len(got) != 2 || got[f.gateway] == nil || got[gw2] == nil {
			t.Fatalf("gateways %v, want gw1 and gw2", got)
		}
		auto := []agentv1.TransportPolicy{agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO}
		if g := got[f.gateway]; !slices.Equal(g.GetRoutes(), []string{f.r1}) || !slices.Equal(g.GetTransports(), auto) ||
			!slices.Equal(g.GetTunnelEndpoints(), []string{"gw1.example:443"}) {
			t.Fatalf("gw1 %v", g)
		}
		if g := got[gw2]; !slices.Equal(g.GetRoutes(), []string{f.rOther}) || len(g.GetTunnelEndpoints()) != 2 {
			t.Fatalf("gw2 %v", g)
		}
		if got := gateways(f.c2); len(got) != 1 || got[f.gateway] == nil {
			t.Fatalf("c2 gets %v, want only gw1", got)
		}
		if got := gateways(f.c3); len(got) != 0 {
			t.Fatalf("a disabled connector gets %v", got)
		}

		// A second route on the group, pinned to quic, next to r1 pinned to h2: both sessions.
		c.Route.UpdateOneID(f.r1).SetTransport("h2").ExecX(f.sys)
		pinned := c.Route.Create().SetOrgID(f.orgA).SetName("pinned").SetType("tcp").SetGatewayGroupID(f.groupA).
			SetTransport("quic").SaveX(f.sys).ID
		c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(pinned).SetConnectorID(f.c1).SetKind("address").SetHost("10.0.0.6").
			SetPort(22).ExecX(f.sys)
		g := gateways(f.c1)[f.gateway]
		want := []string{f.r1, pinned}
		slices.Sort(want)
		if !slices.Equal(g.GetRoutes(), want) || !slices.Equal(g.GetTransports(),
			[]agentv1.TransportPolicy{agentv1.TransportPolicy_TRANSPORT_POLICY_QUIC, agentv1.TransportPolicy_TRANSPORT_POLICY_H2}) {
			t.Fatalf("gw1 %v", g)
		}

		// No route left: no gateway.
		c.RouteTarget.Update().SetEnabled(false).ExecX(f.sys)
		if got := gateways(f.c1); len(got) != 0 {
			t.Fatalf("without a route: %v", got)
		}
	})
}

// TestCompile_Passthrough: a gateway gets the enabled tls_passthrough routes of its group that have
// hostnames, with them sorted and the connectors that serve them; a connector gets such a route
// with its type.
// TestCompile_GatewayCertificates: a gateway gets the active certificates of its group's org that
// cover hostnames of enabled http routes, each with the hostnames it covers; not one for a
// passthrough or disabled route only, a failed one, or another org's; connectors get none.
func TestCompile_GatewayCertificates(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		if err := f.tx(t, func(tx *ent.Tx) error {
			d, err := domains.Claim(f.sys, tx, f.orgA, "example.com", true)
			if err != nil {
				return err
			}
			return tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(f.sys)
		}); err != nil {
			t.Fatal(err)
		}
		mk := func(name string, typ route.Type, enabled bool, hostnames ...string) {
			id := c.Route.Create().SetOrgID(f.orgA).SetName(name).SetType(typ).SetGatewayGroupID(f.groupA).SetEnabled(enabled).SaveX(f.sys).ID
			for _, h := range hostnames {
				if err := f.tx(t, func(tx *ent.Tx) error { _, err := routes.AddHostname(f.sys, tx, id, h, ""); return err }); err != nil {
					t.Fatal(err)
				}
			}
		}
		mk("web", route.TypeHTTP, true, "app.example.com", "*.api.example.com", "www.example.com")
		mk("web-off", route.TypeHTTP, false, "off.example.com")
		mk("pt", route.TypeTLSPassthrough, true, "db.example.com")
		cert := func(org string, status certificate.Status, sans ...string) string {
			return c.Certificate.Create().SetOrgID(org).SetSource(certificate.SourceUploaded).SetSans(sans).SetStatus(status).
				SetNotBefore(time.Now()).SetNotAfter(time.Unix(1893456000, 0)).SetChain([]byte{1}).SetKeyEnc([]byte{2}).
				SetContentSha256([]byte(sans[0])).SaveX(f.sys).ID
		}
		exact := cert(f.orgA, certificate.StatusActive, "app.example.com")
		wild := cert(f.orgA, certificate.StatusActive, "*.example.com", "off.example.com")
		api := cert(f.orgA, certificate.StatusActive, "*.api.example.com")
		cert(f.orgA, certificate.StatusActive, "db.example.com")
		cert(f.orgA, certificate.StatusActive, "off.example.com")
		cert(f.orgA, certificate.StatusFailed, "app.example.com")
		cert(f.orgB, certificate.StatusActive, "app.example.com")

		got := map[string]*agentv1.GatewayCertificate{}
		for _, r := range f.compile(t, pki.KindGateway, f.gateway) {
			if g := r.GetGatewayCertificate(); g != nil {
				got[r.GetId()] = g
			}
		}
		want := map[string][]string{exact: {"app.example.com"}, wild: {"app.example.com", "www.example.com"}, api: {"*.api.example.com"}}
		if len(got) != len(want) {
			t.Fatalf("certificates %v, want %v", got, want)
		}
		for id, hosts := range want {
			if g := got[id]; g == nil || !slices.Equal(g.GetHostnames(), hosts) || len(g.GetContentSha256()) == 0 ||
				!g.GetNotAfter().AsTime().Equal(time.Unix(1893456000, 0)) {
				t.Errorf("certificate %s: %v, want hostnames %v", id, g, hosts)
			}
		}
		for _, r := range f.compile(t, pki.KindConnector, f.c1) {
			if r.GetGatewayCertificate() != nil {
				t.Fatalf("a connector got a certificate: %v", r)
			}
		}
		c.Gateway.UpdateOneID(f.gateway).SetEnabled(false).ExecX(f.sys)
		if rs := f.compile(t, pki.KindGateway, f.gateway); len(rs) != 0 {
			t.Fatalf("a disabled gateway: %v", rs)
		}
	})
}

func TestCompile_Passthrough(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		if err := f.tx(t, func(tx *ent.Tx) error {
			d, err := domains.Claim(f.sys, tx, f.orgA, "example.com", true)
			if err != nil {
				return err
			}
			return tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(f.sys)
		}); err != nil {
			t.Fatal(err)
		}
		mk := func(name string, enabled bool, hostnames ...string) string {
			id := c.Route.Create().SetOrgID(f.orgA).SetName(name).SetType("tls_passthrough").SetGatewayGroupID(f.groupA).
				SetEnabled(enabled).SaveX(f.sys).ID
			c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(id).SetConnectorID(f.c1).SetKind("address").SetHost("10.0.0.7").
				SetPort(443).ExecX(f.sys)
			c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(id).SetConnectorID(f.c2).SetKind("address").SetHost("10.0.0.7").
				SetPort(443).ExecX(f.sys)
			for _, h := range hostnames {
				if err := f.tx(t, func(tx *ent.Tx) error { _, err := routes.AddHostname(f.sys, tx, id, h, ""); return err }); err != nil {
					t.Fatal(err)
				}
			}
			return id
		}
		db1 := mk("pt-db", true, "db.example.com", "*.pg.example.com", "admin.example.com")
		mk("pt-off", false, "off.example.com")
		mk("pt-bare", true)
		var got []*agentv1.GatewayPassthroughRoute
		for _, r := range f.compile(t, pki.KindGateway, f.gateway) {
			if p := r.GetGatewayPassthroughRoute(); p != nil {
				if r.GetId() != db1 {
					t.Fatalf("passthrough resource %s, want only %s", r.GetId(), db1)
				}
				got = append(got, p)
			}
		}
		want := []string{f.c1, f.c2}
		slices.Sort(want)
		if len(got) != 1 || !slices.Equal(got[0].GetHostnames(), []string{"*.pg.example.com", "admin.example.com", "db.example.com"}) ||
			!slices.Equal(got[0].GetConnectors(), want) {
			t.Fatalf("passthrough resources %v", got)
		}
		for _, r := range f.compile(t, pki.KindConnector, f.c1) {
			if r.GetId() == db1 && r.GetConnectorRoute().GetType() != "tls_passthrough" {
				t.Fatalf("connector resource %v", r)
			}
		}
	})
}
