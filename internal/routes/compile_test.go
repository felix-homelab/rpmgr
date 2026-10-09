// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"google.golang.org/protobuf/proto"

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
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
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
// verifiedExample gives org-a a verified wildcard claim on example.com.
func (f *fleet) verifiedExample(t *testing.T) {
	t.Helper()
	if err := f.tx(t, func(tx *ent.Tx) error {
		d, err := domains.Claim(f.sys, tx, f.orgA, "example.com", true)
		if err != nil {
			return err
		}
		return tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(f.sys)
	}); err != nil {
		t.Fatal(err)
	}
}

// httpRoute creates an http route of org-a with hostnames ("name" or "name/prefix") and a target
// on c1 and c2; withHTTP false leaves out its route_http row.
func (f *fleet) httpRoute(t *testing.T, name string, enabled, withHTTP bool, set func(*ent.RouteHTTPCreate), hostnames ...string) string {
	t.Helper()
	c := f.db.Client()
	id := c.Route.Create().SetOrgID(f.orgA).SetName(name).SetType(route.TypeHTTP).SetGatewayGroupID(f.groupA).SetEnabled(enabled).SaveX(f.sys).ID
	if withHTTP {
		h := c.RouteHTTP.Create().SetOrgID(f.orgA).SetRouteID(id)
		if set != nil {
			set(h)
		}
		h.ExecX(f.sys)
	}
	for _, hp := range hostnames {
		host, prefix, _ := strings.Cut(hp, "/")
		if prefix != "" {
			prefix = "/" + prefix
		}
		if err := f.tx(t, func(tx *ent.Tx) error { _, err := routes.AddHostname(f.sys, tx, id, host, prefix); return err }); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// TestCompile_GatewayCertificates: a gateway gets, for each enabled http route of its group, the
// certificate the route's TLS mode names, with the route hostnames it covers: the uploaded one in
// certificate mode, the org's active ACME ones in acme mode; nothing for a disabled route, a failed
// certificate or another mode's; connectors get none.
func TestCompile_GatewayCertificates(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		f.verifiedExample(t)
		cert := func(source certificate.Source, status certificate.Status, sans ...string) string {
			return c.Certificate.Create().SetOrgID(f.orgA).SetSource(source).SetSans(sans).SetStatus(status).
				SetNotBefore(time.Now()).SetNotAfter(time.Unix(1893456000, 0)).SetChain([]byte{1}).SetKeyEnc([]byte{2}).
				SetContentSha256([]byte(sans[0])).SaveX(f.sys).ID
		}
		uploaded := func(id string) func(*ent.RouteHTTPCreate) {
			return func(h *ent.RouteHTTPCreate) { h.SetTLSMode(routehttp.TLSModeCertificate).SetCertificateID(id) }
		}
		wild := cert(certificate.SourceUploaded, certificate.StatusActive, "*.example.com")
		api := cert(certificate.SourceUploaded, certificate.StatusActive, "*.api.example.com")
		failed := cert(certificate.SourceUploaded, certificate.StatusFailed, "off.example.com")
		acmeBlog := cert(certificate.SourceAcme, certificate.StatusActive, "blog.example.com")
		cert(certificate.SourceAcme, certificate.StatusFailed, "blog.example.com")
		unused := cert(certificate.SourceUploaded, certificate.StatusActive, "blog.example.com")
		f.httpRoute(t, "web", true, true, uploaded(wild), "app.example.com", "www.example.com/docs", "*.api.example.com")
		f.httpRoute(t, "api", true, true, uploaded(api), "*.api.example.com/v2")
		f.httpRoute(t, "blog", true, true, nil, "blog.example.com")
		f.httpRoute(t, "http-off", false, true, uploaded(unused), "off2.example.com")
		f.httpRoute(t, "failing", true, true, uploaded(failed), "off.example.com")

		got := map[string]*agentv1.GatewayCertificate{}
		for _, r := range f.compile(t, pki.KindGateway, f.gateway) {
			if g := r.GetGatewayCertificate(); g != nil {
				got[r.GetId()] = g
			}
		}
		want := map[string][]string{wild: {"app.example.com", "www.example.com"}, api: {"*.api.example.com"}, acmeBlog: {"blog.example.com"}}
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
		// Another org's certificate cannot be named: the composite foreign key refuses it.
		other := c.Certificate.Create().SetOrgID(f.orgB).SetSource(certificate.SourceUploaded).SetSans([]string{"x.example.com"}).
			SetNotBefore(time.Now()).SetNotAfter(time.Now()).SetChain([]byte{1}).SetKeyEnc([]byte{2}).SetContentSha256([]byte{3}).SaveX(f.sys).ID
		rid := c.Route.Create().SetOrgID(f.orgA).SetName("cross").SetType(route.TypeHTTP).SetGatewayGroupID(f.groupA).SaveX(f.sys).ID
		if err := c.RouteHTTP.Create().SetOrgID(f.orgA).SetRouteID(rid).SetTLSMode(routehttp.TLSModeCertificate).SetCertificateID(other).Exec(f.sys); err == nil {
			t.Fatal("a route named another org's certificate")
		}
		c.Gateway.UpdateOneID(f.gateway).SetEnabled(false).ExecX(f.sys)
		if rs := f.compile(t, pki.KindGateway, f.gateway); len(rs) != 0 {
			t.Fatalf("a disabled gateway: %v", rs)
		}
	})
}

// TestCompile_GatewayHTTP: a gateway gets its group's enabled http routes that have their HTTP
// row and hostnames, with every hostname and path prefix, the serving connectors and the upstream
// protocol of the targets; connectors get the routes they serve.
func TestCompile_GatewayHTTP(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		f.verifiedExample(t)
		target := func(route, con string, proto routetarget.UpstreamProtocol, priority int) {
			c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(route).SetConnectorID(con).SetKind("address").SetHost("10.0.0.80").
				SetPort(8080).SetUpstreamProtocol(proto).SetPriority(priority).ExecX(f.sys)
		}
		c.GatewayGroup.UpdateOneID(f.groupA).SetTrustedProxyCidrs([]string{"10.0.0.0/8"}).ExecX(f.sys)
		web := f.httpRoute(t, "web", true, true, func(h *ent.RouteHTTPCreate) {
			h.SetWebsocket(false).SetHostHeader("internal.local").SetMaxBodyBytes(1 << 20).SetPort80(routehttp.Port80Off).SetHstsMaxAgeSeconds(600).
				SetRequestHeadersSet(map[string]string{"x-env": "prod", "X-Debug": ""}).SetResponseHeadersSet(map[string]string{"server": ""})
		}, "www.example.com/docs", "app.example.com", "www.example.com")
		target(web, f.c1, routetarget.UpstreamProtocolH2c, 0)
		target(web, f.c2, routetarget.UpstreamProtocolH2c, 1)
		plain := f.httpRoute(t, "plain", true, true, nil, "plain.example.com")
		target(plain, f.c1, routetarget.UpstreamProtocolTCP, 0)
		f.httpRoute(t, "http-off", false, true, nil, "off.example.com")
		f.httpRoute(t, "http-half", true, false, nil, "half.example.com")
		f.httpRoute(t, "bare", true, true, nil)

		got := map[string]*agentv1.GatewayHTTPRoute{}
		for _, r := range f.compile(t, pki.KindGateway, f.gateway) {
			if h := r.GetGatewayHttpRoute(); h != nil {
				got[r.GetId()] = h
			}
		}
		if len(got) != 2 {
			t.Fatalf("http routes %v, want web and plain", got)
		}
		w := got[web]
		var hosts []string
		for _, h := range w.GetHosts() {
			hosts = append(hosts, h.GetHostname()+h.GetPathPrefix())
		}
		cons := []string{f.c1, f.c2}
		slices.Sort(cons)
		if !slices.Equal(hosts, []string{"app.example.com", "www.example.com", "www.example.com/docs"}) || w.GetUpstreamProtocol() != "h2c" ||
			w.GetWebsocket() || !slices.Equal(w.GetConnectors(), cons) {
			t.Fatalf("web %v", w)
		}
		var req, res []string
		for _, h := range w.GetRequestHeaders() {
			req = append(req, h.GetName()+"="+h.GetValue())
		}
		for _, h := range w.GetResponseHeaders() {
			res = append(res, h.GetName()+"="+h.GetValue())
		}
		if w.GetHostHeader() != "internal.local" || w.GetMaxBodyBytes() != 1<<20 || w.GetPort80() != "off" || w.GetHstsMaxAgeSeconds() != 600 || !slices.Equal(req, []string{"X-Debug=", "X-Env=prod"}) ||
			!slices.Equal(res, []string{"Server="}) || !slices.Equal(w.GetTrustedProxies(), []string{"10.0.0.0/8"}) {
			t.Fatalf("web's HTTP settings %v", w)
		}
		if p := got[plain]; p.GetUpstreamProtocol() != "http" || !p.GetWebsocket() || !slices.Equal(p.GetConnectors(), []string{f.c1}) ||
			p.GetHostHeader() != "" || p.GetMaxBodyBytes() != 0 || p.GetPort80() != "redirect" || p.GetHstsMaxAgeSeconds() != 0 {
			t.Fatalf("plain %v", p)
		}
		var types []string
		for _, r := range routesOf(f.compile(t, pki.KindConnector, f.c2)) {
			if r.GetId() == web {
				types = append(types, r.GetConnectorRoute().GetType())
			}
		}
		if !slices.Equal(types, []string{"http"}) {
			t.Fatalf("c2's http routes: %v", types)
		}
	})
}

// TestCompile_HTTPSUpstream: an https route's gateway resource names each enabled target's server
// name (its host by default), CA bundle and SPKI pin; a malformed pin becomes one no key matches.
func TestCompile_HTTPSUpstream(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		f.verifiedExample(t)
		bundle := c.CABundle.Create().SetOrgID(f.orgA).SetName("internal").SetPem([]byte("PEM")).SaveX(f.sys)
		id := f.httpRoute(t, "secure", true, true, nil, "secure.example.com")
		pin := strings.Repeat("ab", 32)
		mk := func(host, name, spki string, enabled bool, ca bool) string {
			tc := c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(id).SetConnectorID(f.c1).SetKind("address").SetHost(host).
				SetPort(8443).SetUpstreamProtocol(routetarget.UpstreamProtocolHTTPS).SetTLSServerName(name).SetTLSSpkiSha256(spki).SetEnabled(enabled)
			if ca {
				tc.SetCaBundleID(bundle.ID)
			}
			return tc.SaveX(f.sys).ID
		}
		named := mk("10.0.0.1", "app.internal", pin, true, true)
		byHost := mk("app2.internal", "", "", true, false)
		badPin := mk("10.0.0.3", "", "not hex", true, false)
		mk("10.0.0.4", "", "", false, false)
		var got *agentv1.GatewayHTTPRoute
		for _, r := range f.compile(t, pki.KindGateway, f.gateway) {
			if r.GetId() == id {
				got = r.GetGatewayHttpRoute()
			}
		}
		want := map[string]*agentv1.UpstreamTLS{
			named:  {TargetId: named, ServerName: "app.internal", CaPem: []byte("PEM"), SpkiSha256: bytes.Repeat([]byte{0xab}, 32)},
			byHost: {TargetId: byHost, ServerName: "app2.internal"},
			badPin: {TargetId: badPin, ServerName: "10.0.0.3", SpkiSha256: make([]byte, 32)},
		}
		if got.GetUpstreamProtocol() != "https" || len(got.GetUpstreamTls()) != len(want) {
			t.Fatalf("route %v", got)
		}
		for _, u := range got.GetUpstreamTls() {
			if !proto.Equal(u, want[u.GetTargetId()]) {
				t.Errorf("target %s: %v, want %v", u.GetTargetId(), u, want[u.GetTargetId()])
			}
		}
		// Another org's bundle cannot be named.
		other := c.CABundle.Create().SetOrgID(f.orgB).SetName("theirs").SetPem([]byte("PEM")).SaveX(f.sys)
		if err := c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(id).SetConnectorID(f.c1).SetKind("address").SetHost("h").
			SetPort(1).SetCaBundleID(other.ID).Exec(f.sys); err == nil {
			t.Fatal("a target named another org's CA bundle")
		}
	})
}

// TestCompile_Access: a gateway route carries the IP rules of its access policies, in the order of
// the policies and of their rules; rules of other kinds are not part of them; a rule whose
// parameters do not parse fails the compile rather than serve the route without it.
func TestCompile_Access(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		params := func(cidrs ...string) []byte {
			b, err := proto.Marshal(&rpmgrv1.PolicyRuleParams{Params: &rpmgrv1.PolicyRuleParams_Ip{Ip: &rpmgrv1.IPRuleParams{Cidrs: cidrs}}})
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		office := c.AccessPolicy.Create().SetOrgID(f.orgA).SetName("office").SaveX(f.sys)
		blocked := c.AccessPolicy.Create().SetOrgID(f.orgA).SetName("blocked").SaveX(f.sys)
		c.PolicyRule.Create().SetOrgID(f.orgA).SetPolicyID(office.ID).SetPosition(2).SetKind(policyrule.KindIPAllow).
			SetParams(params("10.0.0.0/8")).ExecX(f.sys)
		c.PolicyRule.Create().SetOrgID(f.orgA).SetPolicyID(office.ID).SetPosition(1).SetKind(policyrule.KindIPDeny).
			SetParams(params("10.6.6.0/24")).ExecX(f.sys)
		c.PolicyRule.Create().SetOrgID(f.orgA).SetPolicyID(office.ID).SetPosition(3).SetKind(policyrule.KindBasicAuth).
			SetParams([]byte{}).ExecX(f.sys)
		c.PolicyRule.Create().SetOrgID(f.orgA).SetPolicyID(blocked.ID).SetPosition(0).SetKind(policyrule.KindIPDeny).
			SetParams(params("192.0.2.0/24", "2001:db8::/32")).ExecX(f.sys)
		c.RoutePolicy.Create().SetOrgID(f.orgA).SetRouteID(f.r1).SetPolicyID(office.ID).SetPosition(1).ExecX(f.sys)
		c.RoutePolicy.Create().SetOrgID(f.orgA).SetRouteID(f.r1).SetPolicyID(blocked.ID).SetPosition(0).ExecX(f.sys)
		var got []string
		for _, r := range f.compile(t, pki.KindGateway, f.gateway) {
			if r.GetId() == f.r1 {
				for _, rule := range r.GetGatewayTcpRoute().GetAccess().GetIpRules() {
					got = append(got, fmt.Sprintf("%t %s", rule.GetAllow(), strings.Join(rule.GetCidrs(), ",")))
				}
			}
		}
		want := []string{"false 192.0.2.0/24,2001:db8::/32", "false 10.6.6.0/24", "true 10.0.0.0/8"}
		if !slices.Equal(got, want) {
			t.Fatalf("rules %q, want %q", got, want)
		}
		// Another org's policy cannot be applied.
		theirs := c.AccessPolicy.Create().SetOrgID(f.orgB).SetName("theirs").SaveX(f.sys)
		if err := c.RoutePolicy.Create().SetOrgID(f.orgA).SetRouteID(f.r1).SetPolicyID(theirs.ID).SetPosition(5).Exec(f.sys); err == nil {
			t.Fatal("a route applied another org's policy")
		}
		c.PolicyRule.Create().SetOrgID(f.orgA).SetPolicyID(blocked.ID).SetPosition(1).SetKind(policyrule.KindIPDeny).
			SetParams([]byte("not a message")).ExecX(f.sys)
		cmp := &snapshot.Compiler{Sources: routes.Sources()}
		if _, err := cmp.Compile(f.sys, f.db, snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: f.orgA,
			Kind: pki.KindGateway, ID: f.gateway}}); err == nil {
			t.Fatal("a rule that does not parse compiled")
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
