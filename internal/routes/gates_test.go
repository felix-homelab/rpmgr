// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaypage"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// gate registers a gate of kind for capability that the routes ids use, until the test ends.
func gate(t *testing.T, kind pki.Kind, capability string, ids ...string) {
	t.Helper()
	t.Cleanup(routes.Register(routes.Gate{Capability: capability, Kind: kind,
		Uses: func(_ context.Context, _ *ent.Client, id string) (bool, error) { return slices.Contains(ids, id), nil }}))
}

// compileSnap compiles the snapshot of an agent of the fleet's org that announces caps.
func (f *fleet) compileSnap(t *testing.T, kind pki.Kind, id string, caps ...string) *agentv1.Snapshot {
	t.Helper()
	c := &snapshot.Compiler{Sources: routes.Sources()}
	snap, err := c.Compile(f.sys, f.db, snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: f.orgA, Kind: kind, ID: id},
		Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// compileAs is compileSnap's resources.
func (f *fleet) compileAs(t *testing.T, kind pki.Kind, id string, caps ...string) []*agentv1.Resource {
	t.Helper()
	return f.compileSnap(t, kind, id, caps...).GetResources()
}

func ids(rs []*agentv1.Resource) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.GetId()
	}
	return out
}

// everyType adds to the fleet's group an enabled route of each type besides its tcp route r1, each
// with a target on c1, and returns them by type, r1 included.
func (f *fleet) everyType(t *testing.T) map[string]string {
	t.Helper()
	c := f.db.Client()
	if err := f.pool(t, f.orgA, f.groupA, routes.UDP, 20000, 20099); err != nil {
		t.Fatal(err)
	}
	f.verifiedExample(t)
	target := func(id, host string, port int) {
		c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(id).SetConnectorID(f.c1).SetKind("address").SetHost(host).SetPort(port).
			ExecX(f.sys)
	}
	out := map[string]string{"tcp": f.r1}
	mk := func(typ string, ports func(tx *ent.Tx, id string) error) string {
		id := c.Route.Create().SetOrgID(f.orgA).SetName(strings.ReplaceAll(typ, "_", "-")).SetType(route.Type(typ)).SetGatewayGroupID(f.groupA).SaveX(f.sys).ID
		if err := f.tx(t, func(tx *ent.Tx) error { return ports(tx, id) }); err != nil {
			t.Fatal(err)
		}
		out[typ] = id
		return id
	}
	target(mk("udp", func(tx *ent.Tx, id string) error {
		a, err := routes.Allocate(f.sys, tx, f.orgA, f.groupA, routes.UDP, 20010)
		if err != nil {
			return err
		}
		return tx.RouteUDP.Create().SetOrgID(f.orgA).SetRouteID(id).SetPortAllocationID(a.ID).Exec(f.sys)
	}), "10.0.0.53", 53)
	target(mk("tcp_udp", func(tx *ent.Tx, id string) error {
		tcp, udp, err := routes.AllocateBoth(f.sys, tx, f.orgA, f.groupA, 20020, "", "")
		if err != nil {
			return err
		}
		if err := tx.RouteTCP.Create().SetOrgID(f.orgA).SetRouteID(id).SetPortAllocationID(tcp.ID).Exec(f.sys); err != nil {
			return err
		}
		return tx.RouteUDP.Create().SetOrgID(f.orgA).SetRouteID(id).SetPortAllocationID(udp.ID).Exec(f.sys)
	}), "10.0.0.54", 53)
	target(mk("tls_passthrough", func(tx *ent.Tx, id string) error {
		_, err := routes.AddHostname(f.sys, tx, id, "tls.example.com", "")
		return err
	}), "10.0.0.7", 443)
	web := f.httpRoute(t, "web", true, true, nil, "www.example.com")
	c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(web).SetConnectorID(f.c1).SetKind("address").SetHost("10.0.0.80").
		SetPort(8080).SetUpstreamProtocol(routetarget.UpstreamProtocolTCP).ExecX(f.sys)
	out["http"] = web
	return out
}

// TestCompile_GatedRouteNeverReachesOldGateway (docs/12, D113): a route that uses a gated feature
// is left out of the snapshot of every gateway that does not announce the feature's capability, for
// each route type, and only that route; a gateway that announces it, or announces it after
// reconnecting, gets the route as before. A gate of the gateway kind leaves connectors alone.
func TestCompile_GatedRouteNeverReachesOldGateway(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		gw2 := c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetName("gw2").SetSlot(2).
			SetTunnelEndpoints([]string{"gw2.example:443"}).SaveX(f.sys).ID
		byType := f.everyType(t)
		plain := f.httpRoute(t, "plain", true, true, nil, "plain.example.com")
		c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(plain).SetConnectorID(f.c1).SetKind("address").SetHost("10.0.0.81").
			SetPort(8080).SetUpstreamProtocol(routetarget.UpstreamProtocolTCP).ExecX(f.sys)
		gatedIDs := slices.Collect(maps.Values(byType))
		before := ids(f.compileAs(t, pki.KindGateway, f.gateway))
		for _, id := range append(slices.Clone(gatedIDs), plain) {
			if !slices.Contains(before, id) {
				t.Fatalf("without a gate the gateway lacks %s: %v", id, before)
			}
		}

		gate(t, pki.KindGateway, "test.gated", gatedIDs...)
		old := ids(f.compileAs(t, pki.KindGateway, f.gateway, "tunnel.quic", "tunnel.h2"))
		for typ, id := range byType {
			if slices.Contains(old, id) {
				t.Fatalf("an old gateway got the gated %s route: %v", typ, old)
			}
		}
		if want := slices.DeleteFunc(slices.Clone(before), func(id string) bool { return slices.Contains(gatedIDs, id) }); !slices.Equal(old, want) {
			t.Fatalf("an old gateway gets %v, want everything else %v", old, want)
		}
		// The other gateway of the group announces it; so does the first after reconnecting.
		if got := ids(f.compileAs(t, pki.KindGateway, gw2, "test.gated")); !slices.Equal(got, slices.DeleteFunc(slices.Clone(before), func(id string) bool {
			return id == f.gateway // nothing of before is the gateway's own; both get the same routes
		})) {
			t.Fatalf("a new gateway: %v, want %v", got, before)
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "tunnel.quic", "test.gated")); !slices.Equal(got, before) {
			t.Fatalf("after reconnecting with the capability: %v, want %v", got, before)
		}
		// The gate is the gateway's: connectors keep the routes.
		rs := ids(routesOf(f.compileAs(t, pki.KindConnector, f.c1)))
		for _, id := range append(gatedIDs, plain) {
			if !slices.Contains(rs, id) {
				t.Fatalf("a connector lost the gateway-gated route %s: %v", id, rs)
			}
		}
	})
}

// TestCompile_GatedSnapshotsValidate: every snapshot the gates shape, for a gateway or a connector
// with or without the capabilities, of every route type, passes the agent's own validation, which
// an agent runs before applying it: withholding a route never leaves a reference to it behind. A
// connector without the capability names the route in none of its gateway entries.
func TestCompile_GatedSnapshotsValidate(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		byType := f.everyType(t)
		gatedIDs := slices.Collect(maps.Values(byType))
		gate(t, pki.KindGateway, "test.gw", gatedIDs...)
		gate(t, pki.KindConnector, "test.conn", gatedIDs...)
		gwApplier, _ := gateway.NewApplier()
		conApplier := connector.NewApplier(nil, nil)
		for _, caps := range [][]string{nil, {"test.gw"}, {"test.conn"}, {"test.gw", "test.conn"}} {
			if errs := gwApplier.Validate(f.compileSnap(t, pki.KindGateway, f.gateway, caps...)); len(errs) > 0 {
				t.Errorf("gateway with %v: %v", caps, errs)
			}
			snap := f.compileSnap(t, pki.KindConnector, f.c1, caps...)
			if errs := conApplier.Validate(snap); len(errs) > 0 {
				t.Errorf("connector with %v: %v", caps, errs)
			}
			withCap := slices.Contains(caps, "test.conn")
			for _, r := range snap.GetResources() {
				g := r.GetConnectorGateway()
				if g == nil {
					continue
				}
				for _, id := range gatedIDs {
					if slices.Contains(g.GetRoutes(), id) != withCap {
						t.Errorf("connector with %v: gateway entry %s routes %v, gated %s", caps, r.GetId(), g.GetRoutes(), id)
					}
				}
			}
			if !withCap && slices.ContainsFunc(snap.GetResources(), func(r *agentv1.Resource) bool { return slices.Contains(gatedIDs, r.GetId()) }) {
				t.Errorf("connector without the capability got a gated route: %v", ids(snap.GetResources()))
			}
		}
	})
}

// TestCompile_Gates: a connector gate withholds the route from connectors without the capability;
// with two gates an agent needs both; Required lists each capability once, sorted; a removed gate
// withholds nothing; an error of a gate fails the compilation; an invalid gate panics.
func TestCompile_Gates(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		gate(t, pki.KindConnector, "test.conn", f.r1)
		if rs := routesOf(f.compileAs(t, pki.KindConnector, f.c1)); slices.Contains(ids(rs), f.r1) {
			t.Fatalf("a connector without the capability got the route: %v", ids(rs))
		}
		if rs := routesOf(f.compileAs(t, pki.KindConnector, f.c1, "test.conn")); !slices.Contains(ids(rs), f.r1) {
			t.Fatalf("a connector with the capability: %v", ids(rs))
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway)); !slices.Contains(got, f.r1) {
			t.Fatalf("a connector gate withheld the route from a gateway: %v", got)
		}

		gate(t, pki.KindGateway, "test.b", f.r1)
		gate(t, pki.KindGateway, "test.a", f.r1)
		gate(t, pki.KindGateway, "test.a", f.r1)
		reqs, err := routes.Required(f.sys, db.Client(), f.r1)
		if err != nil {
			t.Fatal(err)
		}
		want := []routes.Requirement{{Kind: pki.KindConnector, Capability: "test.conn"}, {Kind: pki.KindGateway, Capability: "test.a"},
			{Kind: pki.KindGateway, Capability: "test.b"}}
		if !slices.Equal(reqs, want) {
			t.Fatalf("Required: %v, want %v", reqs, want)
		}
		if got := routes.Missing(reqs, pki.KindGateway, func(c string) bool { return c == "test.a" }); !slices.Equal(got, []string{"test.b"}) {
			t.Fatalf("Missing: %v", got)
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "test.a")); slices.Contains(got, f.r1) {
			t.Fatalf("a gateway with one of two capabilities got the route: %v", got)
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "test.b", "test.a")); !slices.Contains(got, f.r1) {
			t.Fatalf("a gateway with both: %v", got)
		}
		if reqs, err := routes.Required(f.sys, db.Client(), "rte_unknown"); err != nil || len(reqs) != 0 {
			t.Fatalf("a route no gate uses: %v, %v", reqs, err)
		}

		remove := routes.Register(routes.Gate{Capability: "test.c", Kind: pki.KindGateway,
			Uses: func(_ context.Context, _ *ent.Client, id string) (bool, error) { return id == f.r1, nil }})
		remove()
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "test.a", "test.b")); !slices.Contains(got, f.r1) {
			t.Fatalf("a removed gate still withholds: %v", got)
		}

		boom := errors.New("boom")
		t.Cleanup(routes.Register(routes.Gate{Capability: "test.err", Kind: pki.KindGateway,
			Uses: func(_ context.Context, _ *ent.Client, id string) (bool, error) {
				if id == f.r1 {
					return false, boom
				}
				return false, nil
			}}))
		c := &snapshot.Compiler{Sources: routes.Sources()}
		if _, err := c.Compile(f.sys, f.db, snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: f.orgA,
			Kind: pki.KindGateway, ID: f.gateway}}); !errors.Is(err, boom) {
			t.Fatalf("a failing gate: %v", err)
		}
	})
	for _, g := range []routes.Gate{
		{Kind: pki.KindGateway, Uses: func(context.Context, *ent.Client, string) (bool, error) { return false, nil }},
		{Capability: "x", Kind: pki.KindGateway},
		{Capability: "x", Kind: pki.KindController, Uses: func(context.Context, *ent.Client, string) (bool, error) { return false, nil }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%+v) did not panic", g)
				}
			}()
			routes.Register(g)
		}()
	}
}

// TestCompile_GatewayPages: a gateway that announces pages.custom gets its group's custom pages by
// their hash; one without it, a gateway of another group and a connector get none (D132).
func TestCompile_GatewayPages(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		sum := sha256.Sum256([]byte("<p>maintenance</p>"))
		page := c.GatewayPage.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetKind(gatewaypage.KindMaintenance).
			SetHTML("<p>maintenance</p>").SetContentSha256(sum[:]).SaveX(f.sys)
		pages := func(rs []*agentv1.Resource) []*agentv1.Resource {
			return slices.DeleteFunc(rs, func(r *agentv1.Resource) bool { return r.GetGatewayPage() == nil })
		}
		got := pages(f.compileAs(t, pki.KindGateway, f.gateway, gateway.Capabilities...))
		if len(got) != 1 || got[0].GetId() != page.ID || got[0].GetGatewayPage().GetKind() != rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE ||
			!bytes.Equal(got[0].GetGatewayPage().GetContentSha256(), sum[:]) {
			t.Fatalf("pages %v", got)
		}
		without := slices.DeleteFunc(slices.Clone(gateway.Capabilities), func(c string) bool { return c == agentproto.CapPagesCustom })
		if got := pages(f.compileAs(t, pki.KindGateway, f.gateway, without...)); len(got) != 0 {
			t.Errorf("a gateway without pages.custom got %v", got)
		}
		if got := pages(f.compileAs(t, pki.KindConnector, f.c1, gateway.Capabilities...)); len(got) != 0 {
			t.Errorf("a connector got %v", got)
		}
		other := c.GatewayGroup.Create().SetOrgID(f.orgA).SetName("other").SaveX(f.sys)
		gw := c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(other.ID).SetName("gw-other").SetSlot(1).
			SetTunnelEndpoints([]string{"gw-other.example.com:443"}).SaveX(f.sys)
		if got := pages(f.compileAs(t, pki.KindGateway, gw.ID, gateway.Capabilities...)); len(got) != 0 {
			t.Errorf("a gateway of another group got %v", got)
		}
	})
}
