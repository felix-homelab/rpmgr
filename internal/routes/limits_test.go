// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// limitsOf returns the limits of each gateway route of resources, by route ID.
func limitsOf(rs []*agentv1.Resource) map[string]*agentv1.RouteLimits {
	out := map[string]*agentv1.RouteLimits{}
	for _, r := range rs {
		switch {
		case r.GetGatewayTcpRoute() != nil:
			out[r.GetId()] = r.GetGatewayTcpRoute().GetLimits()
		case r.GetGatewayUdpRoute() != nil:
			out[r.GetId()] = r.GetGatewayUdpRoute().GetLimits()
		case r.GetGatewayTcpUdpRoute() != nil:
			out[r.GetId()] = r.GetGatewayTcpUdpRoute().GetLimits()
		case r.GetGatewayPassthroughRoute() != nil:
			out[r.GetId()] = r.GetGatewayPassthroughRoute().GetLimits()
		case r.GetGatewayHttpRoute() != nil:
			out[r.GetId()] = r.GetGatewayHttpRoute().GetLimits()
		}
	}
	return out
}

// TestCompile_Limits (docs/03-connections.md, "Route limits"): every route type carries its limits
// divided by the enabled gateways of its group, rounded up and at least 1 (D135); a disabled or
// decommissioned gateway does not count, an enabled one does; 0 stays no limit; a route without
// limits carries none; and a gateway without route.limits never gets a route with limits.
func TestCompile_Limits(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		byType := f.everyType(t)
		c := db.Client()
		for _, id := range byType {
			c.RouteLimit.Create().SetOrgID(f.orgA).SetRouteID(id).SetMaxConnections(10).SetRequestsPerSec(1).SetBandwidthBytesPerSec(1000).ExecX(f.sys)
		}
		check := func(what string, want *agentv1.RouteLimits) {
			t.Helper()
			got := limitsOf(f.compileAs(t, pki.KindGateway, f.gateway, agentproto.CapRouteLimits))
			for typ, id := range byType {
				if !proto.Equal(got[id], want) {
					t.Fatalf("%s, the %s route: %v, want %v", what, typ, got[id], want)
				}
			}
		}
		check("one gateway", &agentv1.RouteLimits{MaxConnections: 10, RequestsPerSecond: 1, BandwidthBytesPerSecond: 1000})
		var gws []string
		for i, want := range []*agentv1.RouteLimits{
			{MaxConnections: 5, RequestsPerSecond: 1, BandwidthBytesPerSecond: 500},
			{MaxConnections: 4, RequestsPerSecond: 1, BandwidthBytesPerSecond: 334},
			{MaxConnections: 3, RequestsPerSecond: 1, BandwidthBytesPerSecond: 250},
		} {
			gws = append(gws, c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetName(fmt.Sprintf("gw%d", i+2)).
				SetSlot(i+2).SetTunnelEndpoints([]string{fmt.Sprintf("gw%d.example:443", i+2)}).SaveX(f.sys).ID)
			check(fmt.Sprintf("%d gateways", i+2), want)
		}
		// A gateway of an earlier release, which does not get the route, takes no share; one that
		// announced route.limits does.
		c.AgentSession.Create().SetID(gws[0]).SetOrgID(f.orgA).SetSessionEpoch(1).SetControllerNode("ctn_1").SetAgentVersion("0.2.0").
			SetCapabilities([]string{agentproto.CapTunnelQUIC}).ExecX(f.sys)
		check("an old one of four", &agentv1.RouteLimits{MaxConnections: 4, RequestsPerSecond: 1, BandwidthBytesPerSecond: 334})
		c.AgentSession.UpdateOneID(gws[0]).SetCapabilities([]string{agentproto.CapTunnelQUIC, agentproto.CapRouteLimits}).ExecX(f.sys)
		check("updated", &agentv1.RouteLimits{MaxConnections: 3, RequestsPerSecond: 1, BandwidthBytesPerSecond: 250})
		c.Gateway.UpdateOneID(gws[2]).SetEnabled(false).ExecX(f.sys)
		check("a disabled one of four", &agentv1.RouteLimits{MaxConnections: 4, RequestsPerSecond: 1, BandwidthBytesPerSecond: 334})
		c.Gateway.UpdateOneID(gws[1]).SetDecommissionedAt(time.Now()).ExecX(f.sys)
		check("and a decommissioned one", &agentv1.RouteLimits{MaxConnections: 5, RequestsPerSecond: 1, BandwidthBytesPerSecond: 500})

		c.RouteLimit.Update().SetMaxConnections(0).SetBandwidthBytesPerSec(0).ExecX(f.sys)
		check("0", &agentv1.RouteLimits{RequestsPerSecond: 1})

		rs := f.compileAs(t, pki.KindGateway, f.gateway)
		for typ, id := range byType {
			if slices.Contains(ids(rs), id) {
				t.Errorf("a gateway without route.limits got the %s route", typ)
			}
		}
		c.RouteLimit.Delete().ExecX(f.sys)
		rs = f.compileAs(t, pki.KindGateway, f.gateway)
		for typ, id := range byType {
			if !slices.Contains(ids(rs), id) || limitsOf(rs)[id] != nil {
				t.Errorf("the %s route without limits: %v", typ, limitsOf(rs)[id])
			}
		}
	})
}
