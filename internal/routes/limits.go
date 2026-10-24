// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"slices"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routelimit"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
)

// A route with limits reaches only gateways that enforce them (docs/03-connections.md, "Route
// limits").
func init() {
	Register(Gate{Capability: agentproto.CapRouteLimits, Kind: pki.KindGateway, Uses: usesLimits})
}

// usesLimits reports whether a route has limits, of its own (the API keeps a row only while one is
// set) or as a rate_limit rule of one of its policies.
func usesLimits(ctx context.Context, c *ent.Client, routeID string) (bool, error) {
	if ok, err := c.RouteLimit.Query().Where(routelimit.RouteID(routeID)).Exist(ctx); ok || err != nil {
		return ok, err
	}
	policies, err := c.RoutePolicy.Query().Where(routepolicy.RouteID(routeID)).Select(routepolicy.FieldPolicyID).Strings(ctx)
	if err != nil || len(policies) == 0 {
		return false, err
	}
	return c.PolicyRule.Query().Where(policyrule.KindEQ(policyrule.KindRateLimit), policyrule.PolicyIDIn(policies...)).Exist(ctx)
}

// limitsOf compiles a route's limits for a gateway of its group: each limit divided by the group's
// enabled gateways that enforce limits, rounded up and at least 1 (D135); nil for a route without
// limits. A gateway that is enabled but down keeps its share.
func limitsOf(ctx context.Context, tx *ent.Tx, r *ent.Route) (*agentv1.RouteLimits, error) {
	l, err := tx.RouteLimit.Query().Where(routelimit.RouteID(r.ID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	gws, err := tx.Gateway.Query().Where(gateway.GatewayGroupID(r.GatewayGroupID), gateway.Enabled(true), gateway.DecommissionedAtIsNil()).
		IDs(ctx)
	if err != nil {
		return nil, err
	}
	// Only gateways that enforce limits share them: one of an earlier release does not get the
	// route at all. A gateway that never connected counts, as it will run this release or a newer one.
	n := 0
	for _, id := range gws {
		s, err := tx.AgentSession.Get(ctx, id)
		switch {
		case ent.IsNotFound(err):
			n++
		case err != nil:
			return nil, err
		case slices.Contains(s.Capabilities, agentproto.CapRouteLimits):
			n++
		}
	}
	gateways := int64(max(n, 1))
	share := func(v int64) int64 {
		if v == 0 {
			return 0
		}
		return (v + gateways - 1) / gateways
	}
	return &agentv1.RouteLimits{MaxConnections: uint32(share(l.MaxConnections)), RequestsPerSecond: uint32(share(l.RequestsPerSec)), //nolint:gosec // G115: the API bounds them
		BandwidthBytesPerSecond: uint64(share(l.BandwidthBytesPerSec))}, nil //nolint:gosec // G115: non-negative
}
