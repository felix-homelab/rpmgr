// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routelimit"
)

// A route with limits reaches only gateways that enforce them (docs/03-connections.md, "Route
// limits").
func init() {
	Register(Gate{Capability: agentproto.CapRouteLimits, Kind: pki.KindGateway, Uses: usesLimits})
}

// usesLimits reports whether a route has limits; the API keeps a row only while one is set.
func usesLimits(ctx context.Context, c *ent.Client, routeID string) (bool, error) {
	return c.RouteLimit.Query().Where(routelimit.RouteID(routeID)).Exist(ctx)
}

// limitsOf compiles a route's limits for a gateway of its group: each limit divided by the group's
// enabled gateways, rounded up and at least 1 (D135); nil for a route without limits. A gateway
// that is enabled but down keeps its share.
func limitsOf(ctx context.Context, tx *ent.Tx, r *ent.Route) (*agentv1.RouteLimits, error) {
	l, err := tx.RouteLimit.Query().Where(routelimit.RouteID(r.ID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n, err := tx.Gateway.Query().Where(gateway.GatewayGroupID(r.GatewayGroupID), gateway.Enabled(true), gateway.DecommissionedAtIsNil()).Count(ctx)
	if err != nil {
		return nil, err
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
