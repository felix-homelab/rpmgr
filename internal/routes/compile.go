// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"maps"
	"slices"
	"strings"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routeudp"
)

// Sources are the snapshot sources of the route types implemented so far (docs/03-connections.md,
// "Configuration reconciliation").
func Sources() []snapshot.Source {
	return []snapshot.Source{GatewayTCP, GatewayUDP, GatewayPassthrough, ConnectorRoutes, ConnectorGateways}
}

// GatewayTCP compiles a gateway's tcp routes: every enabled tcp route of its gateway group with a
// port, and the connectors that serve it. A disabled or decommissioned gateway gets none.
func GatewayTCP(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !gw.Enabled || gw.DecommissionedAt != nil {
		return nil, err
	}
	routes, err := tx.Route.Query().Where(route.GatewayGroupID(gw.GatewayGroupID), route.TypeEQ(route.TypeTCP),
		route.Enabled(true)).Order(ent.Asc(route.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*agentv1.Resource
	for _, r := range routes {
		tcp, err := tx.RouteTCP.Query().Where(routetcp.RouteID(r.ID)).WithPort().Only(ctx)
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		connectors, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayTcpRoute{GatewayTcpRoute: &agentv1.GatewayTCPRoute{
			Port: uint32(tcp.Edges.Port.Port), IdleTimeoutSeconds: uint32(tcp.IdleTimeoutSeconds), //nolint:gosec // G115: ports and timeouts are small and positive
			Connectors: connectors}}})
	}
	return out, nil
}

// GatewayUDP compiles a gateway's udp routes: every enabled udp route of its gateway group with a
// port, and the connectors that serve it. A disabled or decommissioned gateway gets none.
func GatewayUDP(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !gw.Enabled || gw.DecommissionedAt != nil {
		return nil, err
	}
	routes, err := tx.Route.Query().Where(route.GatewayGroupID(gw.GatewayGroupID), route.TypeEQ(route.TypeUDP),
		route.Enabled(true)).Order(ent.Asc(route.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*agentv1.Resource
	for _, r := range routes {
		udp, err := tx.RouteUDP.Query().Where(routeudp.RouteID(r.ID)).WithPort().Only(ctx)
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		connectors, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayUdpRoute{GatewayUdpRoute: &agentv1.GatewayUDPRoute{
			Port: uint32(udp.Edges.Port.Port), FlowIdleTimeoutSeconds: uint32(udp.FlowIdleTimeoutSeconds), //nolint:gosec // G115: a port and a small positive number
			Connectors: connectors}}})
	}
	return out, nil
}

// GatewayPassthrough compiles a gateway's tls_passthrough routes: every enabled one of its gateway
// group with hostnames, and the connectors that serve it. A disabled or decommissioned gateway gets
// none.
func GatewayPassthrough(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !gw.Enabled || gw.DecommissionedAt != nil {
		return nil, err
	}
	routes, err := tx.Route.Query().Where(route.GatewayGroupID(gw.GatewayGroupID), route.TypeEQ(route.TypeTLSPassthrough),
		route.Enabled(true)).Order(ent.Asc(route.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*agentv1.Resource
	for _, r := range routes {
		hostnames, err := tx.RouteHostname.Query().Where(routehostname.RouteID(r.ID)).Select(routehostname.FieldHostname).Strings(ctx)
		if err != nil {
			return nil, err
		}
		if len(hostnames) == 0 {
			continue
		}
		slices.Sort(hostnames)
		connectors, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayPassthroughRoute{
			GatewayPassthroughRoute: &agentv1.GatewayPassthroughRoute{Hostnames: hostnames, Connectors: connectors}}})
	}
	return out, nil
}

// serving lists the connectors, sorted, with an enabled target of the route that are themselves
// enabled and not decommissioned.
func serving(ctx context.Context, tx *ent.Tx, routeID string) ([]string, error) {
	targets, err := tx.RouteTarget.Query().Where(routetarget.RouteID(routeID), routetarget.Enabled(true),
		routetarget.HasConnectorWith(connector.Enabled(true), connector.DecommissionedAtIsNil())).
		Select(routetarget.FieldConnectorID).Strings(ctx)
	if err != nil {
		return nil, err
	}
	slices.Sort(targets)
	return slices.Compact(targets), nil
}

// connectorTargets loads the connector a for ConnectorRoutes and ConnectorGateways, its enabled
// targets on enabled tcp, udp and tls_passthrough routes, with the routes, and the instance settings. con is nil for any
// other agent and for a disabled or decommissioned connector, which serve nothing.
func connectorTargets(ctx context.Context, tx *ent.Tx, a snapshot.Agent) (con *ent.Connector, targets []*ent.RouteTarget,
	inst *rpmgrv1.InstanceSettings, err error) {
	if a.Identity.Kind != pki.KindConnector {
		return nil, nil, nil, nil
	}
	con, err = tx.Connector.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil, nil, nil
	}
	if err != nil || !con.Enabled || con.DecommissionedAt != nil {
		return nil, nil, nil, err
	}
	targets, err = tx.RouteTarget.Query().Where(routetarget.ConnectorID(con.ID), routetarget.Enabled(true),
		routetarget.HasRouteWith(route.Enabled(true), route.TypeIn(route.TypeTCP, route.TypeUDP, route.TypeTLSPassthrough))).WithRoute().All(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	inst, _, err = settings.Instance(ctx, tx.Client())
	if err != nil {
		return nil, nil, nil, err
	}
	return con, targets, inst, nil
}

// ConnectorRoutes compiles a connector's routes: for every enabled tcp, udp or tls_passthrough route
// with an enabled target on it, its type, its targets and the effective transport. A disabled or decommissioned connector
// gets none.
func ConnectorRoutes(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	con, targets, inst, err := connectorTargets(ctx, tx, a)
	if con == nil || err != nil {
		return nil, err
	}
	byRoute := map[string]*agentv1.ConnectorRoute{}
	var ids []string
	for _, t := range targets {
		r := t.Edges.Route
		cr := byRoute[r.ID]
		if cr == nil {
			cr = &agentv1.ConnectorRoute{Type: string(r.Type), Transport: effective(r, con, inst)}
			byRoute[r.ID] = cr
			ids = append(ids, r.ID)
		}
		cr.Targets = append(cr.Targets, &agentv1.Target{Id: t.ID, Host: t.Host, Port: uint32(t.Port), UnixPath: t.UnixPath, //nolint:gosec // G115: a port
			ProxyProtocol: string(t.ProxyProtocol), Weight: uint32(t.Weight), Priority: uint32(t.Priority)}) //nolint:gosec // G115: small and positive
	}
	slices.Sort(ids)
	out := make([]*agentv1.Resource, 0, len(ids))
	for _, id := range ids {
		cr := byRoute[id]
		slices.SortFunc(cr.Targets, func(x, y *agentv1.Target) int {
			if x.Priority != y.Priority {
				return int(x.Priority) - int(y.Priority)
			}
			return strings.Compare(x.Id, y.Id)
		})
		out = append(out, &agentv1.Resource{Id: id, Kind: &agentv1.Resource_ConnectorRoute{ConnectorRoute: cr}})
	}
	return out, nil
}

// ConnectorGateways compiles the gateways a connector keeps data sessions to: every enabled
// gateway, not decommissioned, of the groups of the routes ConnectorRoutes compiles, with the
// effective transports and the IDs of those routes (docs/03-connections.md, "Multiple gateways").
func ConnectorGateways(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	con, targets, inst, err := connectorTargets(ctx, tx, a)
	if con == nil || err != nil {
		return nil, err
	}
	type need struct {
		transports map[agentv1.TransportPolicy]bool
		routes     map[string]bool
	}
	byGroup := map[string]*need{}
	for _, t := range targets {
		r := t.Edges.Route
		n := byGroup[r.GatewayGroupID]
		if n == nil {
			n = &need{transports: map[agentv1.TransportPolicy]bool{}, routes: map[string]bool{}}
			byGroup[r.GatewayGroupID] = n
		}
		n.transports[effective(r, con, inst)] = true
		n.routes[r.ID] = true
	}
	if len(byGroup) == 0 {
		return nil, nil
	}
	gws, err := tx.Gateway.Query().Where(gateway.GatewayGroupIDIn(slices.Collect(maps.Keys(byGroup))...), gateway.Enabled(true),
		gateway.DecommissionedAtIsNil()).Order(ent.Asc(gateway.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.Resource, 0, len(gws))
	for _, gw := range gws {
		n := byGroup[gw.GatewayGroupID]
		out = append(out, &agentv1.Resource{Id: gw.ID, Kind: &agentv1.Resource_ConnectorGateway{ConnectorGateway: &agentv1.ConnectorGateway{
			TunnelEndpoints: gw.TunnelEndpoints, Transports: slices.Sorted(maps.Keys(n.transports)), Routes: slices.Sorted(maps.Keys(n.routes))}}})
	}
	return out, nil
}

// effective is the transport policy of a route on a connector: the route's, else the
// connector's, else the instance default (docs/03-connections.md, "Transport selection").
func effective(r *ent.Route, con *ent.Connector, inst *rpmgrv1.InstanceSettings) agentv1.TransportPolicy {
	switch {
	case r.Transport != nil:
		return policyOf(string(*r.Transport))
	case con.Transport != nil:
		return policyOf(string(*con.Transport))
	}
	switch inst.GetDefaultTransport() {
	case rpmgrv1.TransportPolicy_TRANSPORT_POLICY_QUIC:
		return agentv1.TransportPolicy_TRANSPORT_POLICY_QUIC
	case rpmgrv1.TransportPolicy_TRANSPORT_POLICY_H2:
		return agentv1.TransportPolicy_TRANSPORT_POLICY_H2
	}
	return agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO
}

func policyOf(s string) agentv1.TransportPolicy {
	switch s {
	case "quic":
		return agentv1.TransportPolicy_TRANSPORT_POLICY_QUIC
	case "h2":
		return agentv1.TransportPolicy_TRANSPORT_POLICY_H2
	}
	return agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO
}
