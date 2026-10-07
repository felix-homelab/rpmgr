// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"slices"
	"strings"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
)

// Sources are the snapshot sources of the route types implemented so far (docs/03-connections.md,
// "Configuration reconciliation").
func Sources() []snapshot.Source {
	return []snapshot.Source{GatewayTCP, ConnectorRoutes}
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

// ConnectorRoutes compiles a connector's routes: for every enabled tcp route with an enabled
// target on it, its targets and the effective transport. A disabled or decommissioned connector
// gets none.
func ConnectorRoutes(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindConnector {
		return nil, nil
	}
	con, err := tx.Connector.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !con.Enabled || con.DecommissionedAt != nil {
		return nil, err
	}
	targets, err := tx.RouteTarget.Query().Where(routetarget.ConnectorID(con.ID), routetarget.Enabled(true),
		routetarget.HasRouteWith(route.Enabled(true), route.TypeEQ(route.TypeTCP))).WithRoute().All(ctx)
	if err != nil {
		return nil, err
	}
	inst, _, err := settings.Instance(ctx, tx.Client())
	if err != nil {
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
