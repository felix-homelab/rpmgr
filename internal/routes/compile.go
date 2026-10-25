// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/textproto"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectauthority"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectlistener"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/healthcheck"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routeudp"
)

// Sources are the snapshot sources of the route types implemented so far (docs/03-connections.md,
// "Configuration reconciliation").
func Sources() []snapshot.Source { return PreviewSources("") }

// PreviewSources are Sources for the preview of the route previewed, which they compile for its
// gateways even while no connector serves it: a new route has no target yet, and the gateway's
// checks of its port must still see it. Every source leaves out the routes the agent lacks a
// capability for (gates.go).
func PreviewSources(previewed string) []snapshot.Source {
	tcp := func(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
		return gatewayTCP(ctx, tx, a, previewed)
	}
	udp := func(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
		return gatewayUDP(ctx, tx, a, previewed)
	}
	both := func(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
		return gatewayTCPUDP(ctx, tx, a, previewed)
	}
	srcs := []snapshot.Source{tcp, udp, both, GatewayPassthrough, GatewayHTTP, certs.Gateway, domains.GatewayChallenges,
		GatewayDrain, GatewayPages, ConnectorRoutes, ConnectorGateways}
	for i, src := range srcs {
		srcs[i] = gated(src)
	}
	return srcs
}

// GatewayDrain marks the snapshot of a disabled gateway, which drains (R22). A decommissioned
// gateway gets no mark: its identity is revoked, which ends its sessions at once.
func GatewayDrain(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || gw.Enabled || gw.DecommissionedAt != nil {
		return nil, err
	}
	return []*agentv1.Resource{{Id: gw.ID, Kind: &agentv1.Resource_GatewayDrain{GatewayDrain: &agentv1.GatewayDrain{}}}}, nil
}

// gatewayTCP compiles a gateway's tcp routes: every enabled tcp route of its gateway group with a
// port and a connector that serves it, and those connectors; the route previewed also without one.
// A disabled or decommissioned gateway gets none.
func gatewayTCP(ctx context.Context, tx *ent.Tx, a snapshot.Agent, previewed string) ([]*agentv1.Resource, error) {
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
		tcp, err := tx.RouteTCP.Query().Where(routetcp.RouteID(r.ID)).WithPort().WithListener(func(q *ent.ConnectListenerQuery) { q.WithPort() }).Only(ctx)
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		connectors, ranked, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		if len(connectors) == 0 && r.ID != previewed { // no gateway holds a port that no one serves (D78)
			continue
		}
		l := tcp.Edges.Listener
		access, err := accessOf(ctx, tx, r.ID, l != nil && l.AuthMode != connectlistener.AuthModeNone)
		if err != nil {
			return nil, err
		}
		gr := &agentv1.GatewayTCPRoute{IdleTimeoutSeconds: uint32(tcp.IdleTimeoutSeconds), //nolint:gosec // G115: timeouts are small and positive
			Connectors: connectors, RankedConnectors: ranked, Access: access}
		switch {
		case l != nil:
			gr.Port = uint32(l.Edges.Port.Port) //nolint:gosec // G115: a port
			if gr.HttpConnect, err = httpConnectOf(ctx, tx, r.ID, l); err != nil {
				return nil, err
			}
		case tcp.Edges.Port != nil:
			gr.Port = uint32(tcp.Edges.Port.Port) //nolint:gosec // G115: a port
		default:
			continue // an http_connect route between listeners
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayTcpRoute{GatewayTcpRoute: gr}})
	}
	return out, nil
}

// httpConnectOf is a route's place on its CONNECT listener as the gateway gets it.
func httpConnectOf(ctx context.Context, tx *ent.Tx, routeID string, l *ent.ConnectListener) (*agentv1.HTTPConnect, error) {
	authorities, err := tx.ConnectAuthority.Query().Where(connectauthority.RouteID(routeID)).Order(ent.Asc(connectauthority.FieldAuthority)).
		Select(connectauthority.FieldAuthority).Strings(ctx)
	if err != nil {
		return nil, err
	}
	return &agentv1.HTTPConnect{Authorities: authorities, Hostname: l.Hostname, OrgId: l.OrgID,
		Auth: map[connectlistener.AuthMode]agentv1.ConnectAuth{connectlistener.AuthModeNone: agentv1.ConnectAuth_CONNECT_AUTH_NONE,
			connectlistener.AuthModeTLSBasic: agentv1.ConnectAuth_CONNECT_AUTH_TLS_BASIC, connectlistener.AuthModePlainBasic: agentv1.ConnectAuth_CONNECT_AUTH_PLAIN_BASIC}[l.AuthMode]}, nil
}

// gatewayUDP compiles a gateway's udp routes: every enabled udp route of its gateway group with a
// port and a connector that serves it, and those connectors; the route previewed also without one.
// A disabled or decommissioned gateway gets none.
func gatewayUDP(ctx context.Context, tx *ent.Tx, a snapshot.Agent, previewed string) ([]*agentv1.Resource, error) {
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
		connectors, ranked, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		if len(connectors) == 0 && r.ID != previewed { // no gateway holds a port that no one serves (D78)
			continue
		}
		access, err := accessOf(ctx, tx, r.ID, false)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayUdpRoute{GatewayUdpRoute: &agentv1.GatewayUDPRoute{
			Port: uint32(udp.Edges.Port.Port), FlowIdleTimeoutSeconds: uint32(udp.FlowIdleTimeoutSeconds), //nolint:gosec // G115: a port and a small positive number
			Connectors: connectors, RankedConnectors: ranked, Access: access}}})
	}
	return out, nil
}

// gatewayTCPUDP compiles a gateway's tcp_udp routes as gatewayTCP and gatewayUDP do theirs: every
// enabled one of its gateway group with both ports and a connector that serves it, and those
// connectors; the route previewed also without one.
func gatewayTCPUDP(ctx context.Context, tx *ent.Tx, a snapshot.Agent, previewed string) ([]*agentv1.Resource, error) {
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
	routes, err := tx.Route.Query().Where(route.GatewayGroupID(gw.GatewayGroupID), route.TypeEQ(route.TypeTCPUDP),
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
		udp, err := tx.RouteUDP.Query().Where(routeudp.RouteID(r.ID)).Only(ctx)
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		connectors, ranked, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		if len(connectors) == 0 && r.ID != previewed { // no gateway holds a port that no one serves (D78)
			continue
		}
		access, err := accessOf(ctx, tx, r.ID, false)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayTcpUdpRoute{GatewayTcpUdpRoute: &agentv1.GatewayTCPUDPRoute{
			Port: uint32(tcp.Edges.Port.Port), IdleTimeoutSeconds: uint32(tcp.IdleTimeoutSeconds), //nolint:gosec // G115: ports and timeouts are small and positive
			FlowIdleTimeoutSeconds: uint32(udp.FlowIdleTimeoutSeconds), Connectors: connectors, RankedConnectors: ranked, Access: access}}}) //nolint:gosec // G115: small and positive
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
		connectors, ranked, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		access, err := accessOf(ctx, tx, r.ID, false)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayPassthroughRoute{
			GatewayPassthroughRoute: &agentv1.GatewayPassthroughRoute{Hostnames: hostnames, Connectors: connectors, RankedConnectors: ranked,
				Access: access}}})
	}
	return out, nil
}

// GatewayHTTP compiles a gateway's http routes: every enabled one of its gateway group with its
// HTTP settings and hostnames, the connectors that serve it, and the upstream protocol of its
// targets, which the API keeps the same for every target of a route (docs/07-api.md). A disabled or
// decommissioned gateway gets none.
func GatewayHTTP(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
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
	routes, err := tx.Route.Query().Where(route.GatewayGroupID(gw.GatewayGroupID), route.TypeEQ(route.TypeHTTP),
		route.Enabled(true)).Order(ent.Asc(route.FieldID)).All(ctx)
	if err != nil || len(routes) == 0 {
		return nil, err
	}
	group, err := tx.GatewayGroup.Get(ctx, gw.GatewayGroupID)
	if err != nil {
		return nil, err
	}
	var out []*agentv1.Resource
	for _, r := range routes {
		h, err := tx.RouteHTTP.Query().Where(routehttp.RouteID(r.ID)).Only(ctx)
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		names, err := tx.RouteHostname.Query().Where(routehostname.RouteID(r.ID)).
			Order(ent.Asc(routehostname.FieldHostname), ent.Asc(routehostname.FieldPathPrefix)).All(ctx)
		if err != nil {
			return nil, err
		}
		if len(names) == 0 {
			continue
		}
		hosts := make([]*agentv1.HTTPHost, 0, len(names))
		for _, n := range names {
			hosts = append(hosts, &agentv1.HTTPHost{Hostname: n.Hostname, PathPrefix: n.PathPrefix})
		}
		connectors, ranked, err := serving(ctx, tx, r.ID)
		if err != nil {
			return nil, err
		}
		upstream := "http"
		first, err := tx.RouteTarget.Query().Where(routetarget.RouteID(r.ID), routetarget.Enabled(true)).
			Order(ent.Asc(routetarget.FieldPriority), ent.Asc(routetarget.FieldID)).First(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return nil, err
		}
		if first != nil && first.UpstreamProtocol != routetarget.UpstreamProtocolTCP {
			upstream = first.UpstreamProtocol.String()
		}
		var upstreamTLS []*agentv1.UpstreamTLS
		if upstream == "https" {
			if upstreamTLS, err = upstreamTLSOf(ctx, tx, r.ID); err != nil {
				return nil, err
			}
		}
		hostHeader := h.HostHeader
		if hostHeader == "preserve" {
			hostHeader = ""
		}
		access, err := accessOf(ctx, tx, r.ID, true)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.Resource{Id: r.ID, Kind: &agentv1.Resource_GatewayHttpRoute{GatewayHttpRoute: &agentv1.GatewayHTTPRoute{
			Hosts: hosts, UpstreamProtocol: upstream, Connectors: connectors, Websocket: h.Websocket, UpstreamTls: upstreamTLS,
			HostHeader: hostHeader, RequestHeaders: headersOf(h.RequestHeadersSet), ResponseHeaders: headersOf(h.ResponseHeadersSet),
			MaxBodyBytes: uint64(h.MaxBodyBytes), TrustedProxies: group.TrustedProxyCidrs, //nolint:gosec // G115: the schema keeps it non-negative
			Port80: h.Port80.String(), HstsMaxAgeSeconds: uint32(h.HstsMaxAgeSeconds), Access: access, //nolint:gosec // G115: the schema keeps it non-negative
			Maintenance: h.Maintenance, MaintenanceMessage: h.MaintenanceMessage, RankedConnectors: ranked}}})
	}
	return out, nil
}

// headersOf returns a route's header settings sorted by canonical name; an empty value removes
// the header.
func headersOf(set map[string]string) []*agentv1.HTTPHeader {
	out := make([]*agentv1.HTTPHeader, 0, len(set))
	for name, value := range set {
		out = append(out, &agentv1.HTTPHeader{Name: textproto.CanonicalMIMEHeaderKey(name), Value: value})
	}
	slices.SortFunc(out, func(a, b *agentv1.HTTPHeader) int { return strings.Compare(a.GetName(), b.GetName()) })
	return out
}

// upstreamTLS lists how the gateway verifies each enabled target of an https route: the target's
// server name, or else its host; its CA bundle, or else the gateway host's trust store; and its
// SPKI pin; or that it is not verified, or by its pinned key only. A pin that is not 64
// hexadecimal digits, or a pinned-key target without one, gets a pin no key matches, so the target
// fails closed.
func upstreamTLSOf(ctx context.Context, tx *ent.Tx, routeID string) ([]*agentv1.UpstreamTLS, error) {
	targets, err := tx.RouteTarget.Query().Where(routetarget.RouteID(routeID), routetarget.Enabled(true)).
		WithCaBundle().Order(ent.Asc(routetarget.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.UpstreamTLS, 0, len(targets))
	for _, t := range targets {
		u := &agentv1.UpstreamTLS{TargetId: t.ID, ServerName: t.TLSServerName, ConnectorId: t.ConnectorID}
		if u.ServerName == "" {
			u.ServerName = t.Host
		}
		switch t.TLSVerification {
		case routetarget.TLSVerificationUnverified:
			// Verified stays unset, the default, which a gateway that knows no modes applies too.
			u.Verification = agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED
			out = append(out, u)
			continue
		case routetarget.TLSVerificationPinnedKey:
			u.Verification = agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY
		default:
			if t.Edges.CaBundle != nil {
				u.CaPem = t.Edges.CaBundle.Pem
			}
		}
		if t.TLSSpkiSha256 != "" || t.TLSVerification == routetarget.TLSVerificationPinnedKey {
			pin, err := hex.DecodeString(t.TLSSpkiSha256)
			if err != nil || len(pin) != sha256.Size {
				pin = make([]byte, sha256.Size)
			}
			u.SpkiSha256 = pin
		}
		out = append(out, u)
	}
	return out, nil
}

// serving lists the connectors, sorted, with an enabled target of the route that are themselves
// enabled and not decommissioned, and the same connectors ranked: one entry per connector and
// priority of those targets, with the summed weight of its targets at that priority, a weight
// below 1 counted as 1, sorted by connector and priority (D90).
func serving(ctx context.Context, tx *ent.Tx, routeID string) ([]string, []*agentv1.RouteConnector, error) {
	targets, err := tx.RouteTarget.Query().Where(routetarget.RouteID(routeID), routetarget.Enabled(true),
		routetarget.HasConnectorWith(connector.Enabled(true), connector.DecommissionedAtIsNil())).All(ctx)
	if err != nil {
		return nil, nil, err
	}
	type tier struct {
		con      string
		priority uint32
	}
	rank := map[tier]*agentv1.RouteConnector{}
	var ids []string
	for _, t := range targets {
		k := tier{t.ConnectorID, uint32(t.Priority)} //nolint:gosec // G115: the schema keeps it small and non-negative
		if rank[k] == nil {
			rank[k] = &agentv1.RouteConnector{ConnectorId: k.con, Priority: k.priority}
			ids = append(ids, k.con)
		}
		rank[k].Weight = addWeight(rank[k].Weight, t.Weight)
	}
	tiers := slices.SortedFunc(maps.Keys(rank), func(a, b tier) int {
		return cmp.Or(strings.Compare(a.con, b.con), cmp.Compare(a.priority, b.priority))
	})
	ranked := make([]*agentv1.RouteConnector, len(tiers))
	for i, k := range tiers {
		ranked[i] = rank[k]
	}
	slices.Sort(ids)
	return slices.Compact(ids), ranked, nil
}

// maxRankWeight is the largest weight an entry carries: the gateway refuses a larger one.
const maxRankWeight = 1_000_000

// addWeight adds a target's weight, below 1 counted as 1, to an entry's, at most maxRankWeight.
func addWeight(sum uint32, weight int) uint32 {
	return min(sum+uint32(min(max(weight, 1), maxRankWeight)), maxRankWeight) //nolint:gosec // G115: bounded above
}

// connectorTargets loads the connector a for ConnectorRoutes and ConnectorGateways, its enabled
// targets on enabled routes, with the routes, and the instance settings. con is nil for any other
// agent and for a disabled or decommissioned connector, which serve nothing. Targets of routes the
// connector lacks a capability for are left out, so that both sources leave those routes out
// alike: a ConnectorGateway never names a route the snapshot does not hold.
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
		routetarget.HasRouteWith(route.Enabled(true), route.TypeIn(route.TypeTCP, route.TypeUDP, route.TypeTCPUDP, route.TypeHTTP, route.TypeTLSPassthrough))).WithRoute().All(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if targets, err = servable(ctx, tx, a, targets); err != nil {
		return nil, nil, nil, err
	}
	inst, _, err = settings.Instance(ctx, tx.Client())
	if err != nil {
		return nil, nil, nil, err
	}
	return con, targets, inst, nil
}

// ConnectorRoutes compiles a connector's routes: for every enabled route with an enabled target on
// it, its type, its targets and the effective transport. A disabled or decommissioned connector
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
	https := map[string]bool{} // routes whose targets speak https
	for _, t := range targets {
		https[t.RouteID] = https[t.RouteID] || t.UpstreamProtocol == routetarget.UpstreamProtocolHTTPS
	}
	out := make([]*agentv1.Resource, 0, len(ids))
	for _, id := range ids {
		cr := byRoute[id]
		if err := addHealthCheck(ctx, tx, id, cr, https[id]); err != nil {
			return nil, err
		}
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

// addHealthCheck gives a connector's route its health check, if it has one (docs/03-connections.md,
// "Target health"), with its interval and timeout as they take effect, so that the connector's
// bounds see what the API checked: an http check sends the route's host header override as Host,
// else its first hostname that is not a wildcard, and of an http route whose targets speak https
// it speaks TLS, verified by each target's settings as the gateway verifies the route's traffic.
func addHealthCheck(ctx context.Context, tx *ent.Tx, routeID string, cr *agentv1.ConnectorRoute, https bool) error {
	c, err := tx.HealthCheck.Query().Where(healthcheck.RouteID(routeID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	u := func(v int) uint32 { return uint32(v) } //nolint:gosec // G115: the schema bounds them
	interval, timeout := CheckTimes(c.IntervalSeconds, c.TimeoutSeconds)
	hc := &agentv1.HealthCheck{Type: string(c.Type), Port: u(c.Port), Path: c.HTTPPath, StatusMin: u(c.ExpectedStatusMin),
		StatusMax: u(c.ExpectedStatusMax), IntervalMs: u(interval) * 1000, TimeoutMs: u(timeout) * 1000,
		UnhealthyThreshold: u(c.UnhealthyThreshold), HealthyThreshold: u(c.HealthyThreshold)}
	if c.Type == healthcheck.TypeHTTP && cr.GetType() == string(route.TypeHTTP) {
		// The override, else the first exact hostname; a wildcard names no host to ask for, so a
		// route with only wildcards leaves the connector to send the target's address. Only a
		// value the connector accepts as Host is sent.
		names, err := tx.RouteHostname.Query().Where(routehostname.RouteID(routeID), routehostname.Not(routehostname.HostnameHasPrefix("*."))).
			Order(ent.Asc(routehostname.FieldHostname)).Select(routehostname.FieldHostname).Strings(ctx)
		if err != nil {
			return err
		}
		h, err := tx.RouteHTTP.Query().Where(routehttp.RouteID(routeID)).Only(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return err
		}
		if h != nil && h.HostHeader != "preserve" {
			names = append([]string{h.HostHeader}, names...)
		}
		if i := slices.IndexFunc(names, httpguts.ValidHostHeader); i >= 0 {
			hc.Host = names[i]
		}
		if https {
			hc.Https = true
			tls, err := upstreamTLSOf(ctx, tx, routeID)
			if err != nil {
				return err
			}
			for _, t := range cr.GetTargets() {
				for _, u := range tls {
					if u.GetTargetId() == t.GetId() {
						t.Tls = u
					}
				}
			}
		}
	}
	cr.HealthCheck = hc
	return nil
}

// The bounds of a health check (docs/03-connections.md, "Timeouts, keepalive and backoff"): 10 s
// unless set, and a timeout of 5 s unless set, but always below the interval.
const (
	defCheckIntervalSeconds = 10
	defCheckTimeoutSeconds  = 5
)

// CheckTimes are a health check's interval and timeout in seconds as they take effect: 0 is the
// default, and the default timeout stays below the interval.
func CheckTimes(intervalSeconds, timeoutSeconds int) (int, int) {
	interval := cmp.Or(intervalSeconds, defCheckIntervalSeconds)
	return interval, cmp.Or(timeoutSeconds, min(defCheckTimeoutSeconds, interval-1))
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
