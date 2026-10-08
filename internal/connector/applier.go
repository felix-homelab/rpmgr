// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
)

// Applier runs a connector's snapshots (docs/03-connections.md, "Configuration reconciliation"):
// its routes' targets and its data sessions to the gateways of those routes. It implements
// agent.Applier.
type Applier struct {
	targets  *Targets
	sessions *Sessions
}

// NewApplier returns the applier of a connector's targets and data sessions.
func NewApplier(targets *Targets, sessions *Sessions) *Applier {
	return &Applier{targets: targets, sessions: sessions}
}

func transportOf(p agentv1.TransportPolicy) (string, bool) {
	switch p {
	case agentv1.TransportPolicy_TRANSPORT_POLICY_AUTO:
		return TransportAuto, true
	case agentv1.TransportPolicy_TRANSPORT_POLICY_QUIC:
		return TransportQUIC, true
	case agentv1.TransportPolicy_TRANSPORT_POLICY_H2:
		return TransportH2, true
	}
	return "", false
}

// Validate implements agent.Applier: every resource must be a route or a gateway; a route needs a
// known transport and targets that are an address and port or an absolute socket path with a
// known PROXY protocol version; a gateway needs host:port endpoints and names only routes of the
// snapshot.
func (a *Applier) Validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError {
	var errs []*agentv1.SnapshotError
	bad := func(id, format string, args ...any) {
		errs = append(errs, &agentv1.SnapshotError{ResourceId: id, Message: fmt.Sprintf(format, args...)})
	}
	routes := map[string]bool{}
	for _, res := range snap.GetResources() {
		if res.GetConnectorRoute() != nil {
			routes[res.GetId()] = true
		}
	}
	for _, res := range snap.GetResources() {
		id := res.GetId()
		switch {
		case res.GetConnectorRoute() != nil:
			r := res.GetConnectorRoute()
			if r.GetType() != "tcp" && r.GetType() != "tls_passthrough" {
				bad(id, "route type %q is not served by this version", r.GetType())
			}
			if _, ok := transportOf(r.GetTransport()); !ok {
				bad(id, "transport %s", r.GetTransport())
			}
			if len(r.GetTargets()) == 0 {
				bad(id, "a route without targets")
			}
			for _, t := range r.GetTargets() {
				switch {
				case t.GetUnixPath() != "" && (t.GetHost() != "" || t.GetPort() != 0):
					bad(id, "target %s has both a socket path and an address", t.GetId())
				case t.GetUnixPath() != "" && (!filepath.IsAbs(t.GetUnixPath()) || filepath.Clean(t.GetUnixPath()) != t.GetUnixPath()):
					bad(id, "target %s: socket path %q is not a clean absolute path", t.GetId(), t.GetUnixPath())
				case t.GetUnixPath() == "" && (t.GetHost() == "" || t.GetPort() == 0 || t.GetPort() > 65535):
					bad(id, "target %s needs a host and a port", t.GetId())
				}
				switch t.GetProxyProtocol() {
				case "", "none", "v1", "v2":
				default:
					bad(id, "target %s: PROXY protocol %q", t.GetId(), t.GetProxyProtocol())
				}
			}
		case res.GetConnectorGateway() != nil:
			g := res.GetConnectorGateway()
			if len(g.GetTunnelEndpoints()) == 0 {
				bad(id, "a gateway without tunnel endpoints")
			}
			for _, ep := range g.GetTunnelEndpoints() {
				host, port, err := net.SplitHostPort(ep)
				if n, perr := strconv.Atoi(port); err != nil || perr != nil || host == "" || n < 1 || n > 65535 {
					bad(id, "tunnel endpoint %q is not host:port", ep)
				}
			}
			for _, r := range g.GetRoutes() {
				if !routes[r] {
					bad(id, "route %s is not in the snapshot", r)
				}
			}
		default:
			bad(id, "a connector does not run %T resources", res.GetKind())
		}
	}
	return errs
}

// Apply implements agent.Applier: the targets first, so that each route's readiness is known
// before a data session announces it, then the gateways.
func (a *Applier) Apply(_ context.Context, snap *agentv1.Snapshot, _ agent.Changes) []*agentv1.ResourceStatus {
	var routes []Route
	transport := map[string]string{}
	var gateways []Gateway
	for _, res := range snap.GetResources() {
		if r := res.GetConnectorRoute(); r != nil {
			transport[res.GetId()], _ = transportOf(r.GetTransport())
			route := Route{ID: res.GetId()}
			for _, t := range r.GetTargets() {
				route.Targets = append(route.Targets, Target{ID: t.GetId(), Host: t.GetHost(), Port: uint16(t.GetPort()), //nolint:gosec // G115: Validate bounds the port
					UnixPath: t.GetUnixPath(), ProxyProtocol: t.GetProxyProtocol(), Weight: t.GetWeight(), Priority: t.GetPriority()})
			}
			routes = append(routes, route)
		}
	}
	for _, res := range snap.GetResources() {
		if g := res.GetConnectorGateway(); g != nil {
			gw := Gateway{ID: res.GetId(), Endpoints: g.GetTunnelEndpoints(), Routes: map[string]string{}}
			for _, r := range g.GetRoutes() {
				gw.Routes[r] = transport[r]
			}
			gateways = append(gateways, gw)
		}
	}
	a.targets.Set(routes)
	a.sessions.Set(gateways)
	return append(a.targets.Status(), a.sessions.Status()...)
}
