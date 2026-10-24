// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

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
// known PROXY protocol version; a udp or tcp_udp route's targets are addresses, a udp route's
// without a PROXY header (a tcp_udp route's header goes on its TCP connections only); a gateway
// needs host:port endpoints and names only routes of the snapshot.
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
			udp := r.GetType() == "udp" || r.GetType() == "tcp_udp"
			if !slices.Contains([]string{"tcp", "udp", "tcp_udp", "http", "tls_passthrough"}, r.GetType()) {
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
				case "", "none":
				case "v1", "v2":
					if r.GetType() == "udp" {
						bad(id, "target %s: a udp target has no PROXY protocol header", t.GetId())
					}
				default:
					bad(id, "target %s: PROXY protocol %q", t.GetId(), t.GetProxyProtocol())
				}
				if udp && t.GetUnixPath() != "" {
					bad(id, "target %s: a udp target is an address, not a socket path", t.GetId())
				}
				if hc := r.GetHealthCheck(); hc.GetHttps() && t.GetTls() == nil {
					bad(id, "target %s: an https health check without the target's TLS settings", t.GetId())
				}
			}
			if hc := r.GetHealthCheck(); hc != nil {
				if err := validCheck(hc, r.GetType()); err != nil {
					bad(id, "health check: %v", err)
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

// The bounds of a health check (docs/03-connections.md, "Timeouts, keepalive and backoff").
const minCheckInterval = 2 * time.Second

// validCheck checks a route's health check: tcp, or http with a path and Host a request can carry
// and a range of statuses; a udp route only a tcp check of a port it names; an interval of at least
// minCheckInterval and a timeout below it.
func validCheck(c *agentv1.HealthCheck, routeType string) error {
	ms := func(v uint32) time.Duration { return time.Duration(v) * time.Millisecond }
	interval, timeout := cmp.Or(ms(c.GetIntervalMs()), checkInterval), cmp.Or(ms(c.GetTimeoutMs()), checkTimeout)
	switch {
	case c.GetType() != "tcp" && c.GetType() != "http":
		return fmt.Errorf("type %q", c.GetType())
	case routeType == "udp" && (c.GetType() != "tcp" || c.GetPort() == 0):
		return errors.New("a udp route has only a tcp check of a port it names")
	case c.GetPort() > 65535:
		return fmt.Errorf("port %d", c.GetPort())
	case interval < minCheckInterval || timeout >= interval:
		return fmt.Errorf("an interval of %v and a timeout of %v", interval, timeout)
	case c.GetType() == "tcp":
		return nil
	case c.GetPath() != "" && (!strings.HasPrefix(c.GetPath(), "/") || strings.ContainsAny(c.GetPath(), " \r\n\t")):
		return fmt.Errorf("path %q", c.GetPath())
	case c.GetHost() != "" && !httpguts.ValidHostHeader(c.GetHost()):
		return fmt.Errorf("host %q", c.GetHost())
	case (c.GetStatusMin() == 0) != (c.GetStatusMax() == 0) || c.GetStatusMin() > c.GetStatusMax() || c.GetStatusMax() > 599 ||
		c.GetStatusMin() != 0 && c.GetStatusMin() < 100:
		return fmt.Errorf("statuses %d to %d", c.GetStatusMin(), c.GetStatusMax())
	}
	return nil
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
			route := Route{ID: res.GetId(), UDP: r.GetType() == "udp", Both: r.GetType() == "tcp_udp"}
			for _, t := range r.GetTargets() {
				route.Targets = append(route.Targets, Target{ID: t.GetId(), Host: t.GetHost(), Port: uint16(t.GetPort()), //nolint:gosec // G115: Validate bounds the port
					UnixPath: t.GetUnixPath(), ProxyProtocol: t.GetProxyProtocol(), Weight: t.GetWeight(), Priority: t.GetPriority(),
					TLS: tlsOf(t.GetTls())})
			}
			route.Check = healthCheckOf(r.GetHealthCheck())
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
	return a.Readiness()
}

// Readiness returns the resources that are not ready: routes whose targets the local policy
// blocks, and routes whose pinned transport has no session.
func (a *Applier) Readiness() []*agentv1.ResourceStatus {
	return append(a.targets.Status(), a.sessions.Status()...)
}
