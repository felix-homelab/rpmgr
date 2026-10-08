// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/domains"
)

// assignment is the connector assignment of the applied snapshot: which connectors serve which
// route. It implements Assignment.
type assignment struct {
	cur atomic.Pointer[assigned]
}

type assigned struct {
	known  map[string]bool
	routes map[string][]string
}

// Known implements Assignment.
func (a *assignment) Known(connectorID string) bool {
	s := a.cur.Load()
	return s != nil && s.known[connectorID]
}

// Connectors implements Assignment.
func (a *assignment) Connectors(routeID string) []string {
	s := a.cur.Load()
	if s == nil {
		return nil
	}
	return s.routes[routeID]
}

// Applier runs a gateway's snapshots (docs/03-connections.md, "Configuration reconciliation"):
// its tcp routes on their ports and the connector assignment its data sessions are admitted
// against. It implements agent.Applier.
type Applier struct {
	served   Served
	assign   *assignment
	revision atomic.Pointer[agentv1.Revision]
}

// NewApplier returns the gateway's applier and the Assignment for its Sessions; Bind connects
// them.
func NewApplier() (*Applier, Assignment) {
	a := &Applier{assign: &assignment{}}
	return a, a.assign
}

// Served is what the applier updates; any part may be nil.
type Served struct {
	TCP          *TCPRoutes
	UDP          *UDPRoutes
	Passthrough  *Passthrough
	Certificates *Certificates
	Sessions     *Sessions
}

// Bind gives the applier what it updates.
func (a *Applier) Bind(s Served) { a.served = s }

// Revision returns the revision of the applied snapshot; it is TCPOptions.Revision.
func (a *Applier) Revision() *agentv1.Revision { return a.revision.Load() }

// Validate implements agent.Applier: every resource must be one a gateway runs, every port a
// valid one used once per protocol, every hostname a normalised one used once, and every connector
// ID present.
func (a *Applier) Validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError {
	var errs []*agentv1.SnapshotError
	bad := func(id, format string, args ...any) {
		errs = append(errs, &agentv1.SnapshotError{ResourceId: id, Message: fmt.Sprintf(format, args...)})
	}
	ports := map[string]map[uint32]string{"TCP": {}, "UDP": {}}
	port := func(id, proto string, p uint32) {
		switch {
		case p == 0 || p > 65535:
			bad(id, "port %d is not a %s port", p, proto)
		case ports[proto][p] != "":
			bad(id, "%s port %d is also the port of %s", proto, p, ports[proto][p])
		default:
			ports[proto][p] = id
		}
	}
	hostnames := map[string]string{}
	for _, res := range snap.GetResources() {
		id := res.GetId()
		var connectors []string
		switch {
		case res.GetGatewayTcpRoute() != nil:
			port(id, "TCP", res.GetGatewayTcpRoute().GetPort())
			connectors = res.GetGatewayTcpRoute().GetConnectors()
		case res.GetGatewayUdpRoute() != nil:
			port(id, "UDP", res.GetGatewayUdpRoute().GetPort())
			connectors = res.GetGatewayUdpRoute().GetConnectors()
		case res.GetGatewayCertificate() != nil:
			c := res.GetGatewayCertificate()
			if len(c.GetContentSha256()) != sha256.Size {
				bad(id, "a certificate without a SHA-256 content hash")
			}
			if len(c.GetHostnames()) == 0 {
				bad(id, "a certificate without hostnames")
			}
			for _, h := range c.GetHostnames() {
				if n, err := domains.Normalize(h, true); err != nil || n != h {
					bad(id, "hostname %q is not normalised", h)
				}
			}
		case res.GetGatewayPassthroughRoute() != nil:
			p := res.GetGatewayPassthroughRoute()
			if len(p.GetHostnames()) == 0 {
				bad(id, "a passthrough route without hostnames")
			}
			for _, h := range p.GetHostnames() {
				switch n, err := domains.Normalize(h, true); {
				case err != nil || n != h:
					bad(id, "hostname %q is not normalised", h)
				case hostnames[h] != "":
					bad(id, "hostname %s is also a hostname of %s", h, hostnames[h])
				default:
					hostnames[h] = id
				}
			}
			connectors = p.GetConnectors()
		default:
			bad(id, "a gateway does not run %T resources", res.GetKind())
		}
		if slices.Contains(connectors, "") {
			bad(id, "an empty connector ID")
		}
	}
	return errs
}

// Apply implements agent.Applier: the new assignment takes effect first, then the routes, then
// the data sessions of connectors no longer assigned are closed.
func (a *Applier) Apply(ctx context.Context, snap *agentv1.Snapshot, _ agent.Changes) []*agentv1.ResourceStatus {
	next := &assigned{known: map[string]bool{}, routes: map[string][]string{}}
	var (
		tcp         []TCPRoute
		udp         []UDPRoute
		passthrough []PassthroughRoute
		certs       []CertificateRoute
	)
	for _, res := range snap.GetResources() {
		var connectors []string
		switch {
		case res.GetGatewayTcpRoute() != nil:
			r := res.GetGatewayTcpRoute()
			connectors = r.GetConnectors()
			tcp = append(tcp, TCPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				IdleTimeout: time.Duration(r.GetIdleTimeoutSeconds()) * time.Second})
		case res.GetGatewayUdpRoute() != nil:
			r := res.GetGatewayUdpRoute()
			connectors = r.GetConnectors()
			udp = append(udp, UDPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				FlowIdle: time.Duration(r.GetFlowIdleTimeoutSeconds()) * time.Second})
		case res.GetGatewayCertificate() != nil:
			c := res.GetGatewayCertificate()
			certs = append(certs, CertificateRoute{ID: res.GetId(), ContentSHA256: c.GetContentSha256(), Hostnames: c.GetHostnames()})
			continue // serves no route of its own
		case res.GetGatewayPassthroughRoute() != nil:
			p := res.GetGatewayPassthroughRoute()
			connectors = p.GetConnectors()
			passthrough = append(passthrough, PassthroughRoute{ID: res.GetId(), Hostnames: p.GetHostnames()})
		}
		next.routes[res.GetId()] = slices.Clone(connectors)
		for _, c := range connectors {
			next.known[c] = true
		}
	}
	a.revision.Store(proto.Clone(snap.GetRevision()).(*agentv1.Revision))
	a.assign.cur.Store(next)
	var status []*agentv1.ResourceStatus
	s := a.served
	if s.TCP != nil {
		status = append(status, s.TCP.Apply(tcp)...)
	}
	if s.UDP != nil {
		status = append(status, s.UDP.Apply(udp)...)
	}
	if s.Passthrough != nil {
		s.Passthrough.Apply(passthrough)
	}
	if s.Certificates != nil {
		status = append(status, s.Certificates.Apply(ctx, certs)...)
	}
	if s.Sessions != nil {
		s.Sessions.Recheck()
	}
	return status
}
