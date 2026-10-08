// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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
	routes   *TCPRoutes
	pass     *Passthrough
	sessions *Sessions
	assign   *assignment
	revision atomic.Pointer[agentv1.Revision]
}

// NewApplier returns the gateway's applier and the Assignment for its Sessions; Bind connects
// them.
func NewApplier() (*Applier, Assignment) {
	a := &Applier{assign: &assignment{}}
	return a, a.assign
}

// Bind gives the applier the route listeners, the passthrough routes and the data sessions it
// updates; any may be nil.
func (a *Applier) Bind(routes *TCPRoutes, pass *Passthrough, sessions *Sessions) {
	a.routes, a.pass, a.sessions = routes, pass, sessions
}

// Revision returns the revision of the applied snapshot; it is TCPOptions.Revision.
func (a *Applier) Revision() *agentv1.Revision { return a.revision.Load() }

// Validate implements agent.Applier: every resource must be one a gateway runs, every port a
// valid one used once, every hostname a normalised one used once, and every connector ID present.
func (a *Applier) Validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError {
	var errs []*agentv1.SnapshotError
	ports := map[uint32]string{}
	hostnames := map[string]string{}
	for _, res := range snap.GetResources() {
		if p := res.GetGatewayPassthroughRoute(); p != nil {
			if len(p.GetHostnames()) == 0 {
				errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: "a passthrough route without hostnames"})
			}
			for _, h := range p.GetHostnames() {
				switch n, err := domains.Normalize(h, true); {
				case err != nil || n != h:
					errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: fmt.Sprintf("hostname %q is not normalised", h)})
				case hostnames[h] != "":
					errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: fmt.Sprintf("hostname %s is also a hostname of %s", h, hostnames[h])})
				default:
					hostnames[h] = res.GetId()
				}
			}
			if slices.Contains(p.GetConnectors(), "") {
				errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: "an empty connector ID"})
			}
			continue
		}
		r := res.GetGatewayTcpRoute()
		if r == nil {
			errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: fmt.Sprintf("a gateway does not run %T resources", res.GetKind())})
			continue
		}
		switch p := r.GetPort(); {
		case p == 0 || p > 65535:
			errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: fmt.Sprintf("port %d is not a TCP port", p)})
		case ports[p] != "":
			errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: fmt.Sprintf("port %d is also the port of %s", p, ports[p])})
		default:
			ports[p] = res.GetId()
		}
		if slices.Contains(r.GetConnectors(), "") {
			errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: "an empty connector ID"})
		}
	}
	return errs
}

// Apply implements agent.Applier: the new assignment takes effect first, then the routes, then
// the data sessions of connectors no longer assigned are closed.
func (a *Applier) Apply(_ context.Context, snap *agentv1.Snapshot, _ agent.Changes) []*agentv1.ResourceStatus {
	next := &assigned{known: map[string]bool{}, routes: map[string][]string{}}
	var routes []TCPRoute
	var passthrough []PassthroughRoute
	for _, res := range snap.GetResources() {
		var connectors []string
		if p := res.GetGatewayPassthroughRoute(); p != nil {
			connectors = p.GetConnectors()
			passthrough = append(passthrough, PassthroughRoute{ID: res.GetId(), Hostnames: p.GetHostnames()})
		} else {
			r := res.GetGatewayTcpRoute()
			connectors = r.GetConnectors()
			routes = append(routes, TCPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
				IdleTimeout: time.Duration(r.GetIdleTimeoutSeconds()) * time.Second})
		}
		next.routes[res.GetId()] = slices.Clone(connectors)
		for _, c := range connectors {
			next.known[c] = true
		}
	}
	a.revision.Store(proto.Clone(snap.GetRevision()).(*agentv1.Revision))
	a.assign.cur.Store(next)
	var status []*agentv1.ResourceStatus
	if a.routes != nil {
		status = a.routes.Apply(routes)
	}
	if a.pass != nil {
		a.pass.Apply(passthrough)
	}
	if a.sessions != nil {
		a.sessions.Recheck()
	}
	return status
}
