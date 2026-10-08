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

// Bind gives the applier the route listeners and the data sessions it updates.
func (a *Applier) Bind(routes *TCPRoutes, sessions *Sessions) {
	a.routes, a.sessions = routes, sessions
}

// Revision returns the revision of the applied snapshot; it is TCPOptions.Revision.
func (a *Applier) Revision() *agentv1.Revision { return a.revision.Load() }

// Validate implements agent.Applier: every resource must be one a gateway runs, every port a
// valid one used once, and every connector ID present.
func (a *Applier) Validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError {
	var errs []*agentv1.SnapshotError
	ports := map[uint32]string{}
	for _, res := range snap.GetResources() {
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
	for _, res := range snap.GetResources() {
		r := res.GetGatewayTcpRoute()
		next.routes[res.GetId()] = slices.Clone(r.GetConnectors())
		for _, c := range r.GetConnectors() {
			next.known[c] = true
		}
		routes = append(routes, TCPRoute{ID: res.GetId(), Port: uint16(r.GetPort()), //nolint:gosec // G115: Validate bounds the port
			IdleTimeout: time.Duration(r.GetIdleTimeoutSeconds()) * time.Second})
	}
	a.revision.Store(proto.Clone(snap.GetRevision()).(*agentv1.Revision))
	a.assign.cur.Store(next)
	var status []*agentv1.ResourceStatus
	if a.routes != nil {
		status = a.routes.Apply(routes)
	}
	if a.sessions != nil {
		a.sessions.Recheck()
	}
	return status
}
