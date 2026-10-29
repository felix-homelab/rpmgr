// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"slices"
	"strings"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentstate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectlistener"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/healthcheck"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

// wssUnavailable is routes.WSSUnavailable, which newRouteStatuses's parameter routes hides.
var wssUnavailable = routes.WSSUnavailable

// statusWindow is how many of the org's newest revisions a route status reads to find the latest
// change of each route. An agent further behind is pending or in error with every route it serves.
var statusWindow = 1000

// Reasons of RouteNotServing besides the agents' own.
const (
	notServingOffline       = "OFFLINE"
	notServingDisabled      = "DISABLED"
	notServingNoDataSession = "NO_DATA_SESSION"
	// notServingTransportUnavailable is the connectors' own reason, which the controller gives a
	// connector of a release without WSS for a route on wss.
	notServingTransportUnavailable = "TRANSPORT_UNAVAILABLE"
	// notServingCertificatePending: the route's TLS CONNECT listener has no certificate yet.
	notServingCertificatePending = "CERTIFICATE_PENDING"
)

// routeStatuses derives the status of an org's routes from what their agents report
// (docs/06-data-model.md, "Derived route status"). It reads the org's agents once for all routes.
type routeStatuses struct {
	now      time.Time
	epoch    string
	gateways []*ent.Gateway
	enabled  map[string]bool // connectors
	online   map[string]bool
	states   map[string]*ent.AgentState
	notReady map[[2]string]*ent.ResourceStatus // by agent and resource
	links    map[[2]string]bool                // gateway and connector with a data session
	targets  map[string][]*ent.RouteTarget     // by route
	// missing are the capabilities an online agent lacks for a route, by agent and route
	// (routes.Gate): the route is left out of its snapshot.
	missing map[[2]string][]string
	// maintenance are the http routes in maintenance.
	maintenance map[string]bool
	// noWSS are the online connectors, by connector and route, that lack the capability tunnel.wss
	// for a route whose effective transport on them is wss: their snapshot leaves it out.
	noWSS map[[2]string]bool
	// certPending are the routes on a TLS CONNECT listener without a certificate, with the
	// listener's hostname and the last ACME error as detail.
	certPending map[string]string
	// checked are the routes with a health check, and caps the capabilities of each agent's
	// session, which say whether a connector runs checks (D133).
	checked map[string]bool
	caps    map[string][]string
	// changed is the newest revision that changed each resource, among the revisions after the
	// oldest one an online agent has applied. With more of them than statusWindow, cut is the
	// oldest one read, and a change not read counts as that one.
	changed map[string]int64
	cut     int64
}

// newRouteStatuses reads what the agents of org report about routes. sys reads the revisions,
// which are instance rows.
func newRouteStatuses(ctx, sys context.Context, c *ent.Client, org string, routes []*ent.Route, now time.Time) (*routeStatuses, error) {
	v := &routeStatuses{now: now, enabled: map[string]bool{}, online: map[string]bool{}, states: map[string]*ent.AgentState{},
		notReady: map[[2]string]*ent.ResourceStatus{}, links: map[[2]string]bool{}, targets: map[string][]*ent.RouteTarget{},
		changed: map[string]int64{}, maintenance: map[string]bool{}, missing: map[[2]string][]string{}, checked: map[string]bool{},
		noWSS: map[[2]string]bool{}, certPending: map[string]string{}}
	inst, err := c.Instance.Get(sys, 1)
	if err != nil {
		return nil, err
	}
	v.epoch = inst.DbEpoch
	if v.gateways, err = c.Gateway.Query().Where(gateway.OrgID(org), gateway.DecommissionedAtIsNil()).All(ctx); err != nil {
		return nil, err
	}
	cons, err := c.Connector.Query().Where(connector.OrgID(org), connector.DecommissionedAtIsNil()).All(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]*ent.Connector{}
	for _, x := range cons {
		byID[x.ID] = x
	}
	var ids []string
	for _, g := range v.gateways {
		ids = append(ids, g.ID)
	}
	for _, x := range cons {
		ids, v.enabled[x.ID] = append(ids, x.ID), x.Enabled
	}
	sessions, err := c.AgentSession.Query().Where(agentsession.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	caps := map[string][]string{}
	for _, s := range sessions {
		v.online[s.ID] = schema.AgentSessionLive(s.DisconnectedAt, s.LastSeenAt, now)
		caps[s.ID] = s.Capabilities
	}
	states, err := c.AgentState.Query().Where(agentstate.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, st := range states {
		v.states[st.ID] = st
	}
	floor := int64(-1)
	for _, id := range ids {
		if !v.online[id] {
			continue
		}
		applied := int64(0) // of no revision of this epoch
		if st := v.states[id]; st != nil && st.AppliedDbEpoch == v.epoch {
			applied = st.AppliedSeq
		}
		if floor < 0 || applied < floor {
			floor = applied
		}
	}
	nr, err := c.ResourceStatus.Query().Where(resourcestatus.OrgID(org)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range nr {
		v.notReady[[2]string{r.AgentID, r.ResourceID}] = r
	}
	ds, err := c.DataSession.Query().Where(datasession.OrgID(org)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		v.links[[2]string{d.GatewayID, d.ConnectorID}] = true
	}
	routeIDs := make([]string, len(routes))
	for i, r := range routes {
		routeIDs[i] = r.ID
	}
	ts, err := c.RouteTarget.Query().Where(routetarget.RouteIDIn(routeIDs...)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		v.targets[t.RouteID] = append(v.targets[t.RouteID], t)
	}
	inMaintenance, err := c.RouteHTTP.Query().Where(routehttp.RouteIDIn(routeIDs...), routehttp.Maintenance(true)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range inMaintenance {
		v.maintenance[h.RouteID] = true
	}
	checked, err := c.HealthCheck.Query().Where(healthcheck.RouteIDIn(routeIDs...)).Select(healthcheck.FieldRouteID).Strings(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range checked {
		v.checked[id] = true
	}
	v.caps = caps
	if err := v.readMissing(ctx, c, routes, caps); err != nil {
		return nil, err
	}
	defaults, _, err := settings.Instance(sys, c)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		for _, t := range v.targets[r.ID] {
			if x := byID[t.ConnectorID]; x != nil && v.online[x.ID] && wssUnavailable(r, x, defaults, caps[x.ID]) {
				v.noWSS[[2]string{x.ID, r.ID}] = true
			}
		}
	}
	if err := v.readCertificates(ctx, c, routeIDs); err != nil {
		return nil, err
	}
	return v, v.readChanges(sys, c, org, max(floor, 0))
}

// readCertificates notes the routes on a TLS CONNECT listener that has no certificate to present:
// none it names that is active, no uploaded one that covers its hostname, and no ACME one yet.
func (v *routeStatuses) readCertificates(ctx context.Context, c *ent.Client, routeIDs []string) error {
	rows, err := c.RouteTCP.Query().Where(routetcp.RouteIDIn(routeIDs...),
		routetcp.HasListenerWith(connectlistener.AuthModeEQ(connectlistener.AuthModeTLSBasic))).
		WithListener(func(q *ent.ConnectListenerQuery) { q.WithCertificate() }).All(ctx)
	if err != nil {
		return err
	}
	for _, t := range rows {
		l := t.Edges.Listener
		crt, err := certs.ListenerCertificate(ctx, c.Certificate, l)
		if err != nil || crt != nil {
			if err != nil {
				return err
			}
			continue
		}
		detail := l.Hostname
		if l.CertificateID == nil {
			acme, err := certs.ACMEOf(ctx, c.Certificate, l.OrgID, l.Hostname)
			if err != nil {
				return err
			}
			if acme != nil && acme.LastError != "" {
				detail += ": " + acme.LastError
			}
		}
		v.certPending[t.RouteID] = detail
	}
	return nil
}

// readMissing notes the capabilities each online agent of a route lacks for it, from the
// capabilities of its control session.
func (v *routeStatuses) readMissing(ctx context.Context, c *ent.Client, routeRows []*ent.Route, caps map[string][]string) error {
	for _, r := range routeRows {
		reqs, err := routes.Required(ctx, c, r.ID)
		if err != nil {
			return err
		}
		if len(reqs) == 0 {
			continue
		}
		note := func(id string, kind pki.Kind) {
			if !v.online[id] {
				return
			}
			if m := routes.Missing(reqs, kind, func(cp string) bool { return slices.Contains(caps[id], cp) }); len(m) > 0 {
				v.missing[[2]string{id, r.ID}] = m
			}
		}
		for _, g := range v.gateways {
			if g.GatewayGroupID == r.GatewayGroupID {
				note(g.ID, pki.KindGateway)
			}
		}
		for _, t := range v.targets[r.ID] {
			note(t.ConnectorID, pki.KindConnector)
		}
	}
	return nil
}

// readChanges notes the newest revision of org after floor that changed each resource.
func (v *routeStatuses) readChanges(sys context.Context, c *ent.Client, org string, floor int64) error {
	revs, err := c.ConfigRevision.Query().Where(configrevision.OrgID(org), configrevision.DbEpoch(v.epoch), configrevision.IDGT(floor)).
		Order(ent.Desc(configrevision.FieldID)).Limit(statusWindow).All(sys)
	if err != nil {
		return err
	}
	if len(revs) == statusWindow {
		v.cut = revs[len(revs)-1].ID
	}
	for _, r := range revs {
		for _, id := range r.ChangedResources {
			if _, ok := v.changed[id]; !ok {
				v.changed[id] = r.ID
			}
		}
	}
	return nil
}

// of is the status of route r.
func (v *routeStatuses) of(r *ent.Route) *rpmgrv1.RouteStatus {
	out := &rpmgrv1.RouteStatus{State: rpmgrv1.RouteState_ROUTE_STATE_DISABLED}
	if !r.Enabled {
		return out
	}
	// The latest change of the route is its newest revision, or one of its targets'. One older
	// than every online agent's applied revision is not read, and 0 stands for it.
	last := max(v.cut, v.changed[r.ID])
	var targets []*ent.RouteTarget
	for _, t := range v.targets[r.ID] {
		last = max(last, v.changed[t.ID])
		if t.Enabled {
			targets = append(targets, t)
		}
	}
	rev := store.Revision{DBEpoch: v.epoch, Seq: last}

	// Whether the online agents of the route run its latest change.
	pending, checked := false, map[string]bool{}
	check := func(id string) {
		if !v.online[id] || checked[id] {
			return
		}
		checked[id] = true
		switch snapshot.RevisionStatus(v.states[id], rev, v.now) {
		case snapshot.ApplyApplied:
		case snapshot.ApplyRejected:
			a := &rpmgrv1.AgentApplyStatus{AgentId: id, State: rpmgrv1.ApplyState_APPLY_STATE_REJECTED}
			for _, e := range v.states[id].LastRejection {
				a.Errors = append(a.Errors, &rpmgrv1.ApplyError{ResourceId: e["resource_id"], Message: e["message"]})
			}
			out.Rejections = append(out.Rejections, a)
		default:
			pending = true
		}
	}

	// Targets: ready when the connector is online and reports the route ready.
	ready := map[string]bool{} // connectors of ready targets
	for _, t := range targets {
		out.TargetsTotal++
		enabled, known := v.enabled[t.ConnectorID]
		switch nr := v.notReady[[2]string{t.ConnectorID, r.ID}]; {
		case !known || !enabled:
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: t.ID, Reason: notServingDisabled})
		case !v.online[t.ConnectorID]:
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: t.ID, Reason: notServingOffline})
		case v.noWSS[[2]string{t.ConnectorID, r.ID}]:
			// Its release cannot dial WSS, so its snapshot leaves the route out.
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: t.ID, Reason: notServingTransportUnavailable,
				Detail: "wss"})
		case v.missing[[2]string{t.ConnectorID, r.ID}] != nil:
			out.NotServing = append(out.NotServing, capabilityMissing(t.ID, v.missing[[2]string{t.ConnectorID, r.ID}]))
		case nr != nil:
			// The target's own row, from its health checks, says more than the route's.
			if nt := v.notReady[[2]string{t.ConnectorID, t.ID}]; nt != nil {
				nr = nt
			}
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: t.ID, Reason: notReadyReason(nr.Reason), Detail: nr.Detail})
		case v.notReady[[2]string{t.ConnectorID, t.ID}] != nil:
			// The route is ready on the connector, but this target failed its health check.
			nt := v.notReady[[2]string{t.ConnectorID, t.ID}]
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: t.ID, Reason: notReadyReason(nt.Reason), Detail: nt.Detail})
			if nt.Reason == agentv1.NotReadyReason_NOT_READY_REASON_TARGET_UNKNOWN.String() {
				// Not checked yet: it serves when no other target of its priority is healthy (D156).
				out.TargetsReady++
			}
			ready[t.ConnectorID] = true // its other targets serve
		default:
			out.TargetsReady++
			ready[t.ConnectorID] = true
		}
		if v.checked[r.ID] && v.online[t.ConnectorID] && !slices.Contains(v.caps[t.ConnectorID], agentproto.CapHealthActive) {
			out.HealthNotChecked = append(out.HealthNotChecked, t.ID)
		}
		if known && enabled {
			check(t.ConnectorID)
		}
	}

	// Gateways: serving when online, reporting the route ready, and linked to a ready target. In
	// maintenance one that is online and reports it ready answers for it without a target.
	answering := 0
	for _, g := range v.gateways {
		if g.GatewayGroupID != r.GatewayGroupID || !g.Enabled {
			continue
		}
		out.GatewaysTotal++
		check(g.ID)
		switch nr := v.notReady[[2]string{g.ID, r.ID}]; {
		case !v.online[g.ID]:
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: g.ID, Reason: notServingOffline})
		case v.missing[[2]string{g.ID, r.ID}] != nil:
			// Its snapshot leaves the route out, so it neither serves it nor reports it.
			out.NotServing = append(out.NotServing, capabilityMissing(g.ID, v.missing[[2]string{g.ID, r.ID}]))
		case v.certPending[r.ID] != "":
			// Its listener completes no TLS handshake without a certificate.
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: g.ID, Reason: notServingCertificatePending,
				Detail: v.certPending[r.ID]})
		case nr != nil:
			out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: g.ID, Reason: notReadyReason(nr.Reason), Detail: nr.Detail})
		case !v.linked(g.ID, ready):
			answering++
			if len(ready) > 0 {
				out.NotServing = append(out.NotServing, &rpmgrv1.RouteNotServing{Id: g.ID, Reason: notServingNoDataSession})
			}
		default:
			answering++
			out.GatewaysServing++
		}
	}

	switch {
	case len(out.Rejections) > 0:
		out.State = rpmgrv1.RouteState_ROUTE_STATE_ERROR
	case pending:
		out.State = rpmgrv1.RouteState_ROUTE_STATE_PENDING
	case v.maintenance[r.ID] && answering > 0:
		// A gateway answers for it, whatever its targets are; the counts still tell. Without one,
		// the rules below say why no one answers.
		out.State = rpmgrv1.RouteState_ROUTE_STATE_MAINTENANCE
	case out.TargetsReady == 0 || out.GatewaysServing == 0:
		out.State = rpmgrv1.RouteState_ROUTE_STATE_UNAVAILABLE
	case out.TargetsReady < out.TargetsTotal || out.GatewaysServing < out.GatewaysTotal:
		out.State = rpmgrv1.RouteState_ROUTE_STATE_DEGRADED
	default:
		out.State = rpmgrv1.RouteState_ROUTE_STATE_READY
	}
	return out
}

// RoutesWithoutReadyTarget are the enabled routes of org with no ready target, as their status
// counts them, for the alert "route has no ready connector" (docs/10-operations.md, "Suggested
// alerts"). A route in maintenance is left out: a gateway answers for it on purpose.
func RoutesWithoutReadyTarget(ctx context.Context, c *ent.Client, org string, now time.Time) ([]*ent.Route, error) {
	rows, err := c.Route.Query().Where(route.OrgID(org), route.Enabled(true)).All(ctx)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	st, err := newRouteStatuses(ctx, ctx, c, org, rows, now)
	if err != nil {
		return nil, err
	}
	var out []*ent.Route
	for _, r := range rows {
		if s := st.of(r); s.TargetsReady == 0 && s.State != rpmgrv1.RouteState_ROUTE_STATE_MAINTENANCE {
			out = append(out, r)
		}
	}
	return out, nil
}

// capabilityMissing is the reason of an agent that lacks capabilities a route needs, with what
// that means for the route's clients where it is more than the route not being served there.
func capabilityMissing(id string, caps []string) *rpmgrv1.RouteNotServing {
	detail := strings.Join(caps, ", ")
	for _, c := range caps {
		if note := capabilityNotes[c]; note != "" {
			detail += "; " + note
		}
	}
	return &rpmgrv1.RouteNotServing{Id: id, Reason: routes.CapabilityMissing, Detail: detail}
}

// capabilityNotes say what clients meet on an agent that lacks a capability, where another route
// takes the route's requests there (docs/03-connections.md, "Versioning and capabilities").
var capabilityNotes = map[string]string{
	agentproto.CapHTTPHeaderMatch: "this gateway sends the route's requests to a route of the same hostname and path prefix " +
		"without header matches, if there is one",
}

// linked reports whether gateway has a data session with one of connectors.
func (v *routeStatuses) linked(gateway string, connectors map[string]bool) bool {
	for c := range connectors {
		if v.links[[2]string{gateway, c}] {
			return true
		}
	}
	return false
}
