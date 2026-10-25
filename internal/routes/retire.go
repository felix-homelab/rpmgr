// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"slices"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/healthcheck"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portallocation"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routeudp"
)

// Delete deletes the route r in tx with everything of it: its hostnames, its spec, its targets and
// its policy links. Its ports are free again, also one an allocation names it by without its spec
// row. r's version guards against a concurrent change.
func Delete(ctx context.Context, tx *ent.Tx, r *ent.Route) error {
	steps := []func() error{
		func() error {
			_, err := tx.RouteHostname.Delete().Where(routehostname.RouteID(r.ID)).Exec(ctx)
			return err
		},
		func() error { _, err := tx.RouteHTTP.Delete().Where(routehttp.RouteID(r.ID)).Exec(ctx); return err },
		func() error { _, err := tx.HealthCheck.Delete().Where(healthcheck.RouteID(r.ID)).Exec(ctx); return err },
		func() error { _, err := tx.RouteTCP.Delete().Where(routetcp.RouteID(r.ID)).Exec(ctx); return err },
		func() error { _, err := tx.RouteUDP.Delete().Where(routeudp.RouteID(r.ID)).Exec(ctx); return err },
		func() error { _, err := tx.RouteTarget.Delete().Where(routetarget.RouteID(r.ID)).Exec(ctx); return err },
		func() error { _, err := tx.RoutePolicy.Delete().Where(routepolicy.RouteID(r.ID)).Exec(ctx); return err },
		func() error {
			_, err := tx.PortAllocation.Delete().Where(portallocation.RouteID(r.ID)).Exec(ctx)
			return err
		},
	}
	// The spec rows refer to their allocations, which are deleted after them.
	var ports []string
	tcp, err := tx.RouteTCP.Query().Where(routetcp.RouteID(r.ID)).Select(routetcp.FieldPortAllocationID).Strings(ctx)
	if err != nil {
		return err
	}
	udp, err := tx.RouteUDP.Query().Where(routeudp.RouteID(r.ID)).Select(routeudp.FieldPortAllocationID).Strings(ctx)
	if err != nil {
		return err
	}
	ports = append(append(ports, tcp...), udp...)
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	if len(ports) > 0 {
		if _, err := tx.PortAllocation.Delete().Where(portallocation.IDIn(ports...)).Exec(ctx); err != nil {
			return err
		}
	}
	return tx.Route.DeleteOneID(r.ID).Where(route.Version(r.Version)).Exec(ctx)
}

// RetireConnector deletes a decommissioned or purged connector's route targets in tx, and then
// each route that had one and is left with no target at all, which frees its ports and hostnames
// (D78). A route with targets on other connectors stays. Each deletion is audited as by, which
// names the org, the actor and the reason. It returns the routes it deleted and the IDs of every
// route it changed, for the configuration revision.
func RetireConnector(ctx context.Context, tx *ent.Tx, connectorID string, by audit.Entry) (deleted []*ent.Route, changed []string, err error) {
	changed, err = tx.RouteTarget.Query().Where(routetarget.ConnectorID(connectorID)).Select(routetarget.FieldRouteID).Strings(ctx)
	if err != nil {
		return nil, nil, err
	}
	slices.Sort(changed)
	changed = slices.Compact(changed)
	if _, err := tx.RouteTarget.Delete().Where(routetarget.ConnectorID(connectorID)).Exec(ctx); err != nil {
		return nil, nil, err
	}
	for _, id := range changed {
		left, err := tx.RouteTarget.Query().Where(routetarget.RouteID(id)).Exist(ctx)
		if err != nil {
			return nil, nil, err
		}
		if left {
			continue
		}
		r, err := tx.Route.Get(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if err := Delete(ctx, tx, r); err != nil {
			return nil, nil, err
		}
		e := by
		e.Action, e.TargetType, e.TargetID, e.Result = "route.delete", "route", r.ID, audit.Success
		if _, err := audit.Append(ctx, tx, e); err != nil {
			return nil, nil, err
		}
		deleted = append(deleted, r)
	}
	return deleted, changed, nil
}
