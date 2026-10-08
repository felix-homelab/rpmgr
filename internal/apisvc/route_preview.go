// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"slices"

	"connectrpc.com/connect"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	entgateway "github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// errPreview rolls a preview's transaction back.
var errPreview = errors.New("apisvc: a preview saves nothing")

// PreviewRoute implements RouteService: it runs the write in a configuration transaction, compiles
// the route for the gateways of its group and lets each gateway's own checks look at it, and then
// rolls everything back.
func (r *Routes) PreviewRoute(ctx context.Context, req *connect.Request[rpmgrv1.PreviewRouteRequest]) (
	*connect.Response[rpmgrv1.PreviewRouteResponse], error) {
	m := req.Msg
	update := len(m.GetUpdateMask().GetPaths()) > 0
	if !update {
		if err := checkSpec(m.GetRoute()); err != nil {
			return nil, err
		}
	}
	var out *rpmgrv1.PreviewRouteResponse
	_, err := store.ConfigTx(ctx, r.DB, func(tx *ent.Tx) ([]string, error) {
		var (
			row *ent.Route
			err error
		)
		if update {
			row, err = r.updateRouteTx(ctx, tx, &rpmgrv1.UpdateRouteRequest{Route: m.GetRoute(), UpdateMask: m.GetUpdateMask(), Etag: m.GetEtag()})
		} else {
			row, err = r.createRouteTx(ctx, tx, m.GetOrgId(), m.GetRoute())
		}
		if err != nil {
			return nil, err
		}
		rt, err := routeOf(ctx, tx.Client(), row)
		if err != nil {
			return nil, err
		}
		if !update {
			rt.Id, rt.Etag, rt.CreateTime, rt.UpdateTime = "", "", nil, nil
		}
		out = &rpmgrv1.PreviewRouteResponse{Route: rt}
		if out.GatewayIds, out.Problems, err = previewGateways(ctx, tx, row); err != nil {
			return nil, err
		}
		targets, err := tx.RouteTarget.Query().Where(routetarget.RouteID(row.ID), routetarget.Enabled(true),
			routetarget.HasConnectorWith(connector.Enabled(true), connector.DecommissionedAtIsNil())).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range targets {
			out.ConnectorIds = append(out.ConnectorIds, t.ConnectorID)
		}
		slices.Sort(out.ConnectorIds)
		out.ConnectorIds = slices.Compact(out.ConnectorIds)
		return nil, errPreview
	})
	if !errors.Is(err, errPreview) {
		return nil, routeError(err)
	}
	return connect.NewResponse(out), nil
}

// previewGateways compiles the snapshot of each serving gateway of a route's group and validates
// it as the gateway would; it returns the gateways whose snapshot holds the route and what they
// would refuse about it.
func previewGateways(ctx context.Context, tx *ent.Tx, row *ent.Route) ([]string, []*rpmgrv1.ApplyError, error) {
	gws, err := tx.Gateway.Query().Where(entgateway.GatewayGroupID(row.GatewayGroupID), entgateway.Enabled(true),
		entgateway.DecommissionedAtIsNil()).Order(ent.Asc(entgateway.FieldID)).All(ctx)
	if err != nil {
		return nil, nil, err
	}
	var (
		serving  []string
		problems []*rpmgrv1.ApplyError
		seen     = map[string]bool{}
	)
	for _, gw := range gws {
		snap := &agentv1.Snapshot{}
		a := snapshot.Agent{Identity: pki.Identity{Org: gw.OrgID, Kind: pki.KindGateway, ID: gw.ID}}
		for _, src := range routes.Sources() {
			rs, err := src(ctx, tx, a)
			if err != nil {
				return nil, nil, err
			}
			snap.Resources = append(snap.Resources, rs...)
		}
		if slices.ContainsFunc(snap.GetResources(), func(res *agentv1.Resource) bool { return res.GetId() == row.ID }) {
			serving = append(serving, gw.ID)
		}
		applier, _ := gateway.NewApplier()
		for _, e := range applier.Validate(snap) {
			if e.GetResourceId() == row.ID && !seen[e.GetMessage()] {
				seen[e.GetMessage()] = true
				problems = append(problems, &rpmgrv1.ApplyError{ResourceId: e.GetResourceId(), Message: e.GetMessage()})
			}
		}
	}
	return serving, problems, nil
}
