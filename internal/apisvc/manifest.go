// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/manifest"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/accesspolicy"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cabundle"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
)

// Manifests is ManifestService. Its methods run in the org scope the interceptor gives them.
type Manifests struct {
	rpmgrv1connect.UnimplementedManifestServiceHandler
	DB *store.DB
}

// manifestKinds are the kinds ExportManifests writes, in this order when the request names none.
var manifestKinds = []string{"GatewayGroup", "Gateway", "PortPool", "Domain", "CABundle", "AccessPolicy", "Connector", "Route"}

// ExportManifests implements ManifestService. Decommissioned gateways and connectors are not
// configuration and are left out. A resource the request names that is not the org's, or not of
// a kind it names, is NOT_FOUND.
func (m *Manifests) ExportManifests(ctx context.Context, req *connect.Request[rpmgrv1.ExportManifestsRequest]) (
	*connect.Response[rpmgrv1.ExportManifestsResponse], error) {
	org, c := req.Msg.GetOrgId(), m.DB.ReadClient()
	kinds := req.Msg.GetKinds()
	if len(kinds) == 0 {
		kinds = manifestKinds
	}
	want := map[string]bool{}
	for _, id := range req.Msg.GetResourceIds() {
		want[id] = true
	}
	var docs []*manifest.Doc
	add := func(id string, msg proto.Message) error {
		if len(want) > 0 && !want[id] {
			return nil
		}
		delete(want, id)
		d, err := manifest.Of(ctx, orgNames{c}, msg)
		if err != nil {
			return err
		}
		docs = append(docs, d)
		return nil
	}
	for _, kind := range kinds {
		if err := exportKind(ctx, m.DB, org, kind, add); err != nil {
			return nil, storeError(err)
		}
	}
	if len(want) > 0 {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("apisvc: %d resources not found", len(want)))
	}
	var b bytes.Buffer
	if err := manifest.Write(&b, docs); err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ExportManifestsResponse{Yaml: b.String(), Count: int32(len(docs))}), nil //nolint:gosec // G115: bounded by the org's resources
}

// exportKind passes the org's resources of one kind to add, by ID.
func exportKind(ctx context.Context, db *store.DB, org, kind string, add func(string, proto.Message) error) error {
	c := db.ReadClient()
	each := func(ids []string, err error, of func(int) (proto.Message, error)) error {
		if err != nil {
			return err
		}
		for i, id := range ids {
			msg, err := of(i)
			if err != nil {
				return err
			}
			if err := add(id, msg); err != nil {
				return err
			}
		}
		return nil
	}
	switch kind {
	case "GatewayGroup":
		rows, err := c.GatewayGroup.Query().Where(gatewaygroup.OrgID(org)).Order(ent.Asc(gatewaygroup.FieldID)).All(ctx)
		return each(idsOf(rows, func(r *ent.GatewayGroup) string { return r.ID }), err, func(i int) (proto.Message, error) { return groupOf(rows[i]), nil })
	case "Gateway":
		rows, err := c.Gateway.Query().Where(gateway.OrgID(org), gateway.DecommissionedAtIsNil()).Order(ent.Asc(gateway.FieldID)).All(ctx)
		g := &Gateways{DB: db}
		return each(idsOf(rows, func(r *ent.Gateway) string { return r.ID }), err, func(i int) (proto.Message, error) {
			gw := g.gatewayOf(ctx, rows[i])
			gw.Status = nil
			return gw, nil
		})
	case "PortPool":
		rows, err := c.PortPool.Query().Where(portpool.OrgID(org)).Order(ent.Asc(portpool.FieldID)).All(ctx)
		return each(idsOf(rows, func(r *ent.PortPool) string { return r.ID }), err, func(i int) (proto.Message, error) { return poolOf(rows[i], 0), nil })
	case "Domain":
		rows, err := c.Domain.Query().Where(domain.OrgID(org)).Order(ent.Asc(domain.FieldID)).All(ctx)
		return each(idsOf(rows, func(r *ent.Domain) string { return r.ID }), err, func(i int) (proto.Message, error) { return domainOf(rows[i]), nil })
	case "CABundle":
		rows, err := c.CABundle.Query().Where(cabundle.OrgID(org)).Order(ent.Asc(cabundle.FieldID)).All(ctx)
		return each(idsOf(rows, func(r *ent.CABundle) string { return r.ID }), err, func(i int) (proto.Message, error) { return caBundleOf(ctx, c, rows[i]) })
	case "AccessPolicy":
		rows, err := c.AccessPolicy.Query().Where(accesspolicy.OrgID(org)).Order(ent.Asc(accesspolicy.FieldID)).All(ctx)
		return each(idsOf(rows, func(r *ent.AccessPolicy) string { return r.ID }), err, func(i int) (proto.Message, error) { return policyOf(ctx, c, rows[i]) })
	case "Connector":
		rows, err := c.Connector.Query().Where(connector.OrgID(org), connector.DecommissionedAtIsNil()).Order(ent.Asc(connector.FieldID)).All(ctx)
		return each(idsOf(rows, func(r *ent.Connector) string { return r.ID }), err, func(i int) (proto.Message, error) {
			return connectorOf(rows[i], nil, time.Time{}), nil
		})
	case "Route":
		rows, err := c.Route.Query().Where(route.OrgID(org)).Order(ent.Asc(route.FieldID)).All(ctx)
		return each(idsOf(rows, func(r *ent.Route) string { return r.ID }), err, func(i int) (proto.Message, error) { return routeOf(ctx, c, rows[i]) })
	}
	return fmt.Errorf("apisvc: no manifests of %s", kind)
}

func idsOf[T any](rows []T, id func(T) string) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = id(r)
	}
	return out
}

// orgNames resolves the names of resources a manifest names, in the caller's org: the scope
// limits every query to it.
type orgNames struct{ c *ent.Client }

// Name implements manifest.Resolver.
func (n orgNames) Name(ctx context.Context, kind, id string) (string, error) {
	switch kind {
	case "GatewayGroup":
		return n.c.GatewayGroup.Query().Where(gatewaygroup.ID(id)).Select(gatewaygroup.FieldName).String(ctx)
	case "AccessPolicy":
		return n.c.AccessPolicy.Query().Where(accesspolicy.ID(id)).Select(accesspolicy.FieldName).String(ctx)
	case "Connector":
		return n.c.Connector.Query().Where(connector.ID(id)).Select(connector.FieldName).String(ctx)
	case "CABundle":
		return n.c.CABundle.Query().Where(cabundle.ID(id)).Select(cabundle.FieldName).String(ctx)
	}
	return "", fmt.Errorf("apisvc: %s has no name", kind)
}

// ID implements manifest.Resolver.
func (n orgNames) ID(ctx context.Context, kind, name string) (string, error) {
	switch kind {
	case "GatewayGroup":
		return n.c.GatewayGroup.Query().Where(gatewaygroup.Name(name)).OnlyID(ctx)
	case "AccessPolicy":
		return n.c.AccessPolicy.Query().Where(accesspolicy.Name(name)).OnlyID(ctx)
	case "Connector":
		return n.c.Connector.Query().Where(connector.Name(name), connector.DecommissionedAtIsNil()).OnlyID(ctx)
	case "CABundle":
		return n.c.CABundle.Query().Where(cabundle.Name(name)).OnlyID(ctx)
	}
	return "", fmt.Errorf("apisvc: %s has no name", kind)
}

var _ manifest.Resolver = orgNames{}
