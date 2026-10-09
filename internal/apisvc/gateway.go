// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portquota"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
)

// Gateways is GatewayService. Its methods run in the org scope the interceptor gives them, so the
// store sees only the caller's org.
type Gateways struct {
	rpmgrv1connect.UnimplementedGatewayServiceHandler
	DB  *store.DB
	API *api.Server
}

// groupFields are the fields of a gateway group a client may change.
var groupFields = []string{"name", "region", "public_hostnames", "trusted_proxy_cidrs"}

// CreateGatewayGroup implements GatewayService.
func (g *Gateways) CreateGatewayGroup(ctx context.Context, req *connect.Request[rpmgrv1.CreateGatewayGroupRequest]) (
	*connect.Response[rpmgrv1.CreateGatewayGroupResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, g.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateGatewayGroupResponse, error) {
		in := m.GetGatewayGroup()
		var row *ent.GatewayGroup
		rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
			var err error
			row, err = tx.GatewayGroup.Create().SetOrgID(m.GetOrgId()).SetName(in.GetName()).SetRegion(in.GetRegion()).
				SetPublicHostnames(in.GetPublicHostnames()).SetTrustedProxyCidrs(in.GetTrustedProxyCidrs()).Save(ctx)
			if err != nil {
				return nil, err
			}
			return []string{row.ID}, nil
		})
		if err != nil {
			return nil, storeError(err)
		}
		return &rpmgrv1.CreateGatewayGroupResponse{GatewayGroup: groupOf(row), Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetGatewayGroup implements GatewayService.
func (g *Gateways) GetGatewayGroup(ctx context.Context, req *connect.Request[rpmgrv1.GetGatewayGroupRequest]) (
	*connect.Response[rpmgrv1.GetGatewayGroupResponse], error) {
	row, err := g.DB.ReadClient().GatewayGroup.Get(ctx, req.Msg.GetGatewayGroupId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetGatewayGroupResponse{GatewayGroup: groupOf(row)}), nil
}

// ListGatewayGroups implements GatewayService.
func (g *Gateways) ListGatewayGroups(ctx context.Context, req *connect.Request[rpmgrv1.ListGatewayGroupsRequest]) (
	*connect.Response[rpmgrv1.ListGatewayGroupsResponse], error) {
	size, err := api.PageSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := g.API.AfterPage(req.Msg.GetPageToken(), req.Msg)
	if err != nil {
		return nil, err
	}
	q := g.DB.ReadClient().GatewayGroup.Query().Where(gatewaygroup.OrgID(req.Msg.GetOrgId())).Order(ent.Asc(gatewaygroup.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(gatewaygroup.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListGatewayGroupsResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = g.API.PageToken(rows[size-1].ID, req.Msg)
	}
	for _, r := range rows {
		out.GatewayGroups = append(out.GatewayGroups, groupOf(r))
	}
	return connect.NewResponse(out), nil
}

// UpdateGatewayGroup implements GatewayService.
func (g *Gateways) UpdateGatewayGroup(ctx context.Context, req *connect.Request[rpmgrv1.UpdateGatewayGroupRequest]) (
	*connect.Response[rpmgrv1.UpdateGatewayGroupResponse], error) {
	m := req.Msg
	var row *ent.GatewayGroup
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.GatewayGroup.Get(ctx, m.GetGatewayGroup().GetId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, groupOf(cur)); err != nil {
			return nil, err
		}
		next := proto.Clone(groupOf(cur)).(*rpmgrv1.GatewayGroup)
		if err := api.ApplyMask(next, m.GetGatewayGroup(), m.GetUpdateMask(), groupFields...); err != nil {
			return nil, err
		}
		row, err = tx.GatewayGroup.UpdateOneID(cur.ID).Where(gatewaygroup.Version(cur.Version)).SetName(next.GetName()).
			SetRegion(next.GetRegion()).SetPublicHostnames(next.GetPublicHostnames()).SetTrustedProxyCidrs(next.GetTrustedProxyCidrs()).Save(ctx)
		if err != nil {
			return nil, err
		}
		return []string{row.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateGatewayGroupResponse{GatewayGroup: groupOf(row), Revision: revisionOf(rev)}), nil
}

// DeleteGatewayGroup implements GatewayService.
func (g *Gateways) DeleteGatewayGroup(ctx context.Context, req *connect.Request[rpmgrv1.DeleteGatewayGroupRequest]) (
	*connect.Response[rpmgrv1.DeleteGatewayGroupResponse], error) {
	id := req.Msg.GetGatewayGroupId()
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.GatewayGroup.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, groupOf(cur)); err != nil {
			return nil, err
		}
		for _, c := range []struct {
			what  string
			count func(context.Context) (int, error)
		}{
			{"gateways", tx.Gateway.Query().Where(gateway.GatewayGroupID(id), gateway.DecommissionedAtIsNil()).Count},
			{"routes", tx.Route.Query().Where(route.GatewayGroupID(id)).Count},
			{"port pools", tx.PortPool.Query().Where(portpool.GatewayGroupID(id)).Count},
		} {
			if n, err := c.count(ctx); err != nil || n > 0 {
				return nil, errors.Join(err, errIf(n > 0, dependants(fmt.Sprintf("the group still has %d %s", n, c.what))))
			}
		}
		// Decommissioned gateways and the group's quotas go with it.
		if _, err := tx.Gateway.Delete().Where(gateway.GatewayGroupID(id)).Exec(ctx); err != nil {
			return nil, err
		}
		if _, err := tx.PortQuota.Delete().Where(portquota.GatewayGroupID(id)).Exec(ctx); err != nil {
			return nil, err
		}
		if err := tx.GatewayGroup.DeleteOneID(id).Where(gatewaygroup.Version(cur.Version)).Exec(ctx); err != nil {
			return nil, err
		}
		return []string{id}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteGatewayGroupResponse{Revision: revisionOf(rev)}), nil
}

func groupOf(r *ent.GatewayGroup) *rpmgrv1.GatewayGroup {
	return &rpmgrv1.GatewayGroup{Id: r.ID, Name: r.Name, Region: r.Region, PublicHostnames: r.PublicHostnames,
		TrustedProxyCidrs: r.TrustedProxyCidrs, Etag: etagOf(r.Version)}
}
