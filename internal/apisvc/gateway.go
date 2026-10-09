// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portquota"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

// Gateways is GatewayService. Its methods run in the org scope the interceptor gives them, so the
// store sees only the caller's org.
type Gateways struct {
	rpmgrv1connect.UnimplementedGatewayServiceHandler
	DB  *store.DB
	API *api.Server
	// Revocations revoke a decommissioned gateway's identity.
	Revocations *Revocations
	Now         func() time.Time
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

// gatewayFields are the fields of a gateway a client may change.
var gatewayFields = []string{"name", "tunnel_endpoints", "enabled"}

// checkEndpoints refuses a gateway without tunnel endpoints or with one the store would refuse,
// before the store assigns a slot.
func checkEndpoints(eps []string) error {
	if len(eps) == 0 {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: a gateway needs a tunnel endpoint"))
	}
	if err := schema.ValidateEndpoints(eps); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return nil
}

// CreateGateway implements GatewayService. The gateway gets the lowest free slot of its group;
// a group with four gateways in service refuses a fifth.
func (g *Gateways) CreateGateway(ctx context.Context, req *connect.Request[rpmgrv1.CreateGatewayRequest]) (
	*connect.Response[rpmgrv1.CreateGatewayResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, g.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateGatewayResponse, error) {
		in := m.GetGateway()
		if err := checkEndpoints(in.GetTunnelEndpoints()); err != nil {
			return nil, err
		}
		var row *ent.Gateway
		rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
			if _, err := tx.GatewayGroup.Get(ctx, in.GetGatewayGroupId()); err != nil {
				return nil, err
			}
			var err error
			row, err = tx.Gateway.Create().SetOrgID(m.GetOrgId()).SetGatewayGroupID(in.GetGatewayGroupId()).SetName(in.GetName()).
				SetTunnelEndpoints(in.GetTunnelEndpoints()).SetEnabled(true).Save(ctx)
			if err != nil {
				return nil, err
			}
			return []string{row.ID}, nil
		})
		if errors.Is(err, schema.ErrGroupFull) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		if err != nil {
			return nil, storeError(err)
		}
		return &rpmgrv1.CreateGatewayResponse{Gateway: g.gatewayOf(ctx, row), Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetGateway implements GatewayService.
func (g *Gateways) GetGateway(ctx context.Context, req *connect.Request[rpmgrv1.GetGatewayRequest]) (*connect.Response[rpmgrv1.GetGatewayResponse], error) {
	row, err := g.DB.ReadClient().Gateway.Get(ctx, req.Msg.GetGatewayId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetGatewayResponse{Gateway: g.gatewayOf(ctx, row)}), nil
}

// ListGateways implements GatewayService.
func (g *Gateways) ListGateways(ctx context.Context, req *connect.Request[rpmgrv1.ListGatewaysRequest]) (*connect.Response[rpmgrv1.ListGatewaysResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := g.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := g.DB.ReadClient().Gateway.Query().Where(gateway.OrgID(m.GetOrgId())).Order(ent.Asc(gateway.FieldID)).Limit(size + 1)
	if m.GetGatewayGroupId() != "" {
		q.Where(gateway.GatewayGroupID(m.GetGatewayGroupId()))
	}
	if !m.GetShowDecommissioned() {
		q.Where(gateway.DecommissionedAtIsNil())
	}
	if after != "" {
		q.Where(gateway.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListGatewaysResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = g.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.Gateways = append(out.Gateways, g.gatewayOf(ctx, r))
	}
	return connect.NewResponse(out), nil
}

// UpdateGateway implements GatewayService. enabled false takes the gateway out of service without
// revoking it: its next snapshot has no routes, and connectors leave it out of theirs.
func (g *Gateways) UpdateGateway(ctx context.Context, req *connect.Request[rpmgrv1.UpdateGatewayRequest]) (
	*connect.Response[rpmgrv1.UpdateGatewayResponse], error) {
	m := req.Msg
	var row *ent.Gateway
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.Gateway.Get(ctx, m.GetGateway().GetId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, g.gatewayOf(ctx, cur)); err != nil {
			return nil, err
		}
		if cur.DecommissionedAt != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the gateway is decommissioned"))
		}
		next := proto.Clone(g.gatewayOf(ctx, cur)).(*rpmgrv1.Gateway)
		if err := api.ApplyMask(next, m.GetGateway(), m.GetUpdateMask(), gatewayFields...); err != nil {
			return nil, err
		}
		if err := checkEndpoints(next.GetTunnelEndpoints()); err != nil {
			return nil, err
		}
		row, err = tx.Gateway.UpdateOneID(cur.ID).Where(gateway.Version(cur.Version)).SetName(next.GetName()).
			SetTunnelEndpoints(next.GetTunnelEndpoints()).SetEnabled(next.GetEnabled()).Save(ctx)
		if err != nil {
			return nil, err
		}
		return []string{row.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateGatewayResponse{Gateway: g.gatewayOf(ctx, row), Revision: revisionOf(rev)}), nil
}

// DecommissionGateway implements GatewayService. The gateway leaves service for good: its slot is
// free again, and its identity is revoked in the same transaction and recorded in the revocation
// log (docs/04-security.md, "Revocation"). The row stays as a tombstone until its group is
// deleted. A second call changes nothing.
func (g *Gateways) DecommissionGateway(ctx context.Context, req *connect.Request[rpmgrv1.DecommissionGatewayRequest]) (
	*connect.Response[rpmgrv1.DecommissionGatewayResponse], error) {
	actor := api.CallerFrom(ctx).UserID
	var (
		row     *ent.Gateway
		revoked bool
	)
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.Gateway.Get(ctx, req.Msg.GetGatewayId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, g.gatewayOf(ctx, cur)); err != nil {
			return nil, err
		}
		if row = cur; cur.DecommissionedAt != nil {
			return []string{cur.ID}, nil
		}
		now := g.now()
		if row, err = tx.Gateway.UpdateOneID(cur.ID).Where(gateway.Version(cur.Version)).SetDecommissionedAt(now).
			SetEnabled(false).Save(ctx); err != nil {
			return nil, err
		}
		revoked, err = g.Revocations.agent(tx, pki.KindGateway, cur.OrgID, cur.ID, "decommissioned", actor, now)
		return []string{cur.ID}, err
	})
	if err != nil {
		return nil, storeError(err)
	}
	if revoked {
		g.Revocations.applied()
	}
	return connect.NewResponse(&rpmgrv1.DecommissionGatewayResponse{Gateway: g.gatewayOf(ctx, row), Revision: revisionOf(rev)}), nil
}

func (g *Gateways) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// gatewayOf is a gateway with what the controller last saw of it: a gateway is connected while
// its control session with any controller node is live.
func (g *Gateways) gatewayOf(ctx context.Context, r *ent.Gateway) *rpmgrv1.Gateway {
	out := &rpmgrv1.Gateway{Id: r.ID, GatewayGroupId: r.GatewayGroupID, Name: r.Name, Slot: int32(r.Slot), //nolint:gosec // G115: 1 to 4
		TunnelEndpoints: r.TunnelEndpoints, Enabled: r.Enabled, CreateTime: timestamppb.New(r.CreatedAt), Etag: etagOf(r.Version),
		Status: &rpmgrv1.GatewayStatus{Enrolled: r.SpiffeID != ""}}
	if r.DecommissionedAt != nil {
		out.DecommissionTime = timestamppb.New(*r.DecommissionedAt)
	}
	if s, err := g.DB.ReadClient().AgentSession.Query().Where(agentsession.ID(r.ID)).Only(ctx); err == nil {
		out.Status.Connected = schema.AgentSessionLive(s.DisconnectedAt, s.LastSeenAt, g.now())
		out.Status.Version, out.Status.RemoteAddr, out.Status.LastSeenTime = s.AgentVersion, s.RemoteAddr, timestamppb.New(s.LastSeenAt)
	}
	return out
}
