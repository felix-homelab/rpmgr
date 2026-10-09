// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portallocation"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portquota"
)

// poolFields are the fields of a port pool a client may change.
var poolFields = []string{"port_from", "port_to"}

// portErrors gives the port rules' errors their API codes.
func portErrors(err error) error {
	switch {
	case errors.Is(err, routes.ErrNoGroup):
		return connect.NewError(connect.CodeNotFound, errors.New("apisvc: not found"))
	case errors.Is(err, routes.ErrPoolOverlap), errors.Is(err, routes.ErrPoolRange):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, routes.ErrPoolInUse):
		return dependants(err.Error())
	}
	return storeError(err)
}

// CreatePortPool implements GatewayService.
func (g *Gateways) CreatePortPool(ctx context.Context, req *connect.Request[rpmgrv1.CreatePortPoolRequest]) (
	*connect.Response[rpmgrv1.CreatePortPoolResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, g.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreatePortPoolResponse, error) {
		in := m.GetPortPool()
		p, err := protocolOf(in.GetProtocol())
		if err != nil {
			return nil, err
		}
		var row *ent.PortPool
		rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
			var err error
			if row, err = routes.AddPool(ctx, tx, m.GetOrgId(), in.GetGatewayGroupId(), p, int(in.GetPortFrom()), int(in.GetPortTo())); err != nil {
				return nil, err
			}
			return []string{row.ID}, nil
		})
		if err != nil {
			return nil, portErrors(err)
		}
		return &rpmgrv1.CreatePortPoolResponse{PortPool: poolOf(row, 0), Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetPortPool implements GatewayService.
func (g *Gateways) GetPortPool(ctx context.Context, req *connect.Request[rpmgrv1.GetPortPoolRequest]) (*connect.Response[rpmgrv1.GetPortPoolResponse], error) {
	c := g.DB.ReadClient()
	row, err := c.PortPool.Get(ctx, req.Msg.GetPortPoolId())
	if err != nil {
		return nil, storeError(err)
	}
	n, err := allocatedIn(ctx, c.PortAllocation.Query(), row)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.GetPortPoolResponse{PortPool: poolOf(row, n)}), nil
}

// ListPortPools implements GatewayService.
func (g *Gateways) ListPortPools(ctx context.Context, req *connect.Request[rpmgrv1.ListPortPoolsRequest]) (
	*connect.Response[rpmgrv1.ListPortPoolsResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := g.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	c := g.DB.ReadClient()
	q := c.PortPool.Query().Where(portpool.OrgID(m.GetOrgId())).Order(ent.Asc(portpool.FieldID)).Limit(size + 1)
	if m.GetGatewayGroupId() != "" {
		q.Where(portpool.GatewayGroupID(m.GetGatewayGroupId()))
	}
	if after != "" {
		q.Where(portpool.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListPortPoolsResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = g.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		n, err := allocatedIn(ctx, c.PortAllocation.Query(), r)
		if err != nil {
			return nil, err
		}
		out.PortPools = append(out.PortPools, poolOf(r, n))
	}
	return connect.NewResponse(out), nil
}

// UpdatePortPool implements GatewayService.
func (g *Gateways) UpdatePortPool(ctx context.Context, req *connect.Request[rpmgrv1.UpdatePortPoolRequest]) (
	*connect.Response[rpmgrv1.UpdatePortPoolResponse], error) {
	m := req.Msg
	var (
		row *ent.PortPool
		n   int
	)
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.PortPool.Get(ctx, m.GetPortPool().GetId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, poolOf(cur, 0)); err != nil {
			return nil, err
		}
		next := proto.Clone(poolOf(cur, 0)).(*rpmgrv1.PortPool)
		if err := api.ApplyMask(next, m.GetPortPool(), m.GetUpdateMask(), poolFields...); err != nil {
			return nil, err
		}
		if row, err = routes.ResizePool(ctx, tx, cur, int(next.GetPortFrom()), int(next.GetPortTo())); err != nil {
			return nil, err
		}
		if n, err = allocatedIn(ctx, tx.PortAllocation.Query(), row); err != nil {
			return nil, err
		}
		return []string{row.ID}, nil
	})
	if err != nil {
		return nil, portErrors(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdatePortPoolResponse{PortPool: poolOf(row, n), Revision: revisionOf(rev)}), nil
}

// DeletePortPool implements GatewayService.
func (g *Gateways) DeletePortPool(ctx context.Context, req *connect.Request[rpmgrv1.DeletePortPoolRequest]) (
	*connect.Response[rpmgrv1.DeletePortPoolResponse], error) {
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.PortPool.Get(ctx, req.Msg.GetPortPoolId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, poolOf(cur, 0)); err != nil {
			return nil, err
		}
		n, err := allocatedIn(ctx, tx.PortAllocation.Query(), cur)
		if err != nil || n > 0 {
			return nil, errors.Join(err, errIf(n > 0, dependants(fmt.Sprintf("routes hold %d ports of the pool", n))))
		}
		if err := tx.PortPool.DeleteOneID(cur.ID).Where(portpool.Version(cur.Version)).Exec(ctx); err != nil {
			return nil, err
		}
		return []string{cur.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeletePortPoolResponse{Revision: revisionOf(rev)}), nil
}

// SetPortQuota implements GatewayService.
func (g *Gateways) SetPortQuota(ctx context.Context, req *connect.Request[rpmgrv1.SetPortQuotaRequest]) (
	*connect.Response[rpmgrv1.SetPortQuotaResponse], error) {
	m := req.Msg
	p, err := protocolOf(m.GetProtocol())
	if err != nil {
		return nil, err
	}
	var (
		row *ent.PortQuota
		n   int
	)
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		if _, err := tx.GatewayGroup.Get(ctx, m.GetGatewayGroupId()); err != nil {
			return nil, err
		}
		cur, err := tx.PortQuota.Query().Where(portquota.OrgID(m.GetOrgId()), portquota.GatewayGroupID(m.GetGatewayGroupId()),
			portquota.ProtocolEQ(portquota.Protocol(p))).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			row, err = tx.PortQuota.Create().SetOrgID(m.GetOrgId()).SetGatewayGroupID(m.GetGatewayGroupId()).
				SetProtocol(portquota.Protocol(p)).SetMaxPorts(int(m.GetMaxPorts())).Save(ctx)
		case err == nil:
			row, err = tx.PortQuota.UpdateOne(cur).SetMaxPorts(int(m.GetMaxPorts())).Save(ctx)
		}
		if err != nil {
			return nil, err
		}
		if n, err = quotaUsed(ctx, tx.PortAllocation.Query(), row); err != nil {
			return nil, err
		}
		return []string{row.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.SetPortQuotaResponse{PortQuota: quotaOf(row, n), Revision: revisionOf(rev)}), nil
}

// ListPortQuotas implements GatewayService.
func (g *Gateways) ListPortQuotas(ctx context.Context, req *connect.Request[rpmgrv1.ListPortQuotasRequest]) (
	*connect.Response[rpmgrv1.ListPortQuotasResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := g.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	c := g.DB.ReadClient()
	q := c.PortQuota.Query().Where(portquota.OrgID(m.GetOrgId())).Order(ent.Asc(portquota.FieldID)).Limit(size + 1)
	if m.GetGatewayGroupId() != "" {
		q.Where(portquota.GatewayGroupID(m.GetGatewayGroupId()))
	}
	if after != "" {
		q.Where(portquota.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListPortQuotasResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = g.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		n, err := quotaUsed(ctx, c.PortAllocation.Query(), r)
		if err != nil {
			return nil, err
		}
		out.PortQuotas = append(out.PortQuotas, quotaOf(r, n))
	}
	return connect.NewResponse(out), nil
}

// DeletePortQuota implements GatewayService.
func (g *Gateways) DeletePortQuota(ctx context.Context, req *connect.Request[rpmgrv1.DeletePortQuotaRequest]) (
	*connect.Response[rpmgrv1.DeletePortQuotaResponse], error) {
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		if err := tx.PortQuota.DeleteOneID(req.Msg.GetPortQuotaId()).Exec(ctx); err != nil {
			return nil, err
		}
		return []string{req.Msg.GetPortQuotaId()}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeletePortQuotaResponse{Revision: revisionOf(rev)}), nil
}

// protocolOf is a port protocol of the API in the store's terms; it must be set.
func protocolOf(p rpmgrv1.PortProtocol) (routes.Protocol, error) {
	switch p {
	case rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP:
		return routes.TCP, nil
	case rpmgrv1.PortProtocol_PORT_PROTOCOL_UDP:
		return routes.UDP, nil
	}
	return "", connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: the protocol must be tcp or udp"))
}

func protocolOfStore(p string) rpmgrv1.PortProtocol {
	if p == string(routes.UDP) {
		return rpmgrv1.PortProtocol_PORT_PROTOCOL_UDP
	}
	return rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP
}

// allocatedIn counts the ports allocated from a pool.
func allocatedIn(ctx context.Context, q *ent.PortAllocationQuery, p *ent.PortPool) (int, error) {
	return q.Where(portallocation.GatewayGroupID(p.GatewayGroupID), portallocation.ProtocolEQ(portallocation.Protocol(p.Protocol)),
		portallocation.PortGTE(p.PortFrom), portallocation.PortLTE(p.PortTo)).Count(ctx)
}

// quotaUsed counts the ports a quota's org holds in its group.
func quotaUsed(ctx context.Context, q *ent.PortAllocationQuery, r *ent.PortQuota) (int, error) {
	return q.Where(portallocation.OrgID(r.OrgID), portallocation.GatewayGroupID(r.GatewayGroupID),
		portallocation.ProtocolEQ(portallocation.Protocol(r.Protocol))).Count(ctx)
}

func poolOf(r *ent.PortPool, allocated int) *rpmgrv1.PortPool {
	return &rpmgrv1.PortPool{Id: r.ID, GatewayGroupId: r.GatewayGroupID, Protocol: protocolOfStore(string(r.Protocol)),
		PortFrom: int32(r.PortFrom), PortTo: int32(r.PortTo), //nolint:gosec // G115: 1 to 65535
		AllocatedPorts: int32(allocated), Etag: etagOf(r.Version)} //nolint:gosec // G115: at most 65535
}

func quotaOf(r *ent.PortQuota, allocated int) *rpmgrv1.PortQuota {
	return &rpmgrv1.PortQuota{Id: r.ID, GatewayGroupId: r.GatewayGroupID, Protocol: protocolOfStore(string(r.Protocol)),
		MaxPorts: int32(r.MaxPorts), AllocatedPorts: int32(allocated)} //nolint:gosec // G115: at most 65535
}
