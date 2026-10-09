// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

// Connectors is ConnectorService. Its methods run in the org scope the interceptor gives them.
type Connectors struct {
	rpmgrv1connect.UnimplementedConnectorServiceHandler
	DB  *store.DB
	API *api.Server
	// Revocations revoke a decommissioned connector's identity.
	Revocations *Revocations
	Now         func() time.Time
}

// connectorFields are the fields of a connector a client may change.
var connectorFields = []string{"name", "labels", "enabled", "transport"}

// UpdateConnector implements ConnectorService.
func (c *Connectors) UpdateConnector(ctx context.Context, req *connect.Request[rpmgrv1.UpdateConnectorRequest]) (
	*connect.Response[rpmgrv1.UpdateConnectorResponse], error) {
	m := req.Msg
	var row *ent.Connector
	rev, err := store.ConfigTx(ctx, c.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.Connector.Get(ctx, m.GetConnector().GetId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, connectorOf(cur, nil, c.now())); err != nil {
			return nil, err
		}
		if cur.DecommissionedAt != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the connector is decommissioned"))
		}
		next := proto.Clone(connectorOf(cur, nil, c.now())).(*rpmgrv1.Connector)
		if err := api.ApplyMask(next, m.GetConnector(), m.GetUpdateMask(), connectorFields...); err != nil {
			return nil, err
		}
		u := tx.Connector.UpdateOneID(cur.ID).Where(connector.Version(cur.Version)).SetName(next.GetName()).
			SetLabels(next.GetLabels()).SetEnabled(next.GetEnabled())
		if t, ok := storeTransports[next.GetTransport()]; ok {
			u.SetTransport(t)
		} else {
			u.ClearTransport()
		}
		if row, err = u.Save(ctx); err != nil {
			return nil, err
		}
		return []string{row.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	s, err := c.session(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.UpdateConnectorResponse{Connector: connectorOf(row, s, c.now()), Revision: revisionOf(rev)}), nil
}

// DecommissionConnector implements ConnectorService. The identity is revoked in the same
// transaction; a second call changes nothing.
func (c *Connectors) DecommissionConnector(ctx context.Context, req *connect.Request[rpmgrv1.DecommissionConnectorRequest]) (
	*connect.Response[rpmgrv1.DecommissionConnectorResponse], error) {
	actor := api.CallerFrom(ctx).UserID
	var (
		row     *ent.Connector
		revoked bool
	)
	rev, err := store.ConfigTx(ctx, c.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.Connector.Get(ctx, req.Msg.GetConnectorId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, connectorOf(cur, nil, c.now())); err != nil {
			return nil, err
		}
		if row = cur; cur.DecommissionedAt != nil {
			return []string{cur.ID}, nil
		}
		now := c.now()
		if row, err = tx.Connector.UpdateOneID(cur.ID).Where(connector.Version(cur.Version)).SetDecommissionedAt(now).
			SetEnabled(false).Save(ctx); err != nil {
			return nil, err
		}
		revoked, err = c.Revocations.agent(tx, pki.KindConnector, cur.OrgID, cur.ID, "decommissioned", actor, now)
		return []string{cur.ID}, err
	})
	if err != nil {
		return nil, storeError(err)
	}
	if revoked {
		c.Revocations.applied()
	}
	return connect.NewResponse(&rpmgrv1.DecommissionConnectorResponse{Connector: connectorOf(row, nil, c.now()), Revision: revisionOf(rev)}), nil
}

func (c *Connectors) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// storeTransports are the store's transport policies by the API's; unspecified clears it.
var storeTransports = map[rpmgrv1.DataTransport]connector.Transport{rpmgrv1.DataTransport_DATA_TRANSPORT_AUTO: connector.TransportAuto,
	rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC: connector.TransportQuic, rpmgrv1.DataTransport_DATA_TRANSPORT_H2: connector.TransportH2}

// ListConnectors implements ConnectorService.
func (c *Connectors) ListConnectors(ctx context.Context, req *connect.Request[rpmgrv1.ListConnectorsRequest]) (
	*connect.Response[rpmgrv1.ListConnectorsResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := c.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := c.DB.ReadClient().Connector.Query().Where(connector.OrgID(m.GetOrgId())).Order(ent.Asc(connector.FieldID)).Limit(size + 1)
	if !m.GetShowDecommissioned() {
		q.Where(connector.DecommissionedAtIsNil())
	}
	if after != "" {
		q.Where(connector.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListConnectorsResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = c.API.PageToken(rows[size-1].ID, m)
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	sessions, err := c.DB.ReadClient().AgentSession.Query().Where(agentsession.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	byID := map[string]*ent.AgentSession{}
	for _, s := range sessions {
		byID[s.ID] = s
	}
	for _, r := range rows {
		out.Connectors = append(out.Connectors, connectorOf(r, byID[r.ID], c.now()))
	}
	return connect.NewResponse(out), nil
}

// GetConnector implements ConnectorService.
func (c *Connectors) GetConnector(ctx context.Context, req *connect.Request[rpmgrv1.GetConnectorRequest]) (
	*connect.Response[rpmgrv1.GetConnectorResponse], error) {
	row, err := c.DB.ReadClient().Connector.Get(ctx, req.Msg.GetConnectorId())
	if err != nil {
		return nil, storeError(err)
	}
	s, err := c.session(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.GetConnectorResponse{Connector: connectorOf(row, s, c.now())}), nil
}

// GetConnectorStatus implements ConnectorService.
func (c *Connectors) GetConnectorStatus(ctx context.Context, req *connect.Request[rpmgrv1.GetConnectorStatusRequest]) (
	*connect.Response[rpmgrv1.GetConnectorStatusResponse], error) {
	rc := c.DB.ReadClient()
	row, err := rc.Connector.Get(ctx, req.Msg.GetConnectorId())
	if err != nil {
		return nil, storeError(err)
	}
	s, err := c.session(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.ConnectorStatus{Session: agentSessionOf(s, c.now())}
	ds, err := rc.DataSession.Query().Where(datasession.ConnectorID(row.ID)).
		Order(ent.Asc(datasession.FieldGatewayID), ent.Asc(datasession.FieldTransport)).All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	for _, d := range ds {
		cd := &rpmgrv1.ConnectorDataSession{GatewayId: d.GatewayID, Transport: rpmgrv1.DataTransport_DATA_TRANSPORT_H2,
			EstablishTime: timestamppb.New(d.EstablishedAt), ReportTime: timestamppb.New(d.ReportedAt)}
		if d.Transport == datasession.TransportQuic {
			cd.Transport = rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC
		}
		if d.RttMs > 0 {
			cd.Rtt = durationpb.New(time.Duration(d.RttMs) * time.Millisecond)
		}
		out.DataSessions = append(out.DataSessions, cd)
	}
	nr, err := rc.ResourceStatus.Query().Where(resourcestatus.AgentID(row.ID)).Order(ent.Asc(resourcestatus.FieldResourceID)).All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	for _, r := range nr {
		out.NotReady = append(out.NotReady, &rpmgrv1.NotReadyResource{ResourceId: r.ResourceID, Reason: notReadyReason(r.Reason),
			Detail: r.Detail, Since: timestamppb.New(r.Since)})
	}
	return connect.NewResponse(&rpmgrv1.GetConnectorStatusResponse{Status: out}), nil
}

// session is the connector's control session; nil without one.
func (c *Connectors) session(ctx context.Context, id string) (*ent.AgentSession, error) {
	s, err := c.DB.ReadClient().AgentSession.Get(ctx, id)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, storeError(err)
	}
	return s, nil
}

// notReadyReason drops the agent protocol's prefix from a stored reason.
func notReadyReason(r string) string {
	const prefix = "NOT_READY_REASON_"
	if len(r) > len(prefix) && r[:len(prefix)] == prefix {
		return r[len(prefix):]
	}
	return r
}

// agentSessionOf is what an agent's session row says at now: connected while it is live, and the
// version, address and last-seen time of its last session.
func agentSessionOf(s *ent.AgentSession, now time.Time) *rpmgrv1.AgentSession {
	if s == nil {
		return &rpmgrv1.AgentSession{}
	}
	return &rpmgrv1.AgentSession{Connected: schema.AgentSessionLive(s.DisconnectedAt, s.LastSeenAt, now), Version: s.AgentVersion,
		LastSeenTime: timestamppb.New(s.LastSeenAt), RemoteAddr: s.RemoteAddr}
}

func connectorOf(r *ent.Connector, s *ent.AgentSession, now time.Time) *rpmgrv1.Connector {
	out := &rpmgrv1.Connector{Id: r.ID, Name: r.Name, Labels: r.Labels, Ephemeral: r.Ephemeral, Enabled: r.Enabled,
		Session: agentSessionOf(s, now), CreateTime: timestamppb.New(r.CreatedAt), Etag: etagOf(r.Version)}
	if r.Transport != nil {
		out.Transport = map[connector.Transport]rpmgrv1.DataTransport{connector.TransportAuto: rpmgrv1.DataTransport_DATA_TRANSPORT_AUTO,
			connector.TransportQuic: rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC, connector.TransportH2: rpmgrv1.DataTransport_DATA_TRANSPORT_H2}[*r.Transport]
	}
	if r.DecommissionedAt != nil {
		out.DecommissionTime = timestamppb.New(*r.DecommissionedAt)
	}
	return out
}
