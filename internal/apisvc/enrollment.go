// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
)

// Enrollment is EnrollmentService. Its methods run in the org scope the interceptor gives them.
type Enrollment struct {
	rpmgrv1connect.UnimplementedEnrollmentServiceHandler
	DB  *store.DB
	API *api.Server
	Now func() time.Time
}

// CreateEnrollmentToken implements EnrollmentService.
func (e *Enrollment) CreateEnrollmentToken(ctx context.Context, req *connect.Request[rpmgrv1.CreateEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.CreateEnrollmentTokenResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, e.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateEnrollmentTokenResponse, error) {
		mint := enroll.Mint{Org: m.GetOrgId(), ConnectorID: m.GetConnectorId(), GatewayGroupID: m.GetGatewayGroupId(),
			Labels: m.GetLabels(), Ephemeral: m.GetEphemeral(), TTL: m.GetTtl().AsDuration()}
		if m.MaxUses != nil {
			n := int(m.GetMaxUses())
			mint.MaxUses = &n
		}
		tok, row, err := e.mint(ctx, mint)
		if err != nil {
			return nil, err
		}
		return &rpmgrv1.CreateEnrollmentTokenResponse{Token: tok, EnrollmentToken: enrollmentTokenOf(row)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// CreateGatewayEnrollmentToken implements EnrollmentService.
func (e *Enrollment) CreateGatewayEnrollmentToken(ctx context.Context, req *connect.Request[rpmgrv1.CreateGatewayEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.CreateGatewayEnrollmentTokenResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, e.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateGatewayEnrollmentTokenResponse, error) {
		gw, err := e.DB.ReadClient().Gateway.Get(ctx, m.GetGatewayId())
		if err != nil {
			return nil, storeError(err)
		}
		tok, row, err := e.mint(ctx, enroll.Mint{Org: gw.OrgID, GatewayID: gw.ID, TTL: m.GetTtl().AsDuration()})
		if err != nil {
			return nil, err
		}
		return &rpmgrv1.CreateGatewayEnrollmentTokenResponse{Token: tok, EnrollmentToken: enrollmentTokenOf(row)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// mint mints a token for the caller in one write transaction, with the request's audit entry.
func (e *Enrollment) mint(ctx context.Context, m enroll.Mint) (string, *ent.EnrollmentToken, error) {
	m.CreatedBy = api.CallerFrom(ctx).UserID
	var (
		tok string
		row *ent.EnrollmentToken
	)
	err := store.WriteTx(ctx, e.DB, func(tx *ent.Tx) error {
		var err error
		tok, row, err = enroll.MintToken(ctx, tx, m, e.now())
		return err
	})
	switch {
	case errors.Is(err, enroll.ErrTokenTTL), errors.Is(err, enroll.ErrMultiUse), errors.Is(err, enroll.ErrBound):
		return "", nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, enroll.ErrRetired):
		return "", nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return "", nil, storeError(err)
	}
	return tok, row, nil
}

func (e *Enrollment) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func enrollmentTokenOf(r *ent.EnrollmentToken) *rpmgrv1.EnrollmentToken {
	out := &rpmgrv1.EnrollmentToken{Id: r.ID, Role: rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR, Labels: r.Labels, Ephemeral: r.Ephemeral,
		UseCount: int32(r.UseCount), ExpireTime: timestamppb.New(r.ExpiresAt), //nolint:gosec // G115: bounded by max_uses
		CreateTime: timestamppb.New(r.CreatedAt), CreatedBy: r.CreatedBy, LastUseIp: r.LastUsedIP}
	if r.Role == enrollmenttoken.RoleGateway {
		out.Role = rpmgrv1.AgentRole_AGENT_ROLE_GATEWAY
	}
	for dst, src := range map[*string]*string{&out.GatewayGroupId: r.GatewayGroupID, &out.GatewayId: r.GatewayID, &out.ConnectorId: r.ConnectorID} {
		if src != nil {
			*dst = *src
		}
	}
	if r.MaxUses != nil {
		out.MaxUses = int32(*r.MaxUses) //nolint:gosec // G115: at most 100 000
	}
	for dst, src := range map[**timestamppb.Timestamp]*time.Time{&out.LastUseTime: r.LastUsedAt, &out.RevokeTime: r.RevokedAt} {
		if src != nil {
			*dst = timestamppb.New(*src)
		}
	}
	return out
}
