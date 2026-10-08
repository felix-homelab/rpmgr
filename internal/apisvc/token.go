// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Token is TokenService.
type Token struct {
	rpmgrv1connect.UnimplementedTokenServiceHandler
	Tokens *accounts.Tokens
	API    *api.Server // for request_id deduplication
}

// CreateAPIToken implements TokenService. Only a session creates tokens, so that a token never
// makes another.
func (t *Token) CreateAPIToken(ctx context.Context, req *connect.Request[rpmgrv1.CreateAPITokenRequest]) (
	*connect.Response[rpmgrv1.CreateAPITokenResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	resp, err := api.Dedupe(ctx, t.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateAPITokenResponse, error) {
		tok, row, err := t.Tokens.Create(ctx, m.GetOrgId(), c.UserID, m.GetName(), m.GetScopes(), m.GetTtl().AsDuration(), c.MFA)
		if errors.Is(err, accounts.ErrScope) {
			return nil, connect.NewError(connect.CodePermissionDenied, err)
		}
		if err != nil {
			return nil, err
		}
		return &rpmgrv1.CreateAPITokenResponse{Token: tok, ApiToken: tokenOf(row)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// ListAPITokens implements TokenService.
func (t *Token) ListAPITokens(ctx context.Context, req *connect.Request[rpmgrv1.ListAPITokensRequest]) (
	*connect.Response[rpmgrv1.ListAPITokensResponse], error) {
	rows, err := t.Tokens.List(req.Msg.GetOrgId(), api.CallerFrom(ctx).UserID)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.ListAPITokensResponse{}
	for _, r := range rows {
		out.ApiTokens = append(out.ApiTokens, tokenOf(r))
	}
	return connect.NewResponse(out), nil
}

// RevokeAPIToken implements TokenService.
func (t *Token) RevokeAPIToken(ctx context.Context, req *connect.Request[rpmgrv1.RevokeAPITokenRequest]) (
	*connect.Response[rpmgrv1.RevokeAPITokenResponse], error) {
	err := t.Tokens.Revoke(ctx, req.Msg.GetOrgId(), api.CallerFrom(ctx).UserID, req.Msg.GetTokenId())
	if errors.Is(err, accounts.ErrNoToken) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.RevokeAPITokenResponse{}), nil
}

func tokenOf(r *ent.APIToken) *rpmgrv1.APIToken {
	out := &rpmgrv1.APIToken{Id: r.ID, Name: r.Name, Prefix: r.Prefix, Scopes: r.Scopes, CreateTime: timestamppb.New(r.CreatedAt),
		ExpireTime: timestamppb.New(r.ExpiresAt), LastUseIp: r.LastUsedIP}
	if r.LastUsedAt != nil {
		out.LastUseTime = timestamppb.New(*r.LastUsedAt)
	}
	return out
}
