// SPDX-License-Identifier: Apache-2.0

// Package apisvc implements the services of the public API, rpmgr.v1 (docs/07-api.md). The
// interceptor of internal/api authenticates, authorizes and validates every request before a
// method here runs.
package apisvc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/password"
)

// Auth is AuthService.
type Auth struct {
	rpmgrv1connect.UnimplementedAuthServiceHandler
	Accounts *accounts.Accounts
}

// CompletePasswordReset implements AuthService.
func (a *Auth) CompletePasswordReset(ctx context.Context, req *connect.Request[rpmgrv1.CompletePasswordResetRequest]) (
	*connect.Response[rpmgrv1.CompletePasswordResetResponse], error) {
	m := req.Msg
	u, err := a.Accounts.CompleteReset(ctx, m.GetToken(), m.GetNewPassword(), m.GetEmail(), m.GetDisplayName())
	switch {
	case errors.Is(err, accounts.ErrLink), errors.Is(err, accounts.ErrEmail), errors.Is(err, accounts.ErrDisplayName),
		errors.Is(err, password.ErrLength):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, accounts.ErrHasUsers):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.CompletePasswordResetResponse{UserId: u.ID, Email: u.Email}), nil
}
