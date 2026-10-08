// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/totp"
	"github.com/felix-homelab/rpmgr/internal/websession"
)

// User is UserService: the caller's own account.
type User struct {
	rpmgrv1connect.UnimplementedUserServiceHandler
	MFA      *accounts.MFA
	Sessions *websession.Sessions
	Issuer   string // names the instance in authenticator apps
}

// EnrollTOTP implements UserService.
func (u *User) EnrollTOTP(ctx context.Context, _ *connect.Request[rpmgrv1.EnrollTOTPRequest]) (*connect.Response[rpmgrv1.EnrollTOTPResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	seed, uri, err := u.MFA.EnrollTOTP(c.UserID, u.Issuer)
	if errors.Is(err, accounts.ErrMFAEnrolled) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.EnrollTOTPResponse{Secret: totp.Encode(seed), Uri: uri}), nil
}

// ConfirmTOTP implements UserService.
func (u *User) ConfirmTOTP(ctx context.Context, req *connect.Request[rpmgrv1.ConfirmTOTPRequest]) (*connect.Response[rpmgrv1.ConfirmTOTPResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := u.MFA.ConfirmTOTP(c.UserID, req.Msg.GetCode())
	switch {
	case errors.Is(err, accounts.ErrSecondFactor):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, accounts.ErrNoMFA), errors.Is(err, accounts.ErrMFAEnrolled):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, err
	}
	if _, err := u.Sessions.RevokeAll(c.UserID, c.CredentialID, c.UserID, "authenticator set up"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ConfirmTOTPResponse{RecoveryCodes: codes}), nil
}

// RemoveTOTP implements UserService.
func (u *User) RemoveTOTP(ctx context.Context, _ *connect.Request[rpmgrv1.RemoveTOTPRequest]) (*connect.Response[rpmgrv1.RemoveTOTPResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := u.MFA.RemoveTOTP(c.UserID, c.UserID); errors.Is(err, accounts.ErrNoMFA) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	} else if err != nil {
		return nil, err
	}
	if _, err := u.Sessions.RevokeAll(c.UserID, c.CredentialID, c.UserID, "authenticator removed"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.RemoveTOTPResponse{}), nil
}

// RegenerateRecoveryCodes implements UserService.
func (u *User) RegenerateRecoveryCodes(ctx context.Context, _ *connect.Request[rpmgrv1.RegenerateRecoveryCodesRequest]) (
	*connect.Response[rpmgrv1.RegenerateRecoveryCodesResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := u.MFA.RegenerateRecoveryCodes(c.UserID)
	if errors.Is(err, accounts.ErrNoMFA) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.RegenerateRecoveryCodesResponse{RecoveryCodes: codes}), nil
}
