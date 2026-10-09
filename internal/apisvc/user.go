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
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/ratelimit"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/totp"
	"github.com/felix-homelab/rpmgr/internal/websession"
)

// User is UserService: the caller's own account.
type User struct {
	rpmgrv1connect.UnimplementedUserServiceHandler
	MFA       *accounts.MFA
	Sessions  *websession.Sessions
	Issuer    string // names the instance in authenticator apps
	API       *api.Server
	PublicURL string
	Backoff   *ratelimit.Backoff // failed current passwords per user, shared with step-up
}

// EnrollTOTP implements UserService.
func (u *User) EnrollTOTP(ctx context.Context, _ *connect.Request[rpmgrv1.EnrollTOTPRequest]) (*connect.Response[rpmgrv1.EnrollTOTPResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	seed, uri, err := u.MFA.For(ctx).EnrollTOTP(c.UserID, u.Issuer)
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
	codes, err := u.MFA.For(ctx).ConfirmTOTP(c.UserID, req.Msg.GetCode())
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
	if err := u.MFA.For(ctx).RemoveTOTP(c.UserID, c.UserID); errors.Is(err, accounts.ErrNoMFA) {
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
	codes, err := u.MFA.For(ctx).RegenerateRecoveryCodes(c.UserID)
	if errors.Is(err, accounts.ErrNoMFA) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.RegenerateRecoveryCodesResponse{RecoveryCodes: codes}), nil
}

// GetMe implements UserService.
func (u *User) GetMe(ctx context.Context, _ *connect.Request[rpmgrv1.GetMeRequest]) (*connect.Response[rpmgrv1.GetMeResponse], error) {
	c := api.CallerFrom(ctx)
	usr, ms, err := u.MFA.User(c.UserID)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.GetMeResponse{User: u.userOf(usr)}
	for _, m := range ms {
		out.Memberships = append(out.Memberships, &rpmgrv1.Membership{OrgId: m.OrgID, Role: string(m.Role)})
	}
	return connect.NewResponse(out), nil
}

// UpdateMe implements UserService.
func (u *User) UpdateMe(ctx context.Context, req *connect.Request[rpmgrv1.UpdateMeRequest]) (*connect.Response[rpmgrv1.UpdateMeResponse], error) {
	usr, err := u.MFA.SetDisplayName(ctx, api.CallerFrom(ctx).UserID, req.Msg.GetDisplayName())
	if errors.Is(err, accounts.ErrDisplayName) {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.UpdateMeResponse{User: u.userOf(usr)}), nil
}

// ChangePassword implements UserService. A wrong current password counts as a failed step-up.
func (u *User) ChangePassword(ctx context.Context, req *connect.Request[rpmgrv1.ChangePasswordRequest]) (
	*connect.Response[rpmgrv1.ChangePasswordResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	key := "step-up:" + c.UserID
	if u.Backoff != nil {
		if wait := u.Backoff.Wait(key); wait > 0 {
			return nil, limited(wait)
		}
	}
	err = u.MFA.ChangePassword(ctx, c.UserID, req.Msg.GetCurrentPassword(), req.Msg.GetNewPassword())
	switch {
	case errors.Is(err, accounts.ErrCredentials):
		if u.Backoff != nil {
			u.Backoff.Fail(key)
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: the current password is wrong"))
	case errors.Is(err, password.ErrLength):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, err
	}
	if u.Backoff != nil {
		u.Backoff.Succeed(key)
	}
	if _, err := u.Sessions.RevokeAll(c.UserID, c.CredentialID, c.UserID, "password changed"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ChangePasswordResponse{}), nil
}

// ListUsers implements UserService.
func (u *User) ListUsers(_ context.Context, req *connect.Request[rpmgrv1.ListUsersRequest]) (*connect.Response[rpmgrv1.ListUsersResponse], error) {
	size, err := api.PageSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := u.API.AfterPage(req.Msg.GetPageToken(), req.Msg)
	if err != nil {
		return nil, err
	}
	users, err := u.MFA.Users(after, size+1)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.ListUsersResponse{}
	if len(users) > size {
		users = users[:size]
		out.NextPageToken = u.API.PageToken(users[size-1].ID, req.Msg)
	}
	for _, usr := range users {
		out.Users = append(out.Users, u.userOf(usr))
	}
	return connect.NewResponse(out), nil
}

// CreatePasswordResetLink implements UserService: the Instance Admin may reset anyone; an Owner or
// Admin a member of their org, an Admin not an Owner. Anyone else finds no such user.
func (u *User) CreatePasswordResetLink(ctx context.Context, req *connect.Request[rpmgrv1.CreatePasswordResetLinkRequest]) (
	*connect.Response[rpmgrv1.CreatePasswordResetLinkResponse], error) {
	c := api.CallerFrom(ctx)
	target := req.Msg.GetUserId()
	_, theirs, err := u.MFA.User(target)
	if ent.IsNotFound(err) {
		return nil, connect.NewError(connect.CodeNotFound, accounts.ErrNoUser)
	}
	if err != nil {
		return nil, err
	}
	allowed := c.InstanceAdmin
	for _, m := range theirs {
		mine := c.Memberships[m.OrgID]
		if authz.Grants(mine, authz.PermMembersWrite, false) && (mine == authz.RoleOwner || string(m.Role) != authz.RoleOwner) {
			allowed = true
		}
	}
	if !allowed {
		return nil, connect.NewError(connect.CodeNotFound, accounts.ErrNoUser)
	}
	tok, err := u.MFA.For(ctx).ResetLink(target, c.UserID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.CreatePasswordResetLinkResponse{Url: accounts.LinkURL(u.PublicURL, tok),
		ExpireTime: timestamppb.New(time.Now().Add(accounts.ResetLinkTTL))}), nil
}

func (u *User) userOf(usr *ent.User) *rpmgrv1.User {
	has, _ := u.MFA.HasMFA(usr.ID)
	out := &rpmgrv1.User{Id: usr.ID, Email: usr.Email, DisplayName: usr.DisplayName, InstanceAdmin: usr.InstanceAdmin, Mfa: has,
		Status: string(usr.Status), CreateTime: timestamppb.New(usr.CreatedAt)}
	if usr.LastLoginAt != nil {
		out.LastLoginTime = timestamppb.New(*usr.LastLoginAt)
	}
	return out
}
