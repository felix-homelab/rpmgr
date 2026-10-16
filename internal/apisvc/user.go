// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"slices"
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
	// RequireMFA returns an org's policy that its members act in it only after signing in with a
	// second factor; nil requires it nowhere.
	RequireMFA func(ctx context.Context, orgID string) (bool, error)
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

// RegenerateRecoveryCodes implements UserService. The user's other sessions end with the old codes,
// in the same transaction; the session that asked stays, and so do the user's API tokens, as after
// a password change (D96).
func (u *User) RegenerateRecoveryCodes(ctx context.Context, _ *connect.Request[rpmgrv1.RegenerateRecoveryCodesRequest]) (
	*connect.Response[rpmgrv1.RegenerateRecoveryCodesResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := u.MFA.For(ctx).RegenerateRecoveryCodes(c.UserID, func(tx *ent.Tx) (int, error) {
		return u.Sessions.RevokeAllIn(tx, c.UserID, c.CredentialID, c.UserID, "recovery codes replaced")
	})
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
	since, err := u.MFA.RestoreReview()
	if err != nil {
		return nil, err
	}
	if since != nil {
		out.RestoreReviewTime = timestamppb.New(*since)
	}
	return connect.NewResponse(out), nil
}

// themes are the stored names of the API's themes; unspecified keeps the user's theme.
var themes = map[rpmgrv1.Theme]string{rpmgrv1.Theme_THEME_UNSPECIFIED: "", rpmgrv1.Theme_THEME_SYSTEM: "system",
	rpmgrv1.Theme_THEME_LIGHT: "light", rpmgrv1.Theme_THEME_DARK: "dark"}

// UpdateMe implements UserService.
func (u *User) UpdateMe(ctx context.Context, req *connect.Request[rpmgrv1.UpdateMeRequest]) (*connect.Response[rpmgrv1.UpdateMeResponse], error) {
	usr, err := u.MFA.SetProfile(ctx, api.CallerFrom(ctx).UserID, req.Msg.GetDisplayName(), themes[req.Msg.GetTheme()])
	if errors.Is(err, accounts.ErrDisplayName) || errors.Is(err, accounts.ErrTheme) {
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

// CreatePasswordResetLink implements UserService, for a user the caller may recover (recoverable)
// as Owner or Admin.
func (u *User) CreatePasswordResetLink(ctx context.Context, req *connect.Request[rpmgrv1.CreatePasswordResetLinkRequest]) (
	*connect.Response[rpmgrv1.CreatePasswordResetLinkResponse], error) {
	c := api.CallerFrom(ctx)
	target := req.Msg.GetUserId()
	if err := u.mayRecover(ctx, c, target, false); err != nil {
		return nil, err
	}
	tok, err := u.MFA.For(ctx).ResetLink(target, c.UserID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.CreatePasswordResetLinkResponse{Url: accounts.LinkURL(u.PublicURL, tok),
		ExpireTime: timestamppb.New(time.Now().Add(accounts.ResetLinkTTL))}), nil
}

// RemoveUserTOTP implements UserService, for a user the caller may recover (recoverable) as Owner:
// it removes their authenticator and recovery codes and ends their sessions, as their own removal
// would; their API tokens stay.
func (u *User) RemoveUserTOTP(ctx context.Context, req *connect.Request[rpmgrv1.RemoveUserTOTPRequest]) (
	*connect.Response[rpmgrv1.RemoveUserTOTPResponse], error) {
	c := api.CallerFrom(ctx)
	target := req.Msg.GetUserId()
	if target == c.UserID {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: remove your own authenticator under Account"))
	}
	if err := u.mayRecover(ctx, c, target, true); err != nil {
		return nil, err
	}
	if err := u.MFA.For(ctx).RemoveTOTP(target, c.UserID); errors.Is(err, accounts.ErrNoMFA) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	} else if err != nil {
		return nil, err
	}
	if _, err := u.Sessions.RevokeAll(target, "", c.UserID, "authenticator removed by an admin"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.RemoveUserTOTPResponse{}), nil
}

// SetInstanceAdmin implements UserService.
func (u *User) SetInstanceAdmin(ctx context.Context, req *connect.Request[rpmgrv1.SetInstanceAdminRequest]) (
	*connect.Response[rpmgrv1.SetInstanceAdminResponse], error) {
	usr, err := u.MFA.SetInstanceAdmin(ctx, req.Msg.GetUserId(), req.Msg.GetInstanceAdmin(), api.CallerFrom(ctx).UserID)
	switch {
	case errors.Is(err, accounts.ErrNoUser):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, accounts.ErrLastInstanceAdmin):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.SetInstanceAdminResponse{User: u.userOf(usr)}), nil
}

// mayRecover checks that the caller may recover the account of the user target (recoverable), as
// Owner only if ownerOnly, and keeps the MFA policies of the orgs they act through: a user they
// may not recover is not found.
func (u *User) mayRecover(ctx context.Context, c *api.Caller, target string, ownerOnly bool) error {
	usr, theirs, err := u.MFA.User(target)
	if ent.IsNotFound(err) || err == nil && !recoverable(c, usr, theirs, ownerOnly) {
		return connect.NewError(connect.CodeNotFound, accounts.ErrNoUser)
	}
	if err != nil || instanceAdmin(c) || c.MFA || u.RequireMFA == nil {
		return err
	}
	for _, m := range theirs {
		need, err := u.RequireMFA(ctx, m.OrgID)
		if err != nil {
			return err
		}
		if need {
			return withReason(connect.NewError(connect.CodePermissionDenied, errors.New("apisvc: the org requires signing in with a second factor")),
				api.ReasonMFARequired)
		}
	}
	return nil
}

// recoverable reports whether the caller may recover the account of target, whose memberships are
// theirs (docs/04-security.md, "Account recovery"): the Instance Admin, anyone's; another caller
// only that of a user who is no Instance Admin and all of whose orgs are the caller's, as Owner,
// or, unless ownerOnly, as Admin where the user is no Owner. So an org's Owner or Admin never
// reaches another org, or the instance, through an account they share. A token needs the scope
// members.write, or instance.admin, and holds only its own org.
func recoverable(c *api.Caller, target *ent.User, theirs []*ent.Membership, ownerOnly bool) bool {
	if instanceAdmin(c) {
		return true
	}
	if target.InstanceAdmin || len(theirs) == 0 || !scoped(c, authz.PermMembersWrite) {
		return false
	}
	for _, m := range theirs {
		switch mine := c.Memberships[m.OrgID]; {
		case mine == authz.RoleOwner:
		case !ownerOnly && mine == authz.RoleAdmin && string(m.Role) != authz.RoleOwner:
		default:
			return false
		}
	}
	return true
}

// instanceAdmin reports whether the caller acts as the Instance Admin: a session of one, or a token
// of one with that scope.
func instanceAdmin(c *api.Caller) bool { return c.InstanceAdmin && scoped(c, authz.PermInstanceAdmin) }

// scoped reports whether a token's scopes hold p; a session holds every permission of its roles.
func scoped(c *api.Caller, p string) bool { return c.Scopes == nil || slices.Contains(c.Scopes, p) }

func (u *User) userOf(usr *ent.User) *rpmgrv1.User {
	has, _ := u.MFA.HasMFA(usr.ID)
	out := &rpmgrv1.User{Id: usr.ID, Email: usr.Email, DisplayName: usr.DisplayName, InstanceAdmin: usr.InstanceAdmin, Mfa: has,
		Status: string(usr.Status), CreateTime: timestamppb.New(usr.CreatedAt)}
	for t, name := range themes {
		if name == string(usr.Theme) && name != "" {
			out.Theme = t
		}
	}
	if usr.LastLoginAt != nil {
		out.LastLoginTime = timestamppb.New(*usr.LastLoginAt)
	}
	return out
}
