// SPDX-License-Identifier: Apache-2.0

// Package apisvc implements the services of the public API, rpmgr.v1 (docs/07-api.md). The
// interceptor of internal/api authenticates, authorizes and validates every request before a
// method here runs.
package apisvc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/ratelimit"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/websession"
)

// The limits of sign-in (docs/04-security.md, "Human authentication and sessions"): per client
// address, 10 attempts a minute with a burst of 20; per account, a delay after the 5th failure in
// a row, from 1 s doubling up to 60 s.
const (
	IPEvery      = 6 * time.Second
	IPBurst      = 20
	FreeFailures = 5
	FirstDelay   = time.Second
	MaxDelay     = time.Minute
)

// Auth is AuthService.
type Auth struct {
	rpmgrv1connect.UnimplementedAuthServiceHandler
	Accounts *accounts.Accounts
	MFA      *accounts.MFA
	Sessions *websession.Sessions
	IPLimit  *ratelimit.Limiter // logins and password resets per client address
	Backoff  *ratelimit.Backoff // failed logins per account, failed step-ups per user
	Now      func() time.Time
}

// NewAuth returns AuthService with the limits of docs/04.
func NewAuth(mfa *accounts.MFA, s *websession.Sessions, now func() time.Time) *Auth {
	if now == nil {
		now = time.Now
	}
	return &Auth{Accounts: mfa.Accounts, MFA: mfa, Sessions: s, IPLimit: ratelimit.New(IPEvery, IPBurst, now),
		Backoff: ratelimit.NewBackoff(FreeFailures, FirstDelay, MaxDelay, now), Now: now}
}

// Login implements AuthService.
func (a *Auth) Login(ctx context.Context, req *connect.Request[rpmgrv1.LoginRequest]) (*connect.Response[rpmgrv1.LoginResponse], error) {
	ip := hostOf(req.Peer().Addr)
	if !a.IPLimit.Allow(ip) {
		return nil, limited(IPEvery)
	}
	key, err := accounts.NormalizeEmail(req.Msg.GetEmail())
	if err != nil {
		key = req.Msg.GetEmail()
	}
	if wait := a.Backoff.Wait(key); wait > 0 {
		return nil, limited(wait)
	}
	u, err := a.Accounts.Authenticate(ctx, req.Msg.GetEmail(), req.Msg.GetPassword())
	if errors.Is(err, accounts.ErrCredentials) {
		a.Backoff.Fail(key)
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	if err != nil {
		return nil, err
	}
	amr := []string{"pwd"}
	switch has, err := a.MFA.HasMFA(u.ID); {
	case err != nil:
		return nil, err
	case has && req.Msg.GetSecondFactor() == "":
		// The password was right; the second factor is still to come, and counts no failure.
		return nil, withReason(connect.NewError(connect.CodeUnauthenticated, errors.New("apisvc: a second factor is needed")),
			api.ReasonMFARequired)
	case has:
		how, err := a.MFA.VerifySecondFactor(u.ID, req.Msg.GetSecondFactor())
		if errors.Is(err, accounts.ErrSecondFactor) {
			a.Backoff.Fail(key)
			return nil, connect.NewError(connect.CodeUnauthenticated, err)
		}
		if err != nil {
			return nil, err
		}
		amr = append(amr, how)
	}
	a.Backoff.Succeed(key)
	// A new token at every sign-in: a session the browser still carries ends.
	if old, err := (&http.Request{Header: req.Header()}).Cookie(websession.CookieName); err == nil {
		if s, err := a.Sessions.Lookup(old.Value); err == nil {
			_ = a.Sessions.Revoke(s.UserID, s.ID, u.ID)
		}
	}
	tok, sess, err := a.Sessions.Create(u.ID, amr, ip, req.Header().Get("User-Agent"))
	if err != nil {
		return nil, err
	}
	resp := connect.NewResponse(&rpmgrv1.LoginResponse{UserId: u.ID, Session: sessionOf(sess, sess.ID)})
	resp.Header().Add("Set-Cookie", websession.Cookie(tok, sess).String())
	return resp, nil
}

// StepUp implements AuthService. A user with an authenticator steps up with a second factor; the
// password alone is not enough for them.
func (a *Auth) StepUp(ctx context.Context, req *connect.Request[rpmgrv1.StepUpRequest]) (*connect.Response[rpmgrv1.StepUpResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	key := "step-up:" + c.UserID
	if wait := a.Backoff.Wait(key); wait > 0 {
		return nil, limited(wait)
	}
	has, err := a.MFA.HasMFA(c.UserID)
	if err != nil {
		return nil, err
	}
	how := "pwd"
	if has {
		if req.Msg.GetSecondFactor() == "" {
			return nil, withReason(connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: step up with a second factor")),
				api.ReasonMFARequired)
		}
		how, err = a.MFA.VerifySecondFactor(c.UserID, req.Msg.GetSecondFactor())
	} else {
		u, _, uerr := a.Accounts.User(c.UserID)
		if uerr != nil {
			return nil, uerr
		}
		_, err = a.Accounts.Authenticate(ctx, u.Email, req.Msg.GetPassword())
	}
	if errors.Is(err, accounts.ErrSecondFactor) || errors.Is(err, accounts.ErrCredentials) {
		a.Backoff.Fail(key)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("apisvc: the step-up failed"))
	}
	if err != nil {
		return nil, err
	}
	a.Backoff.Succeed(key)
	tok, sess, err := a.Sessions.Elevate(c.CredentialID, how, api.StepUpWindow)
	if err != nil {
		return nil, err
	}
	resp := connect.NewResponse(&rpmgrv1.StepUpResponse{ExpireTime: timestamppb.New(*sess.ElevatedUntil)})
	resp.Header().Add("Set-Cookie", websession.Cookie(tok, sess).String())
	return resp, nil
}

// Logout implements AuthService.
func (a *Auth) Logout(ctx context.Context, _ *connect.Request[rpmgrv1.LogoutRequest]) (*connect.Response[rpmgrv1.LogoutResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.Sessions.Revoke(c.UserID, c.CredentialID, c.UserID); err != nil && !errors.Is(err, websession.ErrNoSession) {
		return nil, err
	}
	resp := connect.NewResponse(&rpmgrv1.LogoutResponse{})
	resp.Header().Add("Set-Cookie", websession.ClearCookie().String())
	return resp, nil
}

// GetSession implements AuthService.
func (a *Auth) GetSession(ctx context.Context, _ *connect.Request[rpmgrv1.GetSessionRequest]) (*connect.Response[rpmgrv1.GetSessionResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	u, ms, err := a.Accounts.User(c.UserID)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.GetSessionResponse{UserId: u.ID, Email: u.Email, DisplayName: u.DisplayName, InstanceAdmin: u.InstanceAdmin}
	for _, m := range ms {
		out.Memberships = append(out.Memberships, &rpmgrv1.Membership{OrgId: m.OrgID, Role: string(m.Role)})
	}
	sessions, err := a.Sessions.List(c.UserID)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		if s.ID == c.CredentialID {
			out.Session = sessionOf(s, c.CredentialID)
		}
	}
	return connect.NewResponse(out), nil
}

// ListSessions implements AuthService.
func (a *Auth) ListSessions(ctx context.Context, _ *connect.Request[rpmgrv1.ListSessionsRequest]) (*connect.Response[rpmgrv1.ListSessionsResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	sessions, err := a.Sessions.List(c.UserID)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.ListSessionsResponse{}
	for _, s := range sessions {
		out.Sessions = append(out.Sessions, sessionOf(s, c.CredentialID))
	}
	return connect.NewResponse(out), nil
}

// RevokeSession implements AuthService.
func (a *Auth) RevokeSession(ctx context.Context, req *connect.Request[rpmgrv1.RevokeSessionRequest]) (*connect.Response[rpmgrv1.RevokeSessionResponse], error) {
	c, err := sessionCaller(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetSessionId()
	if err := a.Sessions.Revoke(c.UserID, id, c.UserID); errors.Is(err, websession.ErrNoSession) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	} else if err != nil {
		return nil, err
	}
	resp := connect.NewResponse(&rpmgrv1.RevokeSessionResponse{})
	if id == c.CredentialID {
		resp.Header().Add("Set-Cookie", websession.ClearCookie().String())
	}
	return resp, nil
}

// CompletePasswordReset implements AuthService; it ends every session of the user.
func (a *Auth) CompletePasswordReset(ctx context.Context, req *connect.Request[rpmgrv1.CompletePasswordResetRequest]) (
	*connect.Response[rpmgrv1.CompletePasswordResetResponse], error) {
	if !a.IPLimit.Allow(hostOf(req.Peer().Addr)) {
		return nil, limited(IPEvery)
	}
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
	if _, err := a.Sessions.RevokeAll(u.ID, "", u.ID, "password reset"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.CompletePasswordResetResponse{UserId: u.ID, Email: u.Email}), nil
}

// sessionCaller returns the caller of a method that needs a session, not an API token.
func sessionCaller(ctx context.Context) (*api.Caller, error) {
	c := api.CallerFrom(ctx)
	if c == nil || c.AuthMethod != "session" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the method needs a session, not an API token"))
	}
	return c, nil
}

func sessionOf(s *ent.Session, current string) *rpmgrv1.Session {
	return &rpmgrv1.Session{Id: s.ID, CreateTime: timestamppb.New(s.CreatedAt), LastSeenTime: timestamppb.New(s.LastSeenAt),
		IdleExpireTime: timestamppb.New(s.IdleExpiresAt), ExpireTime: timestamppb.New(s.AbsoluteExpiresAt), Ip: s.IP,
		UserAgent: s.UserAgent, Current: s.ID == current}
}

// withReason adds a google.rpc.ErrorInfo reason to an error.
func withReason(err *connect.Error, reason string) error {
	if d, derr := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: api.ErrorDomain}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

// limited is RESOURCE_EXHAUSTED with the time to wait (docs/07-api.md, "Errors").
func limited(wait time.Duration) error {
	err := connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("apisvc: too many attempts; retry in %s", wait.Round(time.Second)))
	if d, derr := connect.NewErrorDetail(&errdetails.RetryInfo{RetryDelay: durationpb.New(wait)}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

func hostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
