// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Org is OrgService.
type Org struct {
	rpmgrv1connect.UnimplementedOrgServiceHandler
	Members   *accounts.Members
	API       *api.Server // for request_id deduplication
	PublicURL string
	Now       func() time.Time
	Mail      Mailer // e-mails invitations when there is a relay
	Logger    *slog.Logger
}

// GetOrg implements OrgService.
func (o *Org) GetOrg(_ context.Context, req *connect.Request[rpmgrv1.GetOrgRequest]) (*connect.Response[rpmgrv1.GetOrgResponse], error) {
	org, err := o.Members.Org(req.Msg.GetOrgId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.GetOrgResponse{Org: orgOf(org)}), nil
}

// UpdateOrg implements OrgService.
func (o *Org) UpdateOrg(ctx context.Context, req *connect.Request[rpmgrv1.UpdateOrgRequest]) (*connect.Response[rpmgrv1.UpdateOrgResponse], error) {
	org, err := o.Members.Rename(ctx, req.Msg.GetOrgId(), strings.TrimSpace(req.Msg.GetName()), api.CallerFrom(ctx).UserID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.UpdateOrgResponse{Org: orgOf(org)}), nil
}

// ListMembers implements OrgService.
func (o *Org) ListMembers(_ context.Context, req *connect.Request[rpmgrv1.ListMembersRequest]) (*connect.Response[rpmgrv1.ListMembersResponse], error) {
	ms, err := o.Members.List(req.Msg.GetOrgId())
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.ListMembersResponse{}
	for _, m := range ms {
		out.Members = append(out.Members, &rpmgrv1.Member{UserId: m.UserID, Email: m.Email, DisplayName: m.DisplayName,
			Role: m.Role, CreateTime: timestamppb.New(m.Since)})
	}
	return connect.NewResponse(out), nil
}

// UpdateMember implements OrgService.
func (o *Org) UpdateMember(ctx context.Context, req *connect.Request[rpmgrv1.UpdateMemberRequest]) (*connect.Response[rpmgrv1.UpdateMemberResponse], error) {
	m := req.Msg
	c, role, err := o.acting(ctx, m.GetOrgId(), m.GetRole())
	if err != nil {
		return nil, err
	}
	if err := o.Members.SetRole(ctx, m.GetOrgId(), m.GetUserId(), m.GetRole(), c.UserID, role); err != nil {
		return nil, memberError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateMemberResponse{}), nil
}

// RemoveMember implements OrgService.
func (o *Org) RemoveMember(ctx context.Context, req *connect.Request[rpmgrv1.RemoveMemberRequest]) (*connect.Response[rpmgrv1.RemoveMemberResponse], error) {
	m := req.Msg
	c, role, err := o.acting(ctx, m.GetOrgId(), "")
	if err != nil {
		return nil, err
	}
	if err := o.Members.Remove(ctx, m.GetOrgId(), m.GetUserId(), c.UserID, role); err != nil {
		return nil, memberError(err)
	}
	return connect.NewResponse(&rpmgrv1.RemoveMemberResponse{}), nil
}

// CreateInvitation implements OrgService.
func (o *Org) CreateInvitation(ctx context.Context, req *connect.Request[rpmgrv1.CreateInvitationRequest]) (
	*connect.Response[rpmgrv1.CreateInvitationResponse], error) {
	m := req.Msg
	c, role, err := o.acting(ctx, m.GetOrgId(), m.GetRole())
	if err != nil {
		return nil, err
	}
	resp, err := api.Dedupe(ctx, o.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateInvitationResponse, error) {
		tok, err := o.Members.Invite(ctx, m.GetOrgId(), m.GetEmail(), m.GetRole(), c.UserID, role)
		if err != nil {
			return nil, memberError(err)
		}
		out := &rpmgrv1.CreateInvitationResponse{Url: strings.TrimSuffix(o.PublicURL, "/") + "/invite#" + tok,
			ExpireTime: timestamppb.New(o.now().Add(accounts.InvitationTTL))}
		out.EmailSent = o.mailInvitation(ctx, m.GetOrgId(), m.GetEmail(), m.GetRole(), out.GetUrl())
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// AcceptInvitation implements OrgService.
func (o *Org) AcceptInvitation(ctx context.Context, req *connect.Request[rpmgrv1.AcceptInvitationRequest]) (
	*connect.Response[rpmgrv1.AcceptInvitationResponse], error) {
	signedIn := ""
	if c := api.CallerFrom(ctx); c != nil {
		signedIn = c.UserID
	}
	m := req.Msg
	u, org, err := o.Members.AcceptInvitation(ctx, m.GetToken(), signedIn, m.GetDisplayName(), m.GetPassword())
	switch {
	case errors.Is(err, accounts.ErrInvitation), errors.Is(err, accounts.ErrDisplayName), errors.Is(err, password.ErrLength):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, accounts.ErrSignInFirst):
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, accounts.ErrOtherAddress), errors.Is(err, accounts.ErrMember):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.AcceptInvitationResponse{OrgId: org, UserId: u.ID}), nil
}

// mailInvitation e-mails an invitation if there is a relay, and reports whether the relay took it;
// why it did not goes to the log, not to the caller.
func (o *Org) mailInvitation(ctx context.Context, orgID, to, role, link string) bool {
	if o.Mail == nil {
		return false
	}
	if ok, err := o.Mail.Configured(ctx); err != nil || !ok {
		return false
	}
	org, err := o.Members.Org(orgID)
	if err == nil {
		err = o.Mail.Send(ctx, invitationMail(strings.ToLower(strings.TrimSpace(to)), org.Name, role, link, accounts.InvitationTTL))
	}
	if err != nil && o.Logger != nil {
		o.Logger.Warn("cannot e-mail an invitation", "org", orgID, "error", err)
	}
	return err == nil
}

// acting returns the caller and their role in the org, after the step-up that granting Admin or
// Owner needs (docs/04-security.md, "Human authentication and sessions").
func (o *Org) acting(ctx context.Context, orgID, grants string) (*api.Caller, string, error) {
	c := api.CallerFrom(ctx)
	if grants == authz.RoleAdmin || grants == authz.RoleOwner {
		if err := api.RequireStepUp(ctx, o.now()); err != nil {
			return nil, "", err
		}
	}
	return c, c.Memberships[orgID], nil
}

func (o *Org) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

// memberError gives the member rules their codes.
func memberError(err error) error {
	switch {
	case errors.Is(err, accounts.ErrOwnerOnly):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, accounts.ErrLastOwner):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, accounts.ErrNoMember):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, accounts.ErrRole), errors.Is(err, accounts.ErrEmail):
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return err
}

func orgOf(o *ent.Org) *rpmgrv1.Org {
	return &rpmgrv1.Org{Id: o.ID, Name: o.Name, Slug: o.Slug, CreateTime: timestamppb.New(o.CreatedAt)}
}
