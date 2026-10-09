// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// memberCommands are update and remove member, create invitation, and revoke token; create token
// says where tokens are made.
func memberCommands() map[string][]*cli.Command {
	var role string
	update := &cli.Command{
		Name: "member", Summary: "change a member's role; granting Admin or Owner takes a step-up", Args: "<user ID or e-mail address>",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&role, "role", "", "the new role: owner, admin, operator or viewer")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || role == "" {
				return cli.Usagef("give --role and the member")
			}
			return memberChange(ctx, env, args[0], func(s *apiSession, oc rpmgrv1connect.OrgServiceClient, m *rpmgrv1.Member) (string, error) {
				req := &rpmgrv1.UpdateMemberRequest{OrgId: s.creds.Org, UserId: m.GetUserId(), Role: role}
				if err := protovalidate.Validate(req); err != nil {
					return "", cli.Usagef("%v", err)
				}
				err := s.withStepUp(ctx, func() error {
					_, err := oc.UpdateMember(ctx, connect.NewRequest(req))
					return err
				})
				return fmt.Sprintf("%s is now %s", m.GetEmail(), role), err
			})
		},
	}
	remove := &cli.Command{
		Name: "member", Summary: "end a membership; the user's tokens lose their access to the org", Args: "<user ID or e-mail address>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the member")
			}
			return memberChange(ctx, env, args[0], func(s *apiSession, oc rpmgrv1connect.OrgServiceClient, m *rpmgrv1.Member) (string, error) {
				_, err := oc.RemoveMember(ctx, connect.NewRequest(&rpmgrv1.RemoveMemberRequest{OrgId: s.creds.Org, UserId: m.GetUserId()}))
				return fmt.Sprintf("Removed %s from the org", m.GetEmail()), err
			})
		},
	}
	var email, invRole string
	invite := &cli.Command{
		Name: "invitation", Summary: "invite someone to the org and print the one-time link; as Admin or Owner it takes a step-up",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&email, "email", "", "the invitee's e-mail address")
			fs.StringVar(&invRole, "role", "viewer", "the role: owner, admin, operator or viewer")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 || email == "" {
				return cli.Usagef("give --email and no argument")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.CreateInvitationRequest{OrgId: s.creds.Org, Email: email, Role: invRole}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			var resp *connect.Response[rpmgrv1.CreateInvitationResponse]
			if err := s.withStepUp(ctx, func() error {
				var err error
				resp, err = rpmgrv1connect.NewOrgServiceClient(s.hc, s.creds.Controller).CreateInvitation(ctx, connect.NewRequest(req))
				return err
			}); err != nil {
				return apiError(err)
			}
			sent := "It was not e-mailed: pass it on to " + email + " yourself."
			if resp.Msg.GetEmailSent() {
				sent = "It was also e-mailed to " + email + "."
			}
			_, err = fmt.Fprintf(env.Stdout, "Invitation link, shown once, valid until %s:\n%s\n%s\n",
				resp.Msg.GetExpireTime().AsTime().UTC().Format("2006-01-02 15:04 MST"), resp.Msg.GetUrl(), sent)
			return err
		},
	}
	revoke := &cli.Command{
		Name: "token", Summary: "revoke one of your personal API tokens", Args: "<id>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the token's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			if _, err := rpmgrv1connect.NewTokenServiceClient(s.hc, s.creds.Controller).RevokeAPIToken(ctx,
				connect.NewRequest(&rpmgrv1.RevokeAPITokenRequest{OrgId: s.creds.Org, TokenId: args[0]})); err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Revoked token %s.\n", args[0])
			return err
		},
	}
	create := &cli.Command{
		Name: "token", Summary: "personal API tokens are made in the web UI",
		Run: func(context.Context, *cli.Env, []string) error {
			return cli.Usagef("a personal API token is made in the web UI, under Account: only a signed-in session makes one, so that a token never makes another")
		},
	}
	return map[string][]*cli.Command{"update": {update}, "remove": {remove}, "create": {invite, create}, "revoke": {revoke}}
}

// memberChange finds the member that ref names, by user ID or e-mail address, and makes a change
// to it that returns what to say.
func memberChange(ctx context.Context, env *cli.Env, ref string,
	change func(*apiSession, rpmgrv1connect.OrgServiceClient, *rpmgrv1.Member) (string, error)) error {
	s, err := newAPISession(env)
	if err != nil {
		return err
	}
	oc := rpmgrv1connect.NewOrgServiceClient(s.hc, s.creds.Controller)
	resp, err := oc.ListMembers(ctx, connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: s.creds.Org}))
	if err != nil {
		return apiError(err)
	}
	var m *rpmgrv1.Member
	for _, x := range resp.Msg.GetMembers() {
		if x.GetUserId() == ref || strings.EqualFold(x.GetEmail(), ref) {
			m = x
			break
		}
	}
	if m == nil {
		return fmt.Errorf("the org has no member %q", ref)
	}
	msg, err := change(s, oc, m)
	if err != nil {
		return apiError(err)
	}
	_, err = fmt.Fprintln(env.Stdout, msg+".")
	return err
}
