// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// recoveryCommands recover another user's access (docs/04-security.md, "Account recovery"): create
// reset-link, remove second-factor and update user --instance-admin. Each takes a step-up.
func recoveryCommands() map[string][]*cli.Command {
	link := &cli.Command{
		Name: "reset-link", Summary: "print a one-time link that sets a member's password, for one who forgot it; takes a step-up",
		Args: "<user ID or e-mail address>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the user")
			}
			return recoverUser(ctx, env, args[0], func(s *apiSession, uc rpmgrv1connect.UserServiceClient, id, who string) (string, error) {
				var resp *connect.Response[rpmgrv1.CreatePasswordResetLinkResponse]
				err := s.withStepUp(ctx, func() error {
					var err error
					resp, err = uc.CreatePasswordResetLink(ctx, connect.NewRequest(&rpmgrv1.CreatePasswordResetLinkRequest{UserId: id}))
					return err
				})
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("Password reset link for %s, shown once, valid until %s; pass it on yourself:\n%s", who,
					resp.Msg.GetExpireTime().AsTime().UTC().Format("2006-01-02 15:04 MST"), resp.Msg.GetUrl()), nil
			})
		},
	}
	second := &cli.Command{
		Name: "second-factor", Summary: "remove a user's authenticator and recovery codes, for one who lost both, and end their sessions; takes a step-up",
		Args: "<user ID or e-mail address>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the user")
			}
			return recoverUser(ctx, env, args[0], func(s *apiSession, uc rpmgrv1connect.UserServiceClient, id, who string) (string, error) {
				err := s.withStepUp(ctx, func() error {
					_, err := uc.RemoveUserTOTP(ctx, connect.NewRequest(&rpmgrv1.RemoveUserTOTPRequest{UserId: id}))
					return err
				})
				return fmt.Sprintf("Removed the second factor of %s and ended their sessions. They sign in with their password and set up a new authenticator.", who), err
			})
		},
	}
	var admin *bool
	user := &cli.Command{
		Name: "user", Summary: "grant or revoke the Instance Admin role; as Instance Admin, with a step-up",
		Args: "<user ID or e-mail address>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolFunc("instance-admin", "grant the Instance Admin role, or revoke it with --instance-admin=false", func(v string) error {
				b, err := strconv.ParseBool(v)
				admin = &b
				return err
			})
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || admin == nil {
				return cli.Usagef("give --instance-admin or --instance-admin=false, and the user")
			}
			return recoverUser(ctx, env, args[0], func(s *apiSession, uc rpmgrv1connect.UserServiceClient, id, who string) (string, error) {
				err := s.withStepUp(ctx, func() error {
					_, err := uc.SetInstanceAdmin(ctx, connect.NewRequest(&rpmgrv1.SetInstanceAdminRequest{UserId: id, InstanceAdmin: *admin}))
					return err
				})
				if *admin {
					return who + " is Instance Admin", err
				}
				return who + " is no Instance Admin", err
			})
		},
	}
	return map[string][]*cli.Command{"create": {link}, "remove": {second}, "update": {user}}
}

// recoverUser finds the user that ref names and makes a change to their account that returns what
// to say. A user ID is taken as it is; an e-mail address is looked up among the org's members,
// then, for the Instance Admin, among all users.
func recoverUser(ctx context.Context, env *cli.Env, ref string,
	change func(s *apiSession, uc rpmgrv1connect.UserServiceClient, id, who string) (string, error)) error {
	s, err := newAPISession(env)
	if err != nil {
		return err
	}
	uc := rpmgrv1connect.NewUserServiceClient(s.hc, s.creds.Controller)
	id, who, err := findUser(ctx, s, uc, ref)
	if err != nil {
		return err
	}
	msg, err := change(s, uc, id, who)
	if err != nil {
		return apiError(err)
	}
	_, err = fmt.Fprintln(env.Stdout, msg+".")
	return err
}

func findUser(ctx context.Context, s *apiSession, uc rpmgrv1connect.UserServiceClient, ref string) (id, who string, err error) {
	if strings.HasPrefix(ref, "usr_") {
		return ref, ref, nil
	}
	members, err := rpmgrv1connect.NewOrgServiceClient(s.hc, s.creds.Controller).ListMembers(ctx,
		connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: s.creds.Org}))
	if err != nil {
		return "", "", apiError(err)
	}
	for _, m := range members.Msg.GetMembers() {
		if strings.EqualFold(m.GetEmail(), ref) {
			return m.GetUserId(), m.GetEmail(), nil
		}
	}
	page := ""
	for {
		resp, err := uc.ListUsers(ctx, connect.NewRequest(&rpmgrv1.ListUsersRequest{PageToken: page}))
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			return "", "", fmt.Errorf("the org has no member %q", ref)
		}
		if err != nil {
			return "", "", apiError(err)
		}
		for _, u := range resp.Msg.GetUsers() {
			if strings.EqualFold(u.GetEmail(), ref) {
				return u.GetId(), u.GetEmail(), nil
			}
		}
		if page = resp.Msg.GetNextPageToken(); page == "" {
			return "", "", errors.New("no user has the address " + strconv.Quote(ref))
		}
	}
}
