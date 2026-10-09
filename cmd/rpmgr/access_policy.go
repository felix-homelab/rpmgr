// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/term"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// passwordPrompt asks for a basic-auth user's password; with keep, an empty answer keeps the
// password the policy has for the user. A test replaces it.
var passwordPrompt = func(user string, keep bool) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no password for %s: give it in --passwords-file, or run on a terminal", user)
	}
	defer func() { _ = tty.Close() }()
	prompt := "Password for " + user + ": "
	if keep {
		prompt = "Password for " + user + " (empty keeps the current one): "
	}
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // G115: a file descriptor fits in an int
	_, _ = fmt.Fprintln(tty)
	return string(b), err
}

// policyFlags are the flags of create and update access-policy.
type policyFlags struct {
	name, description, passwords, output string
	rules                                listFlag
	force                                bool
	wait                                 time.Duration
	fs                                   *flag.FlagSet
}

func (f *policyFlags) register(fs *flag.FlagSet, update bool) {
	f.fs = fs
	fs.StringVar(&f.name, "name", "", "the policy's name, unique in the org")
	fs.StringVar(&f.description, "description", "", "a description for people")
	fs.Var(&f.rules, "rule", "a rule: allow:<cidr>,…, deny:<cidr>,… or basic-auth:<user>,…; repeat for more, applied in the order given")
	fs.StringVar(&f.passwords, "passwords-file", "", "a file of user:password lines for the basic-auth users; the others are asked for")
	fs.DurationVar(&f.wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
	if update {
		fs.BoolVar(&f.force, "force", false, "update without checking that the policy is unchanged since this command read it")
	}
	outputFlag(fs, &f.output)
}

// readPasswords reads a file of user:password lines; blank lines and lines starting with # are
// skipped. A file other users may read is reported.
func readPasswords(env *cli.Env, path string) (map[string]string, error) {
	out := map[string]string{}
	if path == "" {
		return out, nil
	}
	warnOpenFile(env, "passwords", path)
	fh, err := os.Open(path) //nolint:gosec // G304: the user's file
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	sc := bufio.NewScanner(fh)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, pw, ok := strings.Cut(line, ":")
		if !ok || user == "" {
			return nil, cli.Usagef("%s, line %d: not user:password", path, n)
		}
		out[user] = pw
	}
	return out, sc.Err()
}

// warnOpenFile warns on standard error when other users may read a file of secrets.
func warnOpenFile(env *cli.Env, what, path string) {
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		_, _ = fmt.Fprintf(env.Stderr, "warning: the %s file %s is open to other users (mode %04o); make it 0600\n", what, path, st.Mode().Perm())
	}
}

// rulesOf turns --rule values into rules, in order. A basic-auth user's password comes from
// passwords, else from the prompt; with keep it may stay empty, which keeps the current one.
func rulesOf(values []string, passwords map[string]string, keep bool) ([]*rpmgrv1.AccessRule, error) {
	var out []*rpmgrv1.AccessRule
	for _, v := range values {
		kind, list, ok := strings.Cut(v, ":")
		if !ok || list == "" {
			return nil, cli.Usagef("--rule %q: allow:<cidr>,…, deny:<cidr>,… or basic-auth:<user>,…", v)
		}
		items := strings.Split(list, ",")
		switch kind {
		case "allow":
			out = append(out, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: items}}})
		case "deny":
			out = append(out, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_IpDeny{IpDeny: &rpmgrv1.IPRuleParams{Cidrs: items}}})
		case "basic-auth":
			ba := &rpmgrv1.BasicAuthRule{}
			for _, user := range items {
				if strings.Contains(user, ":") {
					return nil, cli.Usagef("--rule %q: a user name has no colon; passwords come from --passwords-file or the prompt", "basic-auth:…")
				}
				pw, ok := passwords[user]
				if !ok {
					var err error
					if pw, err = passwordPrompt(user, keep); err != nil {
						return nil, err
					}
				}
				if pw == "" && !keep {
					return nil, cli.Usagef("no password for %s", user)
				}
				ba.Users = append(ba.Users, &rpmgrv1.BasicAuthCredential{Name: user, Password: pw})
			}
			out = append(out, &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: ba}})
		default:
			return nil, cli.Usagef("--rule %q: the kind is allow, deny or basic-auth", v)
		}
	}
	return out, nil
}

// rules reads the passwords and builds the rules the flags give.
func (f *policyFlags) buildRules(env *cli.Env, keep bool) ([]*rpmgrv1.AccessRule, error) {
	passwords, err := readPasswords(env, f.passwords)
	if err != nil {
		return nil, err
	}
	return rulesOf(f.rules, passwords, keep)
}

// accessPolicyCommands are create and update access-policy. Passwords never come from arguments:
// they come from a file or a prompt.
func accessPolicyCommands() (create, update *cli.Command) {
	k, err := apicli.KindOf("access-policy")
	if err != nil {
		panic(err)
	}
	var cf, uf policyFlags
	create = &cli.Command{
		Name: "access-policy", Summary: "create an access policy of IP rules and basic auth, applied in order",
		Flags: func(fs *flag.FlagSet) { cf.register(fs, false) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			if cf.name == "" {
				return cli.Usagef("give --name")
			}
			rules, err := cf.buildRules(env, false)
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			md, err := k.Method("CreateAccessPolicy")
			if err != nil {
				return err
			}
			req := &rpmgrv1.CreateAccessPolicyRequest{OrgId: s.creds.Org,
				AccessPolicy: &rpmgrv1.AccessPolicy{Name: cf.name, Description: cf.description, Rules: rules}}
			return s.send(ctx, env, k, md, req, cf.wait, cf.output, "Created")
		},
	}
	update = &cli.Command{
		Name: "access-policy", Summary: "change an access policy's name, description or rules", Args: "<id>",
		Flags: func(fs *flag.FlagSet) { uf.register(fs, true) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the policy's ID")
			}
			set := setFlags(uf.fs)
			if !set["name"] && !set["description"] && !set["rule"] {
				return cli.Usagef("name a field to change: --name, --description or --rule")
			}
			rules, err := uf.buildRules(env, true)
			if err != nil {
				return err
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			cur, err := rpmgrv1connect.NewPolicyServiceClient(s.hc, s.creds.Controller).GetAccessPolicy(ctx,
				connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: args[0]}))
			if err != nil {
				return apiError(err)
			}
			p := proto.Clone(cur.Msg.GetAccessPolicy()).(*rpmgrv1.AccessPolicy)
			var paths []string
			if set["name"] {
				p.Name, paths = uf.name, append(paths, "name")
			}
			if set["description"] {
				p.Description, paths = uf.description, append(paths, "description")
			}
			if set["rule"] {
				p.Rules, paths = rules, append(paths, "rules")
			}
			req := &rpmgrv1.UpdateAccessPolicyRequest{AccessPolicy: p, UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}
			if !uf.force {
				req.Etag = p.GetEtag()
			}
			md, err := k.Method("UpdateAccessPolicy")
			if err != nil {
				return err
			}
			return s.send(ctx, env, k, md, req, uf.wait, uf.output, "Updated")
		},
	}
	return create, update
}
