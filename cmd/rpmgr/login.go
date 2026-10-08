// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"
	"golang.org/x/term"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// apiTokenPrefix starts every personal API token (docs/04-security.md, "API tokens").
const apiTokenPrefix = "rpmgr_pat_" //nolint:gosec // G101: a prefix, not a credential

// loginCommand is `rpmgr login`: it checks a personal API token against the controller and
// stores it for the commands of the public API.
func loginCommand(prompt func() (string, error)) *cli.Command {
	var controller, org, tokenFile, caFile string
	return &cli.Command{
		Name:    "login",
		Summary: "store a personal API token for the commands of the public API",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&controller, "controller", "", "the controller's URL, e.g. https://panel.example.com")
			fs.StringVar(&org, "org", "", "the ID of the token's org")
			fs.StringVar(&tokenFile, "token-file", "", "file holding the token (default $RPMGR_TOKEN, else a prompt)")
			fs.StringVar(&caFile, "ca-file", "", "PEM certificates that verify the controller instead of the system's roots")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			if controller == "" || org == "" {
				return cli.Usagef("--controller and --org are required")
			}
			base, err := apicli.ControllerURL(controller)
			if err != nil {
				return cli.Usagef("%v", err)
			}
			tok, err := readAPIToken(tokenFile, env.Getenv, prompt)
			if err != nil {
				return err
			}
			creds := &apicli.Credentials{Controller: base, Org: org, Token: tok}
			if caFile != "" {
				if creds.CAFile, err = filepath.Abs(caFile); err != nil {
					return err
				}
			}
			hc, err := apicli.Client(creds)
			if err != nil {
				return err
			}
			o, err := rpmgrv1connect.NewOrgServiceClient(hc, base).GetOrg(ctx, connect.NewRequest(&rpmgrv1.GetOrgRequest{OrgId: org}))
			if err != nil {
				return loginError(err, org)
			}
			path, err := apicli.Path(env.Getenv)
			if err != nil {
				return err
			}
			if err := apicli.Save(path, creds); err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Logged in to %s, org %s (%s); the token is in %s.\n", base, o.Msg.GetOrg().GetName(), org, path)
			return err
		},
	}
}

// logoutCommand is `rpmgr logout`: it removes the stored credentials. The token itself stays
// valid until it expires or is revoked.
func logoutCommand() *cli.Command {
	return &cli.Command{
		Name:    "logout",
		Summary: "remove the stored API token from this machine",
		Run: func(_ context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			path, err := apicli.Path(env.Getenv)
			if err != nil {
				return err
			}
			switch err := os.Remove(path); {
			case errors.Is(err, os.ErrNotExist):
				_, err = fmt.Fprintln(env.Stdout, "Not logged in.")
				return err
			case err != nil:
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Removed %s. The token stays valid until it expires; revoke it in the web UI if no one needs it.\n", path)
			return err
		},
	}
}

// readAPIToken returns a personal API token from, in this order, the file at path, $RPMGR_TOKEN
// or a prompt; never from the command line (docs/04-security.md, "Secrets at rest and in logs").
func readAPIToken(path string, getenv func(string) string, prompt func() (string, error)) (secret.Value, error) {
	var t string
	switch {
	case path != "":
		b, err := os.ReadFile(path) //nolint:gosec // G304: the user's --token-file
		if err != nil {
			return secret.Value{}, err
		}
		t = string(b)
	case getenv("RPMGR_TOKEN") != "":
		t = getenv("RPMGR_TOKEN")
	default:
		var err error
		if t, err = prompt(); err != nil {
			return secret.Value{}, err
		}
	}
	t = strings.TrimSpace(t)
	if !strings.HasPrefix(t, apiTokenPrefix) {
		return secret.Value{}, errors.New("that is not a personal API token; create one in the web UI under Account")
	}
	return secret.FromBytes([]byte(t)), nil
}

// promptAPIToken asks for the token on the terminal with echo off.
func promptAPIToken() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no API token: use --token-file or RPMGR_TOKEN, or run on a terminal")
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, "API token: "); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // G115: a file descriptor fits in an int
	_, _ = fmt.Fprintln(tty)
	return string(b), err
}

// loginError says why the controller refused the token.
func loginError(err error, org string) error {
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated:
		return errors.New("the controller does not accept the token: it is unknown, expired or revoked")
	case connect.CodePermissionDenied:
		return errors.New("the token lacks the org.read scope, which every command needs")
	case connect.CodeNotFound:
		return fmt.Errorf("the token does not belong to the org %s", org)
	}
	return fmt.Errorf("the controller: %w", err)
}
