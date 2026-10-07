// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// enrollCommand is `rpmgr enroll` (docs/16-cli.md). It has no flag for the token itself: the token
// comes from --token-file, $RPMGR_ENROLL_TOKEN or the terminal, never from the command line.
func enrollCommand() *cli.Command {
	var o agent.EnrollOptions
	var tokenFile, bundleFile string
	return &cli.Command{
		Name:    "enroll",
		Summary: "enroll this host as an agent with a single-use token",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&o.Controller, "controller", "", "controller URL, https://<host>[:<port>] (required)")
			fs.StringVar(&o.Pin, "ca-pin", "", "pin of the controller's root CA, sha256:<base64> (required)")
			fs.StringVar(&tokenFile, "token-file", "", "file with the enrollment token (default $RPMGR_ENROLL_TOKEN, else a prompt)")
			fs.BoolVar(&o.Replace, "replace", false, "replace an existing identity on this host")
			fs.StringVar(&o.IdentityDir, "identity-dir", "/var/lib/rpmgr/identity", "where the identity is written")
			fs.StringVar(&bundleFile, "trust-bundle", "", "PEM trust bundle to use instead of downloading it")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			if o.Controller == "" || o.Pin == "" {
				return cli.Usagef("--controller and --ca-pin are required")
			}
			if bundleFile != "" {
				b, err := os.ReadFile(bundleFile) //nolint:gosec // G304: the operator's --trust-bundle
				if err != nil {
					return err
				}
				o.Bundle = b
			}
			tok, err := agent.ReadToken(tokenFile, env.Getenv, promptToken,
				func(w string) { _, _ = fmt.Fprintln(env.Stderr, "warning:", w) })
			if err != nil {
				return err
			}
			o.Token = tok
			host, _ := os.Hostname()
			o.Host = &agentv1.HostFacts{Hostname: host, Os: runtime.GOOS, Arch: runtime.GOARCH}
			o.Version = version.Version
			id, err := agent.Enroll(ctx, o)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Enrolled %s %s in trust domain %s; identity written to %s.\n",
				id.Kind, id.AgentID, id.TrustDomain, o.IdentityDir)
			return err
		},
	}
}

// promptToken asks for the token on the terminal with echo off. With `curl … | sh`, standard input
// is the script, so it reads /dev/tty, not standard input.
func promptToken() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no enrollment token: use --token-file or RPMGR_ENROLL_TOKEN, or run on a terminal")
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, "Enrollment token: "); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // G115: a file descriptor fits in an int
	_, _ = fmt.Fprintln(tty)
	return string(b), err
}
