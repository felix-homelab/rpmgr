// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/policy"
)

// What `rpmgr policy` uses of the host, replaced in tests.
var (
	geteuid = os.Geteuid
	// reloadConnector asks the running connector to reload its policy (SIGHUP through systemd).
	reloadConnector = func(ctx context.Context) error {
		return exec.CommandContext(ctx, "systemctl", "reload", "rpmgr-connector.service").Run() //nolint:gosec // G204: fixed arguments
	}
)

// policyCommand is `rpmgr policy` (docs/16-cli.md): it shows or edits the connector-local policy.
func policyCommand() *cli.Command {
	path := policy.DefaultPath
	pathFlag := func(fs *flag.FlagSet) { fs.StringVar(&path, "file", policy.DefaultPath, "the policy file") }
	edit := func(name, summary string, do func(path, target string) (bool, error)) *cli.Command {
		var noReload bool
		return &cli.Command{Name: name, Summary: summary, Args: "<ip>:<port> | <socket path>",
			Flags: func(fs *flag.FlagSet) {
				pathFlag(fs)
				fs.BoolVar(&noReload, "no-reload", false, "do not ask the running connector to reload the policy")
			},
			Run: func(ctx context.Context, env *cli.Env, args []string) error {
				if len(args) != 1 {
					return cli.Usagef("%s needs one target", name)
				}
				if geteuid() != 0 {
					return errors.New("the local policy is root's; run this as root (sudo)")
				}
				changed, err := do(path, args[0])
				if err != nil {
					return err
				}
				if !changed {
					_, _ = fmt.Fprintf(env.Stdout, "%s: nothing to change\n", path)
					return nil
				}
				_, _ = fmt.Fprintf(env.Stdout, "%s: updated\n", path)
				if noReload {
					return nil
				}
				if err := reloadConnector(ctx); err != nil {
					_, _ = fmt.Fprintf(env.Stderr, "warning: could not reload the connector (%v); it picks the change up within a few seconds\n", err)
				}
				return nil
			}}
	}
	return group("policy", "show or change the connector-local policy of this host",
		&cli.Command{Name: "show", Summary: "print the effective local policy", Flags: pathFlag,
			Run: func(_ context.Context, env *cli.Env, _ []string) error {
				p, err := policy.Load(path)
				if err != nil {
					_, _ = fmt.Fprintf(env.Stdout, "%s: invalid, nothing is allowed\n", path)
					return err
				}
				if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
					_, _ = fmt.Fprintf(env.Stdout, "%s: no file, the defaults apply\n", path)
				} else {
					_, _ = fmt.Fprintf(env.Stdout, "%s:\n", path)
				}
				_, _ = fmt.Fprint(env.Stdout, p.Describe())
				return nil
			}},
		edit("allow-target", "allow the connector to dial a target", policy.AllowTarget),
		edit("remove-target", "stop allowing a target", policy.RemoveTarget),
	)
}
