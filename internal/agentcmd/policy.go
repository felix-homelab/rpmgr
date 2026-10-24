// SPDX-License-Identifier: Apache-2.0

package agentcmd

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
		return exec.CommandContext(ctx, "systemctl", "reload", policyUnit(os.Stat)).Run() //nolint:gosec // G204: one of two fixed units
	}
)

// policyUnit is the unit whose connector reads the policy: rpmgr-connector, or, on a host with an
// all-in-one's boot file and no connector's, rpmgr-all-in-one, whose own connector reads it
// (ADR-0019).
func policyUnit(stat func(string) (os.FileInfo, error)) string {
	if _, err := stat("/etc/rpmgr/connector.yaml"); err != nil {
		if _, err := stat("/etc/rpmgr/all-in-one.yaml"); err == nil {
			return "rpmgr-all-in-one.service"
		}
	}
	return "rpmgr-connector.service"
}

// Policy is `rpmgr policy` (docs/16-cli.md): it shows or edits the connector-local policy.
func Policy() *cli.Command {
	path := policy.DefaultPath
	pathFlag := func(fs *flag.FlagSet) { fs.StringVar(&path, "file", policy.DefaultPath, "the policy file") }
	edit := func(name, summary string, do func(path, target string) (bool, error)) *cli.Command {
		var noReload bool
		return &cli.Command{Name: name, Summary: summary, Args: "<ip or subnet>[:<port or range>] | [<ipv6 or subnet>][:<port or range>] | <socket path>",
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
	// set changes one of the update keys, which the connector, the gateway and the root updater of
	// this host read; they pick a change up without a restart or a reload (docs/04-security.md,
	// "Over-the-air updates").
	set := func(name, summary, values string, do func(path, value string) (bool, error)) *cli.Command {
		return &cli.Command{Name: name, Summary: summary, Args: values, Flags: pathFlag,
			Run: func(_ context.Context, env *cli.Env, args []string) error {
				if len(args) != 1 {
					return cli.Usagef("%s needs one value: %s", name, values)
				}
				if geteuid() != 0 {
					return errors.New("the local policy is root's; run this as root (sudo)")
				}
				changed, err := do(path, args[0])
				if err != nil {
					return err
				}
				p, err := policy.Load(path)
				if err != nil {
					return err
				}
				what := "nothing to change"
				if changed {
					what = "updated; running agents and the updater take it up without a restart"
				}
				_, _ = fmt.Fprintf(env.Stdout, "%s: %s\nauto_update: %s\nupdate_channel: %s\n", path, what, p.AutoUpdate, p.UpdateChannel)
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
		edit("allow-target", "allow the connector to dial a target; without a port, all its ports", policy.AllowTarget),
		edit("remove-target", "stop allowing a target", policy.RemoveTarget),
		edit("deny-target", "deny a target, whatever allows it", policy.DenyTarget),
		edit("remove-deny-target", "stop denying a target", policy.RemoveDenyTarget),
		set("set-auto-update", "set whether this host takes over-the-air updates: auto, notify (only report them) or off",
			"auto | notify | off", policy.SetAutoUpdate),
		set("set-update-channel", "set which releases this host takes: stable, or prerelease for betas and release candidates too",
			"stable | prerelease", policy.SetUpdateChannel),
	)
}
