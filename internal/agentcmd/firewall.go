// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/firewall"
)

// Firewall is `rpmgr firewall`: the root-owned helper that rpmgr-firewall.service runs, which
// applies a gateway's port-pool ranges to ufw within the bounds of a root-owned file (docs/04-
// security.md, "Host firewall for port pools"; D152). Like `rpmgr updater` it is plumbing for the
// units and the install scripts, and not listed in help (D151).
func Firewall() *cli.Command {
	a := firewall.Applier{}
	return &cli.Command{Name: "firewall", Summary: "the root-owned firewall helper of a gateway host", Hidden: true,
		Sub: []*cli.Command{firewallInstall(), {
			Name:    "apply",
			Summary: "open the gateway's port ranges in ufw, inside the bounds, as root, and report the outcome",
			Flags: func(fs *flag.FlagSet) {
				fs.StringVar(&a.Desired, "desired", "/var/lib/rpmgr/firewall/desired.json", "the ranges the gateway wants open, written by the gateway")
				fs.StringVar(&a.Bounds, "bounds", "/etc/rpmgr/firewall.json", "the bounds: the listeners and the maximum range; it must be owned by root and not writable by group or others")
				fs.StringVar(&a.StatusFile, "status", "/run/rpmgr-firewall/status.json", "where the outcome is written for the gateway")
			},
			Run: func(ctx context.Context, env *cli.Env, args []string) error {
				if len(args) != 0 {
					return cli.Usagef("firewall apply takes no arguments")
				}
				if !isRoot() {
					return errors.New("run it as root: the helper trusts only a bounds file root owns")
				}
				ctx, cancel := context.WithTimeout(ctx, firewall.RunTimeout)
				defer cancel()
				st, err := a.Apply(ctx)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(env.Stdout, "Firewall %s: %d rules held.\n", st.State, len(st.Rules))
				return err
			},
		}}}
}
