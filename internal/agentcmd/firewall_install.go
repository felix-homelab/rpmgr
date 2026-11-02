// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

// firewallInstall is `rpmgr firewall install`, which the install script runs once the gateway's
// boot file names the firewall (docs/10-operations.md, "Host firewall helper"): it writes the
// root-owned bounds file from the boot file, makes the directory of the desired file and writes the
// helper's units. The script enables them.
func firewallInstall() *cli.Command {
	var role, etc, lib, unitDir, bin string
	var noUnits bool
	return &cli.Command{
		Name:    "install",
		Summary: "write the firewall helper's bounds from the boot file, its directory and its units, as root",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&role, "role", "gateway", "the role whose boot file names the firewall: gateway or all-in-one")
			fs.StringVar(&etc, "etc", BootDir, "the boot files; the bounds file goes here")
			fs.StringVar(&lib, "lib", "/var/lib/rpmgr", "the state directory, whose firewall/ the gateway writes the desired file in")
			fs.StringVar(&unitDir, "units", "/etc/systemd/system", "where the units rpmgr-firewall.path and rpmgr-firewall.service go")
			fs.StringVar(&bin, "bin", "/usr/local/bin/rpmgr", "the installed binary")
			fs.BoolVar(&noUnits, "no-units", false, "write no units, as on a host without systemd")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("firewall install takes no arguments")
			}
			if !isRoot() {
				return errors.New("run it as root: the helper trusts only a bounds file root owns")
			}
			h := setupHost
			h.Paths = setup.Paths{Etc: etc, Lib: lib, Units: unitDir, Bin: bin}
			r, err := setup.InstallFirewall(ctx, h, role, noUnits)
			if err != nil {
				return err
			}
			if r.FirewallNote != "" {
				_, _ = fmt.Fprintln(env.Stderr, "warning:", r.FirewallNote)
			}
			_, err = fmt.Fprintf(env.Stdout, "Wrote %s/firewall.json and %s/firewall/.\n", etc, lib)
			return err
		},
	}
}
