// SPDX-License-Identifier: Apache-2.0

// Command rpmgr-connector is the connector-only build of rpmgr (D21, D119): the connector role and
// the commands of a connector host, without the controller, the gateway or the importer. It is
// released as rpmgr-<version>-<os>-<arch>-connector and installed as rpmgr
// (docs/02-architecture.md, "Roles").
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/felix-homelab/rpmgr/internal/agentcmd"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/setup"
	"github.com/felix-homelab/rpmgr/internal/version"
)

func init() { version.Variant = "connector" }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, commands(), os.Args[1:], &cli.Env{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
	})
	stop()
	os.Exit(code)
}

// commands returns the command tree of the connector-only build (docs/16-cli.md). The other roles
// are in the tree and report "not available in this build", so that a script that calls one on
// the wrong build learns why.
func commands() *cli.Command {
	return &cli.Command{
		Name:    "rpmgr",
		Summary: "the connector of rpmgr: reach the services of this network for a gateway",
		Sub: []*cli.Command{
			absent("controller"),
			absent("gateway"),
			agentcmd.Connector(),
			absent("all-in-one"),
			agentcmd.Setup("connector", nil, setup.Connector),
			agentcmd.Enroll(),
			agentcmd.Leave(),
			agentcmd.Status(),
			agentcmd.Diag(),
			agentcmd.Policy(),
			agentcmd.Updater("connector"),
			agentcmd.SystemdUnit("connector", "update"),
			agentcmd.Version("connector"),
		},
	}
}

// absent is a role of the full build only.
func absent(role string) *cli.Command {
	return &cli.Command{Name: role, Summary: "not in the connector-only build; install the full build", Run: cli.NotAvailable}
}
