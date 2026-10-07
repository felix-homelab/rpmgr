// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// commands returns rpmgr's command tree (docs/16-cli.md). Commands that are not implemented yet
// report "not available in this build".
func commands() *cli.Command {
	return &cli.Command{
		Name:    "rpmgr",
		Summary: "publish services on private networks through public gateways",
		Sub: []*cli.Command{
			role("controller", "run the controller: web UI, API, CA and configuration",
				controllerInit()),
			role("gateway", "run a gateway: public listeners and data sessions from connectors"),
			role("connector", "run a connector: data sessions to gateways and the local targets"),
			role("all-in-one", "run a controller and a gateway in one process",
				&cli.Command{Name: "init", Summary: "initialise an all-in-one installation", Run: cli.NotAvailable}),
			enrollCommand(),
			{Name: "leave", Summary: "revoke this agent's identity and remove it from the host", Run: cli.NotAvailable},
			{Name: "status", Summary: "show the state of the agent on this host", Run: cli.NotAvailable},
			group("diag", "diagnose this host",
				leaf("transport", "test the data-session transports to a gateway"),
				leaf("clock", "compare this host's clock with the controller's")),
			group("policy", "show or change the connector-local policy of this host",
				leaf("show", "print the effective local policy"),
				leaf("allow-target", "allow the connector to dial a target"),
				leaf("remove-target", "stop allowing a target")),
			{Name: "backup", Summary: "write a consistent backup of the controller", Run: cli.NotAvailable},
			{Name: "restore", Summary: "restore the controller from a backup", Run: cli.NotAvailable,
				Sub: []*cli.Command{leaf("confirm", "end the instance-wide restore review")}},
			{Name: "migrate", Summary: "apply database migrations", Run: cli.NotAvailable},
			group("ca", "administer the internal CA on the controller host",
				leaf("status", "show the CA keys and their validity"),
				leaf("rotate-intermediate", "rotate the issuing intermediate now")),
			group("kek", "administer the key-encryption key on the controller host",
				leaf("status", "show which KEK version wraps the stored secrets"),
				leaf("rotate", "re-wrap every stored secret under a new KEK")),
			group("user", "administer users on the controller host",
				leaf("reset-password", "create a one-time password-reset link")),
			group("release", "administer release artifacts on the controller host",
				leaf("import", "import a signed release for air-gapped installations")),
			{Name: "version", Summary: "print the version of this binary", Run: runVersion},
		},
	}
}

// role is a command that runs one role from its boot file.
func role(name, summary string, sub ...*cli.Command) *cli.Command {
	return &cli.Command{
		Name:    name,
		Summary: summary,
		Flags: func(fs *flag.FlagSet) {
			fs.String("config", "", "boot file (default $RPMGR_CONFIG, else /etc/rpmgr/"+name+".yaml)")
		},
		Run: cli.NotAvailable,
		Sub: sub,
	}
}

// controllerInit is `rpmgr controller init`.
func controllerInit() *cli.Command {
	var o controller.InitOptions
	return &cli.Command{
		Name:    "init",
		Summary: "initialise a controller: boot file, KEK, database, trust domain and CA",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&o.ConfigPath, "config", "", "boot file, written if it does not exist (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml)")
			fs.StringVar(&o.PublicURL, "public-url", "", "https URL of the web UI and API; needed when the boot file does not exist")
			fs.StringVar(&o.KEKSource, "kek-source", "", "KEK source of a new boot file: systemd-credential (default) or file")
			fs.StringVar(&o.KEKPath, "kek-path", "", "KEK file of a new boot file with --kek-source file (default /etc/rpmgr/kek)")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			o.ConfigPath = config.Path(o.ConfigPath, "controller", env.Getenv)
			o.Getenv = env.Getenv
			r, err := controller.Init(ctx, o)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Initialised the controller.\n  trust domain: %s\n  CA pin:       %s\n"+
				"  KEK:          %s\nBack up the KEK separately: without it the database cannot be read.\n",
				r.TrustDomain, r.RootPin, r.KEK)
			return err
		},
	}
}

func group(name, summary string, sub ...*cli.Command) *cli.Command {
	return &cli.Command{Name: name, Summary: summary, Sub: sub}
}

func leaf(name, summary string) *cli.Command {
	return &cli.Command{Name: name, Summary: summary, Run: cli.NotAvailable}
}

func runVersion(_ context.Context, env *cli.Env, _ []string) error {
	_, err := fmt.Fprintln(env.Stdout, version.Get())
	return err
}
