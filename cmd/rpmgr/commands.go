// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// commands returns rpmgr's command tree (docs/16-cli.md). Commands that are not implemented yet
// report "not available in this build".
func commands() *cli.Command {
	return &cli.Command{
		Name:    "rpmgr",
		Summary: "publish services on private networks through public gateways",
		Sub: append([]*cli.Command{
			role("controller", "run the controller: web UI, API, CA and configuration", runController,
				controllerInit()),
			role("gateway", "run a gateway: public listeners and data sessions from connectors", runGateway),
			role("connector", "run a connector: data sessions to gateways and the local targets", runConnector),
			role("all-in-one", "run a controller and a gateway in one process", runAllInOne, allInOneInit()),
			enrollCommand(),
			loginCommand(promptAPIToken),
			logoutCommand(),
			{Name: "leave", Summary: "revoke this agent's identity and remove it from the host", Run: cli.NotAvailable},
			{Name: "status", Summary: "show the state of the agent on this host", Run: cli.NotAvailable},
			group("diag", "diagnose this host",
				leaf("transport", "test the data-session transports to a gateway"),
				leaf("clock", "compare this host's clock with the controller's")),
			policyCommand(),
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
			group("user", "administer users on the controller host", userResetPassword()),
			group("release", "administer release artifacts on the controller host",
				leaf("import", "import a signed release for air-gapped installations")),
			{Name: "version", Summary: "print the version of this binary", Run: runVersion},
		}, append(apiCommands(), testCommands...)...),
	}
}

// testCommands are the commands of the rpmgrtest build only (D60).
var testCommands []*cli.Command

// role is a command that runs one role from its boot file; run nil is not available yet.
func role(name, summary string, run func(ctx context.Context, env *cli.Env, configPath string) error, sub ...*cli.Command) *cli.Command {
	var path string
	c := &cli.Command{
		Name:    name,
		Summary: summary,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&path, "config", "", "boot file (default $RPMGR_CONFIG, else /etc/rpmgr/"+name+".yaml)")
		},
		Run: cli.NotAvailable,
		Sub: sub,
	}
	if run != nil {
		c.Run = func(ctx context.Context, env *cli.Env, _ []string) error {
			return run(ctx, env, config.Path(path, name, env.Getenv))
		}
	}
	return c
}

// runGateway is `rpmgr gateway`: it runs until SIGINT or SIGTERM, then drains for 60 s.
func runGateway(ctx context.Context, env *cli.Env, path string) error {
	var cfg config.Gateway
	if err := config.Load(path, &cfg); err != nil {
		return err
	}
	logger, err := telemetry.NewLogger(env.Stderr, cfg.Log)
	if err != nil {
		return err
	}
	stop, err := startTracing(ctx, cfg.Tracing, "gateway")
	if err != nil {
		return err
	}
	defer stop()
	return gateway.Run(ctx, gateway.RunOptions{Config: cfg, Version: version.Get().Version, Logger: logger})
}

// runConnector is `rpmgr connector`: it runs until SIGINT or SIGTERM.
func runConnector(ctx context.Context, env *cli.Env, path string) error {
	var cfg config.Connector
	if err := config.Load(path, &cfg); err != nil {
		return err
	}
	logger, err := telemetry.NewLogger(env.Stderr, cfg.Log)
	if err != nil {
		return err
	}
	stop, err := startTracing(ctx, cfg.Tracing, "connector")
	if err != nil {
		return err
	}
	defer stop()
	return connector.Run(ctx, connector.RunOptions{Config: cfg, Version: version.Get().Version, Getenv: env.Getenv, Logger: logger})
}

// runController is `rpmgr controller`: it runs until SIGINT or SIGTERM, then drains.
func runController(ctx context.Context, env *cli.Env, path string) error {
	var cfg config.Controller
	if err := config.Load(path, &cfg); err != nil {
		return err
	}
	logger, err := telemetry.NewLogger(env.Stderr, cfg.Log)
	if err != nil {
		return err
	}
	stop, err := startTracing(ctx, cfg.Tracing, "controller")
	if err != nil {
		return err
	}
	defer stop()
	return controller.Run(ctx, controller.RunOptions{Config: cfg, Version: version.Get().Version, Sources: routes.Sources(),
		Getenv: env.Getenv, Logger: logger})
}

// runAllInOne is `rpmgr all-in-one`: it runs until SIGINT or SIGTERM; the gateway drains first.
func runAllInOne(ctx context.Context, env *cli.Env, path string) error {
	var cfg config.AllInOne
	if err := config.Load(path, &cfg); err != nil {
		return err
	}
	logger, err := telemetry.NewLogger(env.Stderr, cfg.Log)
	if err != nil {
		return err
	}
	stop, err := startTracing(ctx, cfg.Tracing, "all-in-one")
	if err != nil {
		return err
	}
	defer stop()
	return allinone.Run(ctx, allinone.RunOptions{Config: cfg, Version: version.Get().Version, Getenv: env.Getenv, Logger: logger})
}

// startTracing starts the process's tracing from a boot file's section (docs/10-operations.md,
// "Traces"); stop exports what is left, within 5 s.
func startTracing(ctx context.Context, cfg config.Tracing, role string) (stop func(), err error) {
	shutdown, err := telemetry.StartTracing(ctx, cfg, role, version.Get().Version)
	if err != nil {
		return nil, err
	}
	return func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = shutdown(sctx)
	}, nil
}

// allInOneInit is `rpmgr all-in-one init`.
func allInOneInit() *cli.Command {
	var o controller.InitOptions
	return &cli.Command{
		Name:    "init",
		Summary: "initialise an all-in-one installation: controller, CA and its enrolled gateway",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&o.ConfigPath, "config", "", "boot file, written if it does not exist (default $RPMGR_CONFIG, else /etc/rpmgr/all-in-one.yaml)")
			fs.StringVar(&o.PublicURL, "public-url", "", "https URL of the web UI, the API and the agents; needed when the boot file does not exist")
			fs.StringVar(&o.KEKSource, "kek-source", "", "KEK source of a new boot file: systemd-credential (default) or file")
			fs.StringVar(&o.KEKPath, "kek-path", "", "KEK file of a new boot file with --kek-source file (default /etc/rpmgr/kek)")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			o.ConfigPath = config.Path(o.ConfigPath, "all-in-one", env.Getenv)
			o.Getenv = env.Getenv
			r, err := allinone.Init(ctx, o)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Initialised the all-in-one installation.\n  trust domain: %s\n  CA pin:       %s\n"+
				"  gateway:      %s\n  KEK:          %s\nBack up the KEK separately: without it the database cannot be read.\n"+firstUser,
				r.TrustDomain, r.RootPin, r.GatewayID, r.KEK, r.FirstUserLink)
			return err
		},
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
				"  KEK:          %s\nBack up the KEK separately: without it the database cannot be read.\n"+firstUser,
				r.TrustDomain, r.RootPin, r.KEK, r.FirstUserLink)
			return err
		},
	}
}

// firstUser ends the output of init with the first-user link.
const firstUser = "Create the first user, Instance Admin and Owner, with this one-time link (valid 7 days):\n  %s\n"

// userResetPassword is `rpmgr user reset-password`: local administration on the controller host,
// audited as local-cli (docs/04-security.md, "Roles").
func userResetPassword() *cli.Command {
	var configPath, email string
	return &cli.Command{
		Name:    "reset-password",
		Summary: "create a one-time password-reset link; before the first user exists, a first-user link",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&configPath, "config", "", "the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml)")
			fs.StringVar(&email, "email", "", "the user's e-mail address; leave it out to create the first user")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			link, err := controller.ResetPasswordLink(ctx, config.Path(configPath, "controller", env.Getenv), email)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "One-time link, valid %s:\n  %s\n", link.Valid, link.URL)
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
