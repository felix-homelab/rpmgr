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
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/units"
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
			backupCommand(),
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
				releaseImport()),
			systemdUnit(),
			versionCommand(),
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

// systemdUnit is `rpmgr systemd-unit`: a role's hardened unit, for a script or manual install
// (docs/10-operations.md, "Hardened systemd units").
func systemdUnit() *cli.Command {
	var configPath, bin string
	return &cli.Command{
		Name:    "systemd-unit",
		Summary: "print the hardened systemd unit of a role",
		Args:    "controller | gateway | connector | all-in-one",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&bin, "bin", "/usr/local/bin/rpmgr", "the installed binary")
			fs.StringVar(&configPath, "config", "", "the controller's or all-in-one's boot file, for its KEK credential (default $RPMGR_CONFIG, else /etc/rpmgr/<role>.yaml)")
		},
		Run: func(_ context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("systemd-unit needs a role")
			}
			o := units.Options{Bin: bin}
			switch role := args[0]; role {
			case "controller", "all-in-one":
				var kek struct{ Source, Name string }
				path := config.Path(configPath, role, env.Getenv)
				if role == "controller" {
					var c config.Controller
					if err := config.Load(path, &c); err != nil {
						return fmt.Errorf("%w; run `rpmgr %s init` first", err, role)
					}
					kek.Source, kek.Name = c.KEK.Source, c.KEK.Name
				} else {
					var a config.AllInOne
					if err := config.Load(path, &a); err != nil {
						return fmt.Errorf("%w; run `rpmgr %s init` first", err, role)
					}
					kek.Source, kek.Name = a.Controller().KEK.Source, a.Controller().KEK.Name
				}
				if kek.Source == config.KEKSystemdCredential {
					o.Credential = kek.Name
				}
			case "gateway", "connector":
			default:
				return cli.Usagef("no role %q: controller, gateway, connector or all-in-one", role)
			}
			b, err := units.Render(args[0], o)
			if err != nil {
				return err
			}
			_, err = env.Stdout.Write(b)
			return err
		},
	}
}

// backupCommand is `rpmgr backup`: the controller's database and logs in one archive, written
// while it runs (docs/10-operations.md, "Backup and restore").
func backupCommand() *cli.Command {
	var configPath, out string
	return &cli.Command{
		Name:    "backup",
		Summary: "write a consistent backup of the controller",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&out, "out", "", "the archive to write; it must not exist (required)")
			fs.StringVar(&configPath, "config", "", "the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml)")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			if out == "" {
				return cli.Usagef("backup needs --out")
			}
			info, err := controller.Backup(ctx, config.Path(configPath, "controller", env.Getenv), out, version.Get().Version, time.Now)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Wrote %s: the database of %s (epoch %s) with its revocation log and audit checkpoints.\n"+
				"Back up the KEK separately and keep it apart from this archive: without it the archive's secrets cannot be read.\n",
				out, info.TrustDomain, info.DBEpoch)
			return err
		},
	}
}

// releaseImport is `rpmgr release import`: the controller's own release from a directory, for
// air-gapped installations (D59).
func releaseImport() *cli.Command {
	var configPath string
	return &cli.Command{
		Name:    "import",
		Summary: "import a signed release for air-gapped installations",
		Args:    "<dir>",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&configPath, "config", "", "the controller's boot file, or all-in-one's (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml)")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("release import needs the directory of a release")
			}
			v := version.Get().Version
			m, err := controller.ImportRelease(ctx, config.Path(configPath, "controller", env.Getenv), args[0], v, release.Roots(), time.Now)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Imported rpmgr %s (manifest %d); the controller serves it under /dl/%s/.\n", m.Version, m.Seq, m.Version)
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

// versionCommand is `rpmgr version`; with --verbose it also prints the release root keys
// compiled into the binary, which the release job checks (D60).
func versionCommand() *cli.Command {
	var verbose bool
	return &cli.Command{
		Name:    "version",
		Summary: "print the version of this binary",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&verbose, "verbose", false, "also print the release root keys compiled into this binary")
		},
		Run: func(_ context.Context, env *cli.Env, _ []string) error {
			if _, err := fmt.Fprintln(env.Stdout, version.Get()); err != nil || !verbose {
				return err
			}
			roots := release.Roots()
			kind := "release root keys"
			if release.TestBuild {
				kind = "test release root keys (rpmgrtest build)"
			}
			if len(roots) == 0 {
				_, err := fmt.Fprintf(env.Stdout, "%s: none; this build verifies no release\n", kind)
				return err
			}
			if _, err := fmt.Fprintf(env.Stdout, "%s:\n", kind); err != nil {
				return err
			}
			for _, k := range roots {
				if _, err := fmt.Fprintf(env.Stdout, "  %s  sha256:%s\n", k.IDString(), k.Fingerprint()); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
