// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agentcmd"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/handoff"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/setup/serversetup"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/update"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// commands returns rpmgr's command tree (docs/16-cli.md). Commands that are not implemented yet
// report "not available in this build".
func commands() *cli.Command {
	return &cli.Command{
		Name:    "rpmgr",
		Summary: "publish services on private networks through public gateways",
		Sub: append([]*cli.Command{
			agentcmd.Role("controller", "run the controller: web UI, API, CA and configuration", runController,
				controllerInit()),
			agentcmd.Role("gateway", "run a gateway: public listeners and data sessions from connectors", runGateway),
			agentcmd.Connector(),
			agentcmd.Role("all-in-one", "run a controller, a gateway and a connector in one process", runAllInOne, allInOneInit()),
			agentcmd.Setup("full", serversetup.Server{}),
			agentcmd.Enroll(),
			loginCommand(promptAPIToken),
			logoutCommand(),
			agentcmd.Leave(),
			agentcmd.Handoff(),
			agentcmd.Status(),
			agentcmd.Diag(),
			agentcmd.Policy(),
			agentcmd.Updater("full"),
			backupCommand(),
			restoreCommand(),
			migrateCommand(),
			caCommand(),
			kekCommand(),
			group("user", "administer users on the controller host", userResetPassword()),
			group("release", "administer release artifacts on the controller host",
				releaseImport()),
			agentcmd.SystemdUnit(),
			agentcmd.Version("full"),
		}, append(apiCommands(), testCommands...)...),
	}
}

// testCommands are the commands of the rpmgrtest build only (D60).
var testCommands []*cli.Command

// runGateway is `rpmgr gateway`: it runs until SIGINT or SIGTERM, then drains for 60 s.
func runGateway(ctx context.Context, env *cli.Env, path string) error {
	var cfg config.Gateway
	if err := config.Load(path, &cfg); err != nil {
		return err
	}
	logger, live, err := telemetry.NewLiveLogger(env.Stderr, cfg.Log)
	if err != nil {
		return err
	}
	stop, err := agentcmd.StartTracing(ctx, cfg.Tracing, "gateway")
	if err != nil {
		return err
	}
	defer stop()
	return gateway.Run(ctx, gateway.RunOptions{Config: cfg, Version: version.Get().Version, Logger: logger, LiveLog: live, Now: agentcmd.Clock,
		Update: update.UpdaterInstalled(), Handoff: handoff.LinkFrom(ctx)})
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
	stop, err := agentcmd.StartTracing(ctx, cfg.Tracing, "controller")
	if err != nil {
		return err
	}
	defer stop()
	return controller.Run(ctx, controller.RunOptions{Config: cfg, Version: version.Get().Version, Sources: routes.Sources(),
		Getenv: env.Getenv, Logger: logger, Now: agentcmd.Clock})
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
	stop, err := agentcmd.StartTracing(ctx, cfg.Tracing, "all-in-one")
	if err != nil {
		return err
	}
	defer stop()
	return allinone.Run(ctx, allinone.RunOptions{Config: cfg, Version: version.Get().Version, Getenv: env.Getenv, Logger: logger,
		Handoff: handoff.LinkFrom(ctx)})
}

// kekSourceHelp describes --kek-source of init; the default is config.KEKSourceFor's.
const kekSourceHelp = "KEK source of a new boot file: systemd-credential or file (default systemd-credential from systemd 250, else file)"

// allInOneInit is `rpmgr all-in-one init`.
func allInOneInit() *cli.Command {
	var o controller.InitOptions
	return &cli.Command{
		Name:    "init",
		Summary: "initialise an all-in-one installation: controller, CA and its enrolled gateway and connector",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&o.ConfigPath, "config", "", "boot file, written if it does not exist (default $RPMGR_CONFIG, else /etc/rpmgr/all-in-one.yaml)")
			fs.StringVar(&o.PublicURL, "public-url", "", "https URL of the web UI, the API and the agents; needed when the boot file does not exist")
			fs.StringVar(&o.KEKSource, "kek-source", "", kekSourceHelp)
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
				"  gateway:      %s\n  connector:    %s\n  KEK:          %s\nBack up the KEK separately: without it the database cannot be read.\n"+
				"The connector allows no target until its local policy does: rpmgr policy allow-target <host:port>.\n"+agentcmd.FirstUserText,
				r.TrustDomain, r.RootPin, r.GatewayID, r.ConnectorID, r.KEK, r.FirstUserLink)
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
			fs.StringVar(&o.KEKSource, "kek-source", "", kekSourceHelp)
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
				"  KEK:          %s\nBack up the KEK separately: without it the database cannot be read.\n"+agentcmd.FirstUserText,
				r.TrustDomain, r.RootPin, r.KEK, r.FirstUserLink)
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
			fs.StringVar(&configPath, "config", "", bootFlagHelp)
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			if out == "" {
				return cli.Usagef("backup needs --out")
			}
			info, err := controller.Backup(ctx, controllerBoot(configPath, env.Getenv), out, version.Get().Version, time.Now)
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

// restoreCommand is `rpmgr restore`: the controller's database and logs from a backup, with the
// revocations since applied again (docs/10-operations.md, "Backup and restore").
func restoreCommand() *cli.Command {
	var configPath, in string
	var logs []string
	return &cli.Command{
		Name:    "restore",
		Summary: "restore the controller from a backup",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&in, "in", "", "the archive of rpmgr backup (required)")
			fs.Func("revocation-log", "the revocation-log sink directory, or a replica's revocations.log; repeat for each (default the state directory's revocations.log)",
				func(s string) error { logs = append(logs, s); return nil })
			fs.StringVar(&configPath, "config", "", bootFlagHelp)
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			if in == "" {
				return cli.Usagef("restore needs --in")
			}
			r, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: controllerBoot(configPath, env.Getenv),
				Archive: in, RevocationLogs: logs})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Restored the backup of %s taken %s: new epoch %s (was %s).\n"+
				"Applied %d revocations since the backup again; %d of them name something the backup does not hold.\n"+
				"Every session, enrollment token, reset link and open invitation of the backup is invalidated.\n"+
				"The replaced files are kept with the suffix %s. Start one controller, check /readyz, then the others;\n"+
				"re-enroll agents enrolled after the backup.\n",
				r.TrustDomain, r.Backup.UTC().Format(time.RFC3339), r.NewEpoch, r.OldEpoch, r.Reapplied, r.Unknown, r.Previous)
			if err == nil && len(r.Kept) > 0 {
				_, err = fmt.Fprintf(env.Stdout, "\nNot applied again, check these on the Users page:\n  - %s\n", strings.Join(r.Kept, "\n  - "))
			}
			if err != nil || len(r.Review) == 0 {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "\nFAILED CLOSED: the revocations since the backup may be incomplete:\n  - %s\n"+
				"The instance and every org are in restore review and read-only; every API token is suspended; every user\n"+
				"must reset their password (rpmgr user reset-password --email …) and set up their second factor again.\n"+
				"Each org's Owner confirms its members and roles and resumes its tokens; end the review here with\n"+
				"rpmgr restore confirm.\n", strings.Join(r.Review, "\n  - "))
			return err
		},
		Sub: []*cli.Command{restoreConfirm()},
	}
}

// restoreConfirm is `rpmgr restore confirm`: the Instance Admin ends the restore review on the
// controller host, the instance-wide one or, with --org, an org's.
func restoreConfirm() *cli.Command {
	var configPath, org string
	return &cli.Command{
		Name:    "confirm",
		Summary: "end the instance-wide restore review",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&org, "org", "", "confirm this org's members and roles instead, by ID or slug")
			fs.StringVar(&configPath, "config", "", bootFlagHelp)
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			pending, err := controller.ConfirmRestore(ctx, controllerBoot(configPath, env.Getenv), org)
			if err != nil {
				return err
			}
			what := "Ended the instance-wide restore review."
			if org != "" {
				what = "Confirmed the members and roles of " + org + "."
			}
			if len(pending) == 0 {
				_, err = fmt.Fprintf(env.Stdout, "%s No org is in review.\n", what)
			} else {
				_, err = fmt.Fprintf(env.Stdout, "%s Orgs still in review, until their Owner confirms them: %s.\n", what, strings.Join(pending, ", "))
			}
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
			fs.StringVar(&configPath, "config", "", bootFlagHelp)
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("release import needs the directory of a release")
			}
			v := version.Get().Version
			m, err := controller.ImportRelease(ctx, controllerBoot(configPath, env.Getenv), args[0], v, release.Roots(), time.Now)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Imported rpmgr %s (manifest %d); the controller serves it under /dl/%s/.\n", m.Version, m.Seq, m.Version)
			return err
		},
	}
}

// userResetPassword is `rpmgr user reset-password`: local administration on the controller host,
// audited as local-cli (docs/04-security.md, "Roles").
func userResetPassword() *cli.Command {
	var configPath, email string
	return &cli.Command{
		Name:    "reset-password",
		Summary: "create a one-time password-reset link; before the first user exists, a first-user link",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&configPath, "config", "", bootFlagHelp)
			fs.StringVar(&email, "email", "", "the user's e-mail address; leave it out to create the first user")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			link, err := controller.ResetPasswordLink(ctx, controllerBoot(configPath, env.Getenv), email)
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
