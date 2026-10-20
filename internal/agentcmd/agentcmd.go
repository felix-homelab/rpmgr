// SPDX-License-Identifier: Apache-2.0

// Package agentcmd holds the commands of a connector or gateway host (docs/16-cli.md): the
// connector role, enroll, leave, status, diag, policy and version, and the helpers the role
// commands share. It is registered by cmd/rpmgr and links nothing of the controller, the gateway
// or the importer, so that the connector-only build can register it too (docs/02-architecture.md,
// "Roles"; D119).
package agentcmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/units"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// Clock is the roles' clock: nil, which is time.Now, except in the rpmgrtest build, whose
// chaos tests shift it (D60).
var Clock func() time.Time

// BootDir is where the boot files are; a test replaces it.
var BootDir = "/etc/rpmgr"

// Role is a command that runs one role from its boot file; run nil is not available yet.
func Role(name, summary string, run func(ctx context.Context, env *cli.Env, configPath string) error, sub ...*cli.Command) *cli.Command {
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

// StartTracing starts the process's tracing from a boot file's section (docs/10-operations.md,
// "Traces"); stop exports what is left, within 5 s.
func StartTracing(ctx context.Context, cfg config.Tracing, role string) (stop func(), err error) {
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

// Connector is `rpmgr connector`.
func Connector() *cli.Command {
	return Role("connector", "run a connector: data sessions to gateways and the local targets", runConnector)
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
	stop, err := StartTracing(ctx, cfg.Tracing, "connector")
	if err != nil {
		return err
	}
	defer stop()
	return connector.Run(ctx, connector.RunOptions{Config: cfg, Version: version.Get().Version, Getenv: env.Getenv, Logger: logger,
		Now: Clock})
}

// Version is `rpmgr version`; with --verbose it also prints the build's variant, full or
// connector, which the install scripts read to keep it (D119), and the release root keys compiled
// into the binary, which the release job checks (D60).
func Version(variant string) *cli.Command {
	var verbose bool
	return &cli.Command{
		Name:    "version",
		Summary: "print the version of this binary",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&verbose, "verbose", false, "also print the variant of this build and the release root keys compiled into it")
		},
		Run: func(_ context.Context, env *cli.Env, _ []string) error {
			if _, err := fmt.Fprintln(env.Stdout, version.Get()); err != nil || !verbose {
				return err
			}
			if _, err := fmt.Fprintf(env.Stdout, "variant: %s\n", variant); err != nil {
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

func group(name, summary string, sub ...*cli.Command) *cli.Command {
	return &cli.Command{Name: name, Summary: summary, Sub: sub}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SystemdUnit is `rpmgr systemd-unit`: the hardened unit of one of roles, all four when none are
// given, for a script or manual install (docs/10-operations.md, "Hardened systemd units"). The
// connector-only build prints the connector's only.
func SystemdUnit(roles ...string) *cli.Command {
	if len(roles) == 0 {
		roles = []string{"controller", "gateway", "connector", "all-in-one"}
	}
	var configPath, bin string
	return &cli.Command{
		Name:    "systemd-unit",
		Summary: "print the hardened systemd unit of a role",
		Args:    strings.Join(roles, " | "),
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&bin, "bin", "/usr/local/bin/rpmgr", "the installed binary")
			fs.StringVar(&configPath, "config", "", "the controller's or all-in-one's boot file, for its KEK credential and revocation-log sink (default $RPMGR_CONFIG, else /etc/rpmgr/<role>.yaml)")
		},
		Run: func(_ context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("systemd-unit needs a role")
			}
			var o units.Options
			if !slices.Contains(roles, args[0]) {
				return cli.Usagef("no role %q: %s", args[0], strings.Join(roles, ", "))
			}
			switch role := args[0]; role {
			case "controller", "all-in-one":
				var c config.Controller
				path := config.Path(configPath, role, env.Getenv)
				if role == "controller" {
					if err := config.Load(path, &c); err != nil {
						return fmt.Errorf("%w; run `rpmgr %s init` first", err, role)
					}
				} else {
					var a config.AllInOne
					if err := config.Load(path, &a); err != nil {
						return fmt.Errorf("%w; run `rpmgr %s init` first", err, role)
					}
					c = a.Controller()
				}
				o = units.ForController(c) // the KEK credential and the revocation-log sink
			}
			o.Bin = bin
			b, err := units.Render(args[0], o)
			if err != nil {
				return err
			}
			_, err = env.Stdout.Write(b)
			return err
		},
	}
}
