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
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
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

// Version is `rpmgr version`; with --verbose it also prints the release root keys compiled into
// the binary, which the release job checks (D60).
func Version() *cli.Command {
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

func group(name, summary string, sub ...*cli.Command) *cli.Command {
	return &cli.Command{Name: name, Summary: summary, Sub: sub}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
