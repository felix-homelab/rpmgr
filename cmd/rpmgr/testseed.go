// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/testseed"
)

func init() { testCommands = append(testCommands, testseedCommand()) }

// list is a repeatable string flag.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// testseedCommand is `rpmgr testseed`, the end-to-end tests' seeding command of the rpmgrtest
// build (docs/12-testing-and-quality.md, "Where the cells run").
func testseedCommand() *cli.Command {
	var path string
	open := func(ctx context.Context, env *cli.Env) (*testseed.Seeder, error) {
		var cfg config.Controller
		if err := config.Load(config.Path(path, "controller", env.Getenv), &cfg); err != nil {
			return nil, err
		}
		return testseed.Open(ctx, cfg.Database.DSN, filepath.Join(filepath.Dir(cfg.Database.DSN), "revocations.log"))
	}
	configFlag := func(fs *flag.FlagSet) {
		fs.StringVar(&path, "config", "", "the controller's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml)")
	}
	var (
		group, name, target, transport, enabled, kind string
		endpoints, connectors                         list
		port, uses                                    int
		idle                                          time.Duration
	)
	verb := func(name, summary string, flags func(fs *flag.FlagSet), run func(*testseed.Seeder, *cli.Env) error) *cli.Command {
		return &cli.Command{Name: name, Summary: summary,
			Flags: func(fs *flag.FlagSet) {
				endpoints, connectors = nil, nil // one process may run several verbs in tests
				configFlag(fs)
				flags(fs)
			},
			Run: func(ctx context.Context, env *cli.Env, _ []string) error {
				s, err := open(ctx, env)
				if err != nil {
					return err
				}
				defer func() { _ = s.Close() }()
				return run(s, env)
			}}
	}
	return &cli.Command{Name: "testseed", Summary: "seed end-to-end test configuration (rpmgrtest builds only)", Sub: []*cli.Command{
		verb("gateway", "create a gateway and print the token that enrolls it", func(fs *flag.FlagSet) {
			fs.StringVar(&group, "group", "e2e", "gateway group, created if needed")
			fs.StringVar(&name, "name", "", "gateway name")
			fs.Var(&endpoints, "endpoint", "tunnel endpoint host:port (repeatable)")
		}, func(s *testseed.Seeder, env *cli.Env) error {
			tok, err := s.Gateway(group, name, endpoints)
			if err == nil {
				_, err = fmt.Fprintln(env.Stdout, tok)
			}
			return err
		}),
		verb("connector-token", "print a token that enrolls connectors", func(fs *flag.FlagSet) {
			fs.IntVar(&uses, "uses", 1, "how many connectors it enrolls")
		}, func(s *testseed.Seeder, env *cli.Env) error {
			tok, err := s.ConnectorToken(uses)
			if err == nil {
				_, err = fmt.Fprintln(env.Stdout, tok)
			}
			return err
		}),
		verb("route", "create a tcp route", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "route name")
			fs.StringVar(&group, "group", "e2e", "gateway group")
			fs.IntVar(&port, "port", 0, "public port")
			fs.Var(&connectors, "connector", "connector name that serves the route (repeatable)")
			fs.StringVar(&target, "target", "", "target host:port on the connectors' side")
			fs.StringVar(&transport, "transport", "", "auto, quic or h2; empty inherits")
			fs.DurationVar(&idle, "idle", 0, "idle timeout; 0 keeps the default")
		}, func(s *testseed.Seeder, _ *cli.Env) error {
			return s.AddRoute(testseed.Route{Name: name, Group: group, Port: port, Connectors: connectors, Target: target,
				Transport: transport, Idle: idle})
		}),
		verb("route-update", "change a route", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "route name")
			fs.StringVar(&transport, "transport", "", "auto, quic or h2; empty keeps it")
			fs.DurationVar(&idle, "idle", 0, "idle timeout; 0 keeps it")
			fs.StringVar(&enabled, "enabled", "", "true or false; empty keeps it")
		}, func(s *testseed.Seeder, _ *cli.Env) error {
			var on *bool
			if enabled != "" {
				b, err := strconv.ParseBool(enabled)
				if err != nil {
					return err
				}
				on = &b
			}
			return s.UpdateRoute(name, idle, transport, on)
		}),
		verb("revoke", "revoke a connector's or a gateway's identity", func(fs *flag.FlagSet) {
			fs.StringVar(&kind, "kind", "connector", "connector or gateway")
			fs.StringVar(&name, "name", "", "its name")
		}, func(s *testseed.Seeder, _ *cli.Env) error {
			switch pki.Kind(kind) {
			case pki.KindConnector, pki.KindGateway:
				return s.Revoke(pki.Kind(kind), name)
			}
			return errors.New("--kind: connector or gateway")
		}),
	}}
}
