// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
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
	var (
		path string
		cfg  config.Controller
	)
	open := func(ctx context.Context, env *cli.Env) (*testseed.Seeder, error) {
		if err := config.Load(config.Path(path, "controller", env.Getenv), &cfg); err != nil {
			return nil, err
		}
		return testseed.Open(ctx, cfg.Database.DSN, filepath.Join(filepath.Dir(cfg.Database.DSN), "revocations.log"))
	}
	// withKEK lets s store certificate keys under the KEK of the boot file open read.
	withKEK := func(s *testseed.Seeder, env *cli.Env) error {
		var (
			kek secret.KEK
			err error
		)
		switch cfg.KEK.Source {
		case config.KEKFile:
			kek, err = secret.LoadKEKFile(cfg.KEK.Path)
		case config.KEKSystemdCredential:
			kek, err = secret.LoadSystemdCredential(cfg.KEK.Name, env.Getenv)
		default:
			err = fmt.Errorf("kek.source %q", cfg.KEK.Source)
		}
		if err == nil {
			err = s.UseKEK(kek)
		}
		return err
	}
	configFlag := func(fs *flag.FlagSet) {
		fs.StringVar(&path, "config", "", "the controller's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/controller.yaml)")
	}
	var (
		group, name, target, transport, enabled, kind string
		upstream, serverName, certFile, keyFile, ca   string
		endpoints, connectors, hostnames, rules       list
		port, uses                                    int
		idle                                          time.Duration
	)
	verb := func(name, summary string, flags func(fs *flag.FlagSet), run func(*testseed.Seeder, *cli.Env) error) *cli.Command {
		return &cli.Command{Name: name, Summary: summary,
			Flags: func(fs *flag.FlagSet) {
				endpoints, connectors, hostnames, rules = nil, nil, nil, nil // one process may run several verbs in tests
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
		verb("udp-route", "create a udp route", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "route name")
			fs.StringVar(&group, "group", "e2e", "gateway group")
			fs.IntVar(&port, "port", 0, "public port")
			fs.Var(&connectors, "connector", "connector name that serves the route (repeatable)")
			fs.StringVar(&target, "target", "", "target host:port on the connectors' side")
			fs.StringVar(&transport, "transport", "", "auto, quic or h2; empty inherits")
			fs.DurationVar(&idle, "idle", 0, "flow idle timeout; 0 keeps the default")
		}, func(s *testseed.Seeder, _ *cli.Env) error {
			return s.AddUDPRoute(testseed.Route{Name: name, Group: group, Port: port, Connectors: connectors, Target: target,
				Transport: transport, Idle: idle})
		}),
		verb("http-route", "create an http route with an uploaded certificate", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "route name")
			fs.StringVar(&group, "group", "e2e", "gateway group")
			fs.Var(&hostnames, "hostname", "hostname, its parent domain claimed and verified (repeatable)")
			fs.Var(&connectors, "connector", "connector name that serves the route (repeatable)")
			fs.StringVar(&target, "target", "", "upstream host:port on the connectors' side")
			fs.StringVar(&transport, "transport", "", "auto, quic or h2; empty inherits")
			fs.StringVar(&upstream, "upstream", "http", "http, h2c or https")
			fs.StringVar(&serverName, "server-name", "", "https: the name the upstream's certificate carries")
			fs.StringVar(&ca, "ca-file", "", "https: PEM CA bundle that verifies the upstream")
			fs.StringVar(&certFile, "cert-file", "", "PEM certificate chain of the route")
			fs.StringVar(&keyFile, "key-file", "", "PEM private key of the route's certificate")
		}, func(s *testseed.Seeder, env *cli.Env) error {
			if err := withKEK(s, env); err != nil {
				return err
			}
			r := testseed.HTTPRoute{Name: name, Group: group, Hostnames: hostnames, Connectors: connectors, Target: target,
				Transport: transport, Upstream: upstream, ServerName: serverName}
			var err error
			if r.CertPEM, err = os.ReadFile(certFile); err != nil { //nolint:gosec // G304: the test's own file
				return err
			}
			if r.KeyPEM, err = os.ReadFile(keyFile); err != nil { //nolint:gosec // G304: the test's own file
				return err
			}
			if ca != "" {
				if r.CABundle, err = os.ReadFile(ca); err != nil { //nolint:gosec // G304: the test's own file
					return err
				}
			}
			return s.AddHTTPRoute(r)
		}),
		verb("passthrough-route", "create a tls_passthrough route", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "route name")
			fs.StringVar(&group, "group", "e2e", "gateway group")
			fs.Var(&hostnames, "hostname", "hostname, its parent domain claimed and verified (repeatable)")
			fs.Var(&connectors, "connector", "connector name that serves the route (repeatable)")
			fs.StringVar(&target, "target", "", "TLS backend host:port on the connectors' side")
			fs.StringVar(&transport, "transport", "", "auto, quic or h2; empty inherits")
		}, func(s *testseed.Seeder, _ *cli.Env) error {
			return s.AddPassthroughRoute(name, group, hostnames, connectors, target, transport)
		}),
		verb("access", "set the IP rules of a route's own access policy", func(fs *flag.FlagSet) {
			fs.StringVar(&name, "route", "", "route name")
			fs.Var(&rules, "rule", "allow=<cidr>[,<cidr>] or deny=<cidr>[,<cidr>], in order (repeatable); none clears them")
		}, func(s *testseed.Seeder, _ *cli.Env) error {
			var rs []testseed.IPRule
			for _, r := range rules {
				verb, cidrs, ok := strings.Cut(r, "=")
				if !ok || (verb != "allow" && verb != "deny") || cidrs == "" {
					return fmt.Errorf("--rule %q: allow=<cidrs> or deny=<cidrs>", r)
				}
				rs = append(rs, testseed.IPRule{Allow: verb == "allow", CIDRs: strings.Split(cidrs, ",")})
			}
			return s.SetAccess(name, rs)
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
