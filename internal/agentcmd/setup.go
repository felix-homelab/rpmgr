// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

// setupHost is the host `rpmgr setup` changes; tests replace it. Setup gives it its Server.
var setupHost = setup.Host{}

// Setup is `rpmgr setup`, with variant the build's, full or connector, server the steps of a
// controller and an all-in-one, the full build's (package serversetup), and roles the roles the
// build sets up, all of them when none are given. The connector-only build passes no server and
// the connector role (docs/02-architecture.md, "Roles").
func Setup(variant string, server setup.Server, roles ...setup.Role) *cli.Command {
	setupHost.Variant, setupHost.Server, setupHost.Roles = variant, server, roles
	return setupCommand()
}

// offeredRoles names the roles setupHost sets up, for messages.
func offeredRoles() string {
	var names []string
	for _, r := range setup.Roles {
		if setupHost.Offers(r.Role) {
			names = append(names, string(r.Role))
		}
	}
	return strings.Join(names, ", ")
}

// setupCommand is `rpmgr setup` (docs/16-cli.md): it asks for the values in forms pre-filled with
// its flags, shows the plan, and on confirmation runs it; with --yes it asks nothing and takes every
// value from the flags. The token never comes from the command line: it comes from --token-file,
// $RPMGR_ENROLL_TOKEN or the terminal, as for `rpmgr enroll`; nor does a proxy URL with
// credentials, which comes from --proxy-file or the form.
func setupCommand() *cli.Command {
	var v setup.Values
	var role, tokenFile, proxyFile string
	var targets, denied cli.List
	var yes bool
	return &cli.Command{
		Name:    "setup",
		Summary: "set this host up for a role: boot file, init or enrollment, systemd unit",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&role, "role", "", "all-in-one, controller, gateway or connector (required with --yes)")
			fs.StringVar(&v.PublicURL, "public-url", "", "controller, all-in-one: https URL of the web UI, the API and the agents")
			fs.StringVar(&v.KEKSource, "kek-source", "", "controller, all-in-one: systemd-credential or file (default by the systemd version)")
			fs.StringVar(&v.KEKPath, "kek-path", "", "controller, all-in-one: the KEK file with --kek-source file (default /etc/rpmgr/kek)")
			fs.StringVar(&v.TLS, "tls", "", "controller, all-in-one: the public URL's certificate: acme, files or self-signed (default acme for a public name, else self-signed)")
			fs.StringVar(&v.CertFile, "cert-file", "", "controller, all-in-one: the certificate chain with --tls files")
			fs.StringVar(&v.KeyFile, "key-file", "", "controller, all-in-one: its key with --tls files")
			fs.StringVar(&v.ACMEDirectory, "acme-directory", "", "controller, all-in-one: the instance's ACME CA for the public URL and the routes: production, staging or a directory URL (default production)")
			fs.StringVar(&v.ACMEEmail, "acme-email", "", "controller, all-in-one: the instance's ACME account e-mail address")
			fs.StringVar(&v.ListenHTTPS, "listen-https", "", "controller: listen.https (default :443)")
			fs.StringVar(&v.ListenTCP, "listen-tcp", "", "all-in-one, gateway: listen.tcp (default :443)")
			fs.StringVar(&v.ListenUDP, "listen-udp", "", "all-in-one, gateway: listen.udp (default :443)")
			fs.StringVar(&v.ListenHTTP, "listen-http", "", "controller, all-in-one, gateway: listen.http, or off (default :80)")
			fs.StringVar(&v.ListenAdmin, "listen-admin", "", "listen.admin (default the role's 127.0.0.1 port)")
			fs.StringVar(&v.ControllerURL, "controller", "", "gateway, connector: the controller URL, https://<host>[:<port>]")
			fs.StringVar(&v.Pin, "ca-pin", "", "gateway, connector: the controller's CA pin, sha256:<base64>")
			fs.StringVar(&tokenFile, "token-file", "", "gateway, connector: file with the gateway or enrollment token (default $RPMGR_ENROLL_TOKEN, else a prompt)")
			fs.Var(&targets, "allow-target", "connector: a target the connector-local policy allows: an address or subnet, optionally "+
				":port or :port-port, IPv6 in brackets, or a socket path; repeat for more")
			fs.Var(&denied, "deny-target", "connector: a target the connector-local policy denies, whatever allows it; the same form")
			fs.StringVar(&v.Proxy, "proxy", "", "connector: the proxy of its enrollment and its service, http://, socks5:// or socks5h://, without credentials")
			fs.StringVar(&proxyFile, "proxy-file", "", "connector: file with the proxy URL instead of --proxy, for one with a user name or password")
			fs.BoolVar(&v.NoUnit, "no-unit", false, "install no systemd unit and start nothing")
			fs.BoolVar(&v.Force, "force", false, "replace an existing boot file (kept beside it) or an agent's identity")
			fs.BoolVar(&yes, "yes", false, "ask nothing: take every value from the flags and run the plan")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			if role == "" && yes {
				return cli.Usagef("setup --yes needs --role: %s", offeredRoles())
			}
			v.Role, v.AllowTargets, v.DenyTargets = setup.Role(role), targets, denied
			if role != "" && setup.CheckRole(role) == nil && !setupHost.Offers(v.Role) {
				return fmt.Errorf("the role %s: %w; this build sets up: %s", role, cli.ErrNotAvailable, offeredRoles())
			}
			switch {
			case proxyFile != "" && v.Proxy != "":
				return cli.Usagef("--proxy and --proxy-file exclude each other")
			case proxyFile != "":
				p, err := setup.ReadProxyFile(proxyFile, func(w string) { _, _ = fmt.Fprintln(env.Stderr, "warning:", w) })
				if err != nil {
					return fmt.Errorf("--proxy-file: %w", err)
				}
				v.Proxy = p
			case setup.ProxyHasCredentials(v.Proxy):
				return cli.Usagef("--proxy holds credentials, which a command line shows to every user of the host: put the URL in a file for --proxy-file")
			}
			var form *setupForm
			if !yes {
				facts, err := setup.Preflight(setupHost)
				if err != nil {
					return err
				}
				form = newSetupForm(ctx, env.Stdout, facts)
				if err := form.values(&v); err != nil {
					return err
				}
			}
			if v.Role.Initialises() && tokenFile != "" {
				return cli.Usagef("--token-file is a gateway's or a connector's")
			}
			if v.Role.Initialises() && v.TLS == "" {
				v.TLS = setup.TLSSelfSigned
				if _, public := setupHost.PublicHost(v.PublicURL); public {
					v.TLS = setup.TLSACME
				}
			}
			if !v.Role.Initialises() && setup.CheckRole(string(v.Role)) == nil {
				prompt := PromptToken
				if form != nil {
					prompt = form.token
				}
				tok, err := agent.ReadToken(tokenFile, env.Getenv, prompt,
					func(w string) { _, _ = fmt.Fprintln(env.Stderr, "warning:", w) })
				if err != nil {
					return err
				}
				v.Token = tok
			}
			plan, err := setup.New(v, setupHost)
			if err != nil {
				return err
			}
			if form != nil {
				if err := form.confirm(plan); err != nil {
					return err
				}
			}
			r, err := plan.Run(ctx, func(step string) { _, _ = fmt.Fprintln(env.Stdout, "→", step) })
			if err != nil {
				if len(r.Written) > 0 {
					_, _ = fmt.Fprintf(env.Stderr, "setup stopped. It had created: %s\nRemove them, or fix the cause and run setup again with --force where it applies.\n",
						strings.Join(r.Written, ", "))
				}
				return err
			}
			return printSetup(env.Stdout, v, r)
		},
	}
}

// printSetup shows what setup made and the next steps.
func printSetup(w io.Writer, v setup.Values, r setup.Result) error {
	running := "is set up"
	if r.Unit != "" {
		running = "is set up and runs as " + r.Unit
	}
	var b strings.Builder
	if v.Role.Initialises() {
		fmt.Fprintf(&b, "\nrpmgr %s %s.\n\n  trust domain: %s\n  CA pin:       %s\n", v.Role, running, r.TrustDomain, r.Pin)
		if r.GatewayID != "" {
			fmt.Fprintf(&b, "  gateway:      %s\n", r.GatewayID)
		}
		if r.ConnectorID != "" {
			fmt.Fprintf(&b, "  connector:    %s\n", r.ConnectorID)
		}
		fmt.Fprintf(&b, "  KEK:          %s\nBack up the KEK separately: without it the database cannot be read.\n\n"+FirstUserText, r.KEK, r.FirstUserLink)
		agents, role := "gateway and connector with its token", "<gateway|connector>"
		if v.Role == setup.AllInOne {
			agents, role = "connector on another network with its enrollment token", "connector"
		}
		fmt.Fprintf(&b, "\nNext: create the first user with the link, then set up each %s:\n"+
			"  rpmgr setup --role %s --controller %s --ca-pin %s\n", agents, role, strings.TrimSuffix(v.PublicURL, "/"), r.Pin)
		if v.Role == setup.AllInOne {
			b.WriteString("Services on this host go through the all-in-one's own connector: allow them with rpmgr policy allow-target <target>.\n")
		}
	} else {
		fmt.Fprintf(&b, "\nrpmgr %s %s: enrolled as %s %s.\nNext: check it with rpmgr status", v.Role, running, r.AgentKind, r.AgentID)
		if v.Role == setup.Connector {
			b.WriteString("; allow more targets with rpmgr policy allow-target <target>")
		}
		b.WriteString(".\n")
		if r.NoUpdaterState {
			b.WriteString("Over-the-air updates stay off until an install script records a release: run its install.sh --upgrade.\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// FirstUserText ends the output of init, and of setup's init, with the first-user link.
const FirstUserText = "Create the first user, Instance Admin and Owner, with this one-time link (valid 7 days):\n  %s\n"
