// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// The commands of an agent host (docs/16-cli.md): each reads the connector's or the gateway's boot
// file for the identity and state directories, or, on an all-in-one host, the all-in-one's boot
// file for those of its built-in gateway and connector.

const agentBootHelp = "the connector's, gateway's or all-in-one's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/connector.yaml, " +
	"else /etc/rpmgr/gateway.yaml, else /etc/rpmgr/all-in-one.yaml)"

// agentBoot is what the agent commands need of a boot file.
type agentBoot struct {
	path, role string
	config.Agent
	admin   string // the admin listener, host:port
	builtIn bool   // an all-in-one's built-in gateway or connector, which runs in its process
}

// loadAgentBoots reads the agents of the host: the one of loadAgentBoot, or, for an all-in-one's
// boot file, its built-in gateway and connector, in that order. Without a boot file given, an
// all-in-one host is one with neither a connector's nor a gateway's boot file in /etc/rpmgr but
// the all-in-one's.
func loadAgentBoots(flagPath string, getenv func(string) string) ([]agentBoot, error) {
	path := flagPath
	if path == "" {
		path = getenv("RPMGR_CONFIG")
	}
	if path == "" {
		if path = filepath.Join(BootDir, "all-in-one.yaml"); !fileExists(path) ||
			fileExists(filepath.Join(BootDir, "connector.yaml")) || fileExists(filepath.Join(BootDir, "gateway.yaml")) {
			path = ""
		}
	}
	b, err := loadAgentBoot(flagPath, getenv)
	if err == nil || path == "" {
		return []agentBoot{b}, err
	}
	var a config.AllInOne
	if aerr := config.Load(path, &a); aerr != nil {
		return nil, err // the agent's error: an all-in-one's boot file is the exception
	}
	g, c := a.Gateway(), a.Connector()
	return []agentBoot{
		{path: path, role: "gateway", Agent: g.Agent, admin: a.Listen.Admin, builtIn: true},
		{path: path, role: "connector", Agent: c.Agent, admin: a.Listen.Admin, builtIn: true},
	}, nil
}

// loadAgentBoot reads the boot file given, else $RPMGR_CONFIG, else the connector's or the
// gateway's in /etc/rpmgr, whichever exists. A file that is valid for both roles, such as the
// one /install.sh writes for a gateway, has the role its identity records, else the connector's
// unless it is the gateway's in /etc/rpmgr.
func loadAgentBoot(flagPath string, getenv func(string) string) (agentBoot, error) {
	path, gatewayPath := config.Path(flagPath, "connector", getenv), false
	if flagPath == "" && getenv("RPMGR_CONFIG") == "" {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			path, gatewayPath = config.Path("", "gateway", getenv), true
		}
	}
	var c config.Connector
	var g config.Gateway
	cerr, gerr := config.Load(path, &c), config.Load(path, &g)
	connector := agentBoot{path: path, role: "connector", Agent: c.Agent, admin: c.Listen.Admin}
	gateway := agentBoot{path: path, role: "gateway", Agent: g.Agent, admin: g.Listen.Admin}
	switch {
	case cerr != nil && gerr != nil:
		return agentBoot{}, cerr
	case gerr != nil:
		return connector, nil
	case cerr != nil:
		return gateway, nil
	}
	if id, err := agent.ReadIdentity(c.IdentityDir); err == nil && id.Kind != "" {
		if id.Kind == string(pki.KindGateway) {
			return gateway, nil
		}
		return connector, nil
	}
	if gatewayPath {
		return gateway, nil
	}
	return connector, nil
}

// agentCommand is a command of an agent host that takes --config; run gets the host's agents
// (loadAgentBoots).
func agentCommand(name, summary, args string, flags func(fs *flag.FlagSet), run func(ctx context.Context, env *cli.Env, bs []agentBoot, args []string) error) *cli.Command {
	var configPath string
	return &cli.Command{
		Name: name, Summary: summary, Args: args,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&configPath, "config", "", agentBootHelp)
			if flags != nil {
				flags(fs)
			}
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			bs, err := loadAgentBoots(configPath, env.Getenv)
			if err != nil {
				return err
			}
			return run(ctx, env, bs, args)
		},
	}
}

// Status is `rpmgr status`: the agent of the host, or both built-in agents of an all-in-one,
// one after the other.
func Status() *cli.Command {
	return agentCommand("status", "show the state of the agents on this host", "", nil, func(ctx context.Context, env *cli.Env, bs []agentBoot, _ []string) error {
		var errs []error
		for i, b := range bs {
			if i > 0 {
				fmt.Fprintln(env.Stdout)
			}
			if err := writeStatus(ctx, env, b); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
}

// writeStatus writes the state of the agent of b.
func writeStatus(ctx context.Context, env *cli.Env, b agentBoot) error {
	now := time.Now()
	l, err := agent.ReadLocal(b.IdentityDir, b.StateDir, now)
	if err != nil {
		if b.builtIn {
			return fmt.Errorf("the all-in-one's %s has no identity in %s; rpmgr all-in-one enrolls it at its next start: %w", b.role, b.IdentityDir, err)
		}
		return fmt.Errorf("no identity in %s (run rpmgr enroll): %w", b.IdentityDir, err)
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s:\t%s\n", k, v) }
	if b.builtIn {
		row("Role", b.role+", built into the all-in-one (boot file "+b.path+")")
	} else {
		row("Role", b.role+" (boot file "+b.path+")")
	}
	row("Agent", l.AgentID+"  "+l.SPIFFE())
	row("Trust domain", l.TrustDomain)
	row("Enrolled", l.EnrolledAt.UTC().Format(time.RFC3339))
	if leaf := l.Certificate.Leaf; leaf != nil {
		left := leaf.NotAfter.Sub(now).Round(time.Minute)
		state := "valid for " + left.String()
		if left <= 0 {
			state = "expired; the agent re-authenticates within the grace period, else re-enroll"
		}
		row("Certificate", fmt.Sprintf("expires %s, %s", leaf.NotAfter.UTC().Format(time.RFC3339), state))
	}
	row("Controller", strings.Join(l.ControllerEndpoints(), ", "))
	switch {
	case l.SnapshotErr != nil:
		row("Configuration", "the stored copy does not verify: "+l.SnapshotErr.Error())
	case l.Snapshot == nil:
		row("Configuration", "none received yet")
	default:
		rev := l.Snapshot.GetRevision()
		row("Configuration", fmt.Sprintf("revision %d of epoch %s, %d resources", rev.GetSeq(), rev.GetDbEpoch(), len(l.Snapshot.GetResources())))
	}
	deny := fmt.Sprintf("%d entries", l.Denied)
	if l.DenyErr != nil {
		deny += "; " + l.DenyErr.Error()
	}
	row("Deny-list", deny)
	if b.builtIn {
		row("Service", "rpmgr-all-in-one.service, "+serviceState(ctx, b.admin))
	} else {
		row("Service", serviceState(ctx, b.admin))
	}
	return tw.Flush()
}

// serviceState asks the running agent's admin listener whether it is ready.
func serviceState(ctx context.Context, admin string) string {
	if admin == "" {
		return "unknown: the admin listener is off"
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+admin+"/readyz", nil)
	if err != nil {
		return "unknown: " + err.Error()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "not running (nothing answers on " + admin + ")"
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode == http.StatusOK {
		return "running and ready"
	}
	// The admin listener answers "not ready: <reason>"; the reason is said once.
	reason := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "not ready:"))
	if reason == "" {
		return "running, not ready"
	}
	return "running, not ready: " + reason
}

// errBuiltInLeave refuses `rpmgr leave` on an all-in-one host, whose agents are built in.
var errBuiltInLeave = errors.New("this host runs rpmgr all-in-one, whose gateway and connector are built in and cannot leave: " +
	"switch one off on its page in the web UI, or stop and disable rpmgr-all-in-one.service")

// Leave is `rpmgr leave`.
func Leave() *cli.Command {
	return agentCommand("leave", "revoke this agent's identity and remove it from the host", "", nil, func(ctx context.Context, env *cli.Env, bs []agentBoot, _ []string) error {
		b := bs[0]
		if b.builtIn {
			return errBuiltInLeave
		}
		l, err := agent.Leave(ctx, b.IdentityDir, b.StateDir, nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(env.Stdout, "The controller revoked %s. Its identity and stored configuration are removed from this host.\n"+
			"Stop and disable rpmgr-%s.service; %s can go too unless the host enrolls again.\n", l.SPIFFE(), b.role, b.path)
		return err
	})
}

// Diag is `rpmgr diag …`.
func Diag() *cli.Command {
	var gateway string
	return group("diag", "diagnose this host",
		agentCommand("transport", "test the data-session transports to a gateway", "",
			func(fs *flag.FlagSet) {
				fs.StringVar(&gateway, "gateway", "", "the gateway's ID (default every gateway of the connector's configuration)")
			},
			func(ctx context.Context, env *cli.Env, bs []agentBoot, _ []string) error {
				b := diagBoot(bs)
				d, err := connector.Diagnose(ctx, b.IdentityDir, b.StateDir, gateway, time.Now)
				if err != nil {
					return err
				}
				if b.builtIn {
					fmt.Fprintln(env.Stdout, "The all-in-one's built-in connector reaches the built-in gateway in memory; "+
						"these sessions test the network path to its gateways' tunnel endpoints.")
				}
				return writeDiagnosis(env, d)
			}),
		agentCommand("clock", "compare this host's clock with the controller's", "", nil, func(ctx context.Context, env *cli.Env, bs []agentBoot, _ []string) error {
			b := diagBoot(bs)
			c, err := agent.MeasureClock(ctx, b.IdentityDir, b.StateDir, version.Get().Version, time.Now, nil)
			if err != nil {
				return fmt.Errorf("no controller answered; a TLS error about an expired or not yet valid certificate means this host's clock is far off: %w", err)
			}
			verdict := "within the " + agent.MaxClockSkew.String() + " agents accept"
			if c.Offset > agent.MaxClockSkew || -c.Offset > agent.MaxClockSkew {
				verdict = "more than the " + agent.MaxClockSkew.String() + " agents accept: fix NTP on this host or the controller's"
			}
			_, err = fmt.Fprintf(env.Stdout, "Controller %s: its clock is %s ahead of this host's (round trip %s), %s.\n"+
				"A running agent's control session reconnects once after the measurement.\n",
				c.Endpoint, c.Offset.Round(time.Millisecond), c.RTT.Round(time.Millisecond), verdict)
			return err
		}))
}

// diagBoot is the agent rpmgr diag runs as: the host's agent, or an all-in-one's built-in connector.
func diagBoot(bs []agentBoot) agentBoot {
	for _, b := range bs {
		if b.builtIn && b.role == "connector" {
			return b
		}
	}
	return bs[0]
}

func writeDiagnosis(env *cli.Env, d connector.Diagnosis) error {
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GATEWAY\tENDPOINT\tTRANSPORT\tRESULT\tHANDSHAKE\tRTT")
	for _, p := range d.Probes {
		result, rtt := "ok", "-"
		if p.Err != nil {
			result = "failed: " + p.Err.Error()
		}
		if p.RTT > 0 {
			rtt = p.RTT.Round(time.Millisecond).String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Gateway, p.Endpoint, p.Transport, result, p.Handshake.Round(time.Millisecond), rtt)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	t := d.Tuning
	gso := "off"
	if t.GSO {
		gso = "on"
	}
	fmt.Fprintf(env.Stdout, "\nUDP socket: receive buffer %d bytes, send buffer %d bytes, GSO %s.\n", t.ReceiveBuffer, t.SendBuffer, gso)
	if t.BufferLow {
		fmt.Fprintln(env.Stdout, "The UDP buffers are below what QUIC asks for: apply the installer's /etc/sysctl.d/60-rpmgr.conf.")
	}
	if d.MTU > 0 {
		fmt.Fprintf(env.Stdout, "MTU towards the gateway: %d on %s.\n", d.MTU, d.Interface)
	}
	return nil
}
