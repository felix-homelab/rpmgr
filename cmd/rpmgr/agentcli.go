// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// The commands of an agent host (docs/16-cli.md): each reads the connector's or the gateway's boot
// file for the identity and state directories.

const agentBootHelp = "the connector's or gateway's boot file (default $RPMGR_CONFIG, else /etc/rpmgr/connector.yaml, else /etc/rpmgr/gateway.yaml)"

// agentBoot is what the agent commands need of a boot file.
type agentBoot struct {
	path, role string
	config.Agent
	admin string // the admin listener, host:port
}

// loadAgentBoot reads the boot file given, else $RPMGR_CONFIG, else the connector's or the
// gateway's in /etc/rpmgr, whichever exists.
func loadAgentBoot(flagPath string, getenv func(string) string) (agentBoot, error) {
	path := config.Path(flagPath, "connector", getenv)
	if flagPath == "" && getenv("RPMGR_CONFIG") == "" {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			path = config.Path("", "gateway", getenv)
		}
	}
	var c config.Connector
	cerr := config.Load(path, &c)
	if cerr == nil {
		return agentBoot{path: path, role: "connector", Agent: c.Agent, admin: c.Listen.Admin}, nil
	}
	var g config.Gateway
	if err := config.Load(path, &g); err == nil {
		return agentBoot{path: path, role: "gateway", Agent: g.Agent, admin: g.Listen.Admin}, nil
	}
	return agentBoot{}, cerr
}

// agentCommand is a command of an agent host that takes --config.
func agentCommand(name, summary, args string, flags func(fs *flag.FlagSet), run func(ctx context.Context, env *cli.Env, b agentBoot, args []string) error) *cli.Command {
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
			b, err := loadAgentBoot(configPath, env.Getenv)
			if err != nil {
				return err
			}
			return run(ctx, env, b, args)
		},
	}
}

// statusCommand is `rpmgr status`.
func statusCommand() *cli.Command {
	return agentCommand("status", "show the state of the agent on this host", "", nil, func(ctx context.Context, env *cli.Env, b agentBoot, _ []string) error {
		now := time.Now()
		l, err := agent.ReadLocal(b.IdentityDir, b.StateDir, now)
		if err != nil {
			return fmt.Errorf("no identity in %s (run rpmgr enroll): %w", b.IdentityDir, err)
		}
		tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
		row := func(k, v string) { fmt.Fprintf(tw, "%s:\t%s\n", k, v) }
		row("Role", b.role+" (boot file "+b.path+")")
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
		row("Controller", strings.Join(l.Endpoints, ", "))
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
		row("Service", serviceState(ctx, b.admin))
		return tw.Flush()
	})
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
	return "running, not ready: " + strings.TrimSpace(string(body))
}

// leaveCommand is `rpmgr leave`.
func leaveCommand() *cli.Command {
	return agentCommand("leave", "revoke this agent's identity and remove it from the host", "", nil, func(ctx context.Context, env *cli.Env, b agentBoot, _ []string) error {
		l, err := agent.Leave(ctx, b.IdentityDir, b.StateDir, nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(env.Stdout, "The controller revoked %s. Its identity and stored configuration are removed from this host.\n"+
			"Stop and disable rpmgr-%s.service; %s can go too unless the host enrolls again.\n", l.SPIFFE(), b.role, b.path)
		return err
	})
}

// diagCommand is `rpmgr diag …`.
func diagCommand() *cli.Command {
	var gateway string
	return group("diag", "diagnose this host",
		agentCommand("transport", "test the data-session transports to a gateway", "",
			func(fs *flag.FlagSet) {
				fs.StringVar(&gateway, "gateway", "", "the gateway's ID (default every gateway of the connector's configuration)")
			},
			func(ctx context.Context, env *cli.Env, b agentBoot, _ []string) error {
				d, err := connector.Diagnose(ctx, b.IdentityDir, b.StateDir, gateway, time.Now)
				if err != nil {
					return err
				}
				return writeDiagnosis(env, d)
			}),
		agentCommand("clock", "compare this host's clock with the controller's", "", nil, func(ctx context.Context, env *cli.Env, b agentBoot, _ []string) error {
			c, err := agent.MeasureClock(ctx, b.IdentityDir, version.Get().Version, time.Now, nil)
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
