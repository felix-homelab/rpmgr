// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// Capabilities are what this connector version implements (docs/03-connections.md, "Versioning
// and capabilities").
var Capabilities = []string{agentproto.CapTunnelQUIC, agentproto.CapTunnelH2, agentproto.CapProxyProtoV1,
	agentproto.CapProxyProtoV2}

// RunOptions configure Run.
type RunOptions struct {
	Config  config.Connector
	Version string
	Getenv  func(string) string // os.Getenv; for the proxy variables
	Now     func() time.Time
	Logger  *slog.Logger
	// Listening, if set, is called once the connector runs.
	Listening func()
}

// Run runs a connector from its boot file until ctx ends (docs/02-architecture.md): its control
// plane, its data sessions to the gateways of its routes, the targets those routes deliver to as
// its local policy allows, the policy watcher, and the admin listener.
func Run(ctx context.Context, o RunOptions) error {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	cfg := o.Config
	dial, err := ProxyDialer(o.Getenv)
	if err != nil {
		return err
	}
	var (
		sessions *Sessions
		targets  *Targets
		ctl      *agent.Control
	)
	watcher := policy.NewWatcher(cfg.PolicyFile, func(p *policy.Policy, err error) {
		if err != nil {
			o.Logger.Error("the local policy does not load: every target is blocked", "file", cfg.PolicyFile, "error", err)
		}
		if targets != nil {
			targets.Recheck()
		}
	})
	if p := watcher.Current(); p.Invalid != nil {
		o.Logger.Error("the local policy does not load: every target is blocked", "file", cfg.PolicyFile, "error", p.Invalid)
	}
	reg := telemetry.NewRegistry()
	udpMetrics, err := tunnel.NewUDPMetrics(reg)
	if err != nil {
		return err
	}
	targets = NewTargets(TargetsOptions{Policy: watcher.Current, Logger: o.Logger, UDPMetrics: udpMetrics,
		OnHealth: func(h *tunnelv1.RouteHealth) { sessions.SetReady(h) }})
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: pc}
	defer func() { _ = tr.Close(); _ = pc.Close() }() // a Transport does not close a conn it was given
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		return err
	}
	sessions = New(Options{QUIC: tr, Dial: dial, Streams: targets.Handle, Now: o.Now, Logger: o.Logger,
		Hello: func() *tunnelv1.SessionHello {
			return &tunnelv1.SessionHello{AgentVersion: o.Version, Capabilities: Capabilities, BootId: hex.EncodeToString(boot)}
		},
		TLS: func(gatewayID string) (*tls.Config, error) { return gatewayTLS(ctl, gatewayID, o.Now) }})
	defer sessions.Close()
	ctl, err = agent.NewControl(agent.ControlOptions{IdentityDir: cfg.IdentityDir, StateDir: cfg.StateDir, Version: o.Version,
		Capabilities: Capabilities, Applier: NewApplier(targets, sessions), Now: o.Now, Logger: o.Logger})
	if err != nil {
		return err
	}
	if k := ctl.Identity().Kind; k != string(pki.KindConnector) {
		return fmt.Errorf("connector: the identity in %s is a %s's", cfg.IdentityDir, k)
	}
	if err := ctl.Register(reg); err != nil {
		return err
	}
	run, stop := context.WithCancel(ctx)
	defer stop()
	errs := make(chan error, 2)
	go watcher.Run(run)
	go func() {
		if err := telemetry.ServeAdmin(run, cfg.Listen.Admin, reg, ctl.Ready); err != nil {
			errs <- fmt.Errorf("connector: admin listener: %w", err)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- ctl.Run(run) }()
	o.Logger.Info("connector running", "connector", ctl.Identity().AgentID, "policy", cfg.PolicyFile)
	if o.Listening != nil {
		o.Listening()
	}
	select {
	case <-ctx.Done():
		stop()
		<-done
		return nil
	case err := <-errs:
		stop()
		<-done
		return err
	case err := <-done:
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		return err
	}
}

// gatewayTLS is the client configuration for a data session to gatewayID: the connector's current
// certificate, its pinned roots, ServerName <gateway-id>.gateway.<td> and exactly that gateway's
// identity, in the connector's organisation, not named by the deny-list.
func gatewayTLS(ctl *agent.Control, gatewayID string, now func() time.Time) (*tls.Config, error) {
	id := ctl.Identity()
	own, err := ownIdentity(ctl)
	if err != nil {
		return nil, err
	}
	gw := pki.Identity{TrustDomain: id.TrustDomain, Org: own.Org, Kind: pki.KindGateway, ID: gatewayID}
	if err := gw.Validate(); err != nil {
		return nil, err
	}
	cfg := pki.ClientConfig(ctl.Certificate(), id.Roots, gw.DNSName(), pki.Expect{TrustDomain: id.TrustDomain, Exact: &gw,
		Denied: ctl.DenyList().Denied}, now, nil)
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		c := ctl.Certificate()
		return &c, nil
	}
	return cfg, nil
}

func ownIdentity(ctl *agent.Control) (pki.Identity, error) {
	c := ctl.Certificate()
	if c.Leaf == nil || len(c.Leaf.URIs) != 1 {
		return pki.Identity{}, errors.New("connector: the certificate has no rpmgr identity")
	}
	return pki.ParseSPIFFE(c.Leaf.URIs[0], ctl.Identity().TrustDomain)
}
