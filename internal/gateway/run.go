// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// ResetKeyFile is the gateway's stateless reset key in its state directory
// (docs/10-operations.md, "Filesystem layout").
const ResetKeyFile = "quic-reset.key"

// tunnelHandshake bounds the TLS handshake of a data session over TCP.
const tunnelHandshake = 10 * time.Second

// Capabilities are what this gateway version implements (docs/03-connections.md, "Versioning and
// capabilities").
var Capabilities = []string{agentproto.CapTunnelQUIC, agentproto.CapTunnelH2}

// RunOptions configure Run.
type RunOptions struct {
	Config  config.Gateway
	Version string
	Now     func() time.Time
	Logger  *slog.Logger
	// DrainPeriod is how long a stopping gateway keeps its streams; 0 is DrainPeriod.
	DrainPeriod time.Duration
	// Listening, if set, is called once every listener is up.
	Listening func()
}

// Run runs a gateway from its boot file until ctx ends (docs/02-architecture.md): its control
// plane, the multiplexer on TCP port 443, the QUIC listener for data sessions, the tcp routes on
// their ports and the admin listener. When ctx ends it stops accepting public connections, tells
// its data sessions to drain and keeps their streams for the drain period (R22).
func Run(ctx context.Context, o RunOptions) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.DrainPeriod == 0 {
		o.DrainPeriod = DrainPeriod
	}
	cfg := o.Config
	applier, assign := NewApplier()
	var sessions *Sessions
	ctl, err := agent.NewControl(agent.ControlOptions{IdentityDir: cfg.IdentityDir, StateDir: cfg.StateDir, Version: o.Version,
		Capabilities: Capabilities, Applier: applier, Now: o.Now, Logger: o.Logger,
		OnDenyList: func() {
			if sessions != nil {
				sessions.Recheck()
			}
		}})
	if err != nil {
		return err
	}
	id := ctl.Identity()
	if id.Kind != string(pki.KindGateway) {
		return fmt.Errorf("gateway: the identity in %s is a %s's", cfg.IdentityDir, id.Kind)
	}
	sessions = NewSessions(SessionsOptions{TrustDomain: id.TrustDomain, GatewayID: id.AgentID, Assignment: assign,
		Denied: ctl.DenyList().Denied, Capabilities: Capabilities, Now: o.Now, Logger: o.Logger})
	host, _, err := net.SplitHostPort(cfg.Listen.TCP)
	if err != nil {
		return err
	}
	routes := NewTCPRoutes(TCPOptions{Host: host, Sessions: sessions, Revision: applier.Revision, Logger: o.Logger})
	defer routes.Close()
	applier.Bind(routes, sessions)

	tunnelTLS := pki.ServerConfig(ctl.Certificate(), id.Roots, pki.Expect{TrustDomain: id.TrustDomain,
		Kinds: []pki.Kind{pki.KindConnector}, Denied: ctl.DenyList().Denied}, o.Now)
	tunnelTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := ctl.Certificate()
		return &c, nil
	}
	h2TLS := tunnelTLS.Clone()
	h2TLS.NextProtos = []string{tunnel.ALPNH2}
	def, err := DefaultTLS()
	if err != nil {
		return err
	}
	budget := tunnel.NewBudget(tunnel.DefaultWindowBudget)
	run, stop := context.WithCancel(context.Background()) // outlives ctx by the drain period
	defer stop()
	router := &Router{TrustDomain: id.TrustDomain, GatewayID: id.AgentID, TunnelTLS: h2TLS, DefaultTLS: def, Logger: o.Logger,
		Tunnel: func(c *tls.Conn) {
			defer func() { _ = c.Close() }()
			hctx, cancel := context.WithTimeout(run, tunnelHandshake)
			err := c.HandshakeContext(hctx)
			cancel()
			if err != nil {
				return
			}
			windows, release, err := budget.AdmitH2(tunnel.DefaultH2Windows())
			if err != nil {
				o.Logger.Warn("refusing a data session over TCP", "error", err)
				return
			}
			defer release()
			s, err := tunnel.NewH2Gateway(c, windows)
			if err != nil {
				return
			}
			if err := sessions.Serve(run, s, c.ConnectionState().PeerCertificates[0]); err != nil {
				o.Logger.Debug("data session over TCP ended", "error", err)
			}
		}}

	resetKey, err := tunnel.LoadResetKey(filepath.Join(cfg.StateDir, ResetKeyFile))
	if err != nil {
		return err
	}
	udp := cfg.Listen.UDP
	if cfg.Listen.TunnelUDP != "" {
		udp = cfg.Listen.TunnelUDP
	}
	pc, err := net.ListenPacket("udp", udp)
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: pc, StatelessResetKey: resetKey}
	defer func() { _ = tr.Close(); _ = pc.Close() }() // a Transport does not close a conn it was given
	qln, err := tunnel.ListenQUIC(tr, QUICTLS(id.TrustDomain, id.AgentID, tunnelTLS), budget)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", cfg.Listen.TCP)
	if err != nil {
		_ = qln.Close()
		return err
	}

	reg := telemetry.NewRegistry()
	if err := ctl.Register(reg); err != nil {
		return err
	}
	errs := make(chan error, 4)
	go func() {
		if err := ctl.Run(run); err != nil && !errors.Is(err, context.Canceled) {
			errs <- fmt.Errorf("gateway: control plane: %w", err)
		}
	}()
	go func() {
		if err := telemetry.ServeAdmin(run, cfg.Listen.Admin, reg, ctl.Ready); err != nil {
			errs <- fmt.Errorf("gateway: admin listener: %w", err)
		}
	}()
	go func() { _ = router.Serve(tcp) }()
	go func() {
		for {
			s, err := qln.Accept(run)
			if err != nil {
				return
			}
			go func() {
				if err := sessions.Serve(run, s, s.PeerCertificate()); err != nil {
					o.Logger.Debug("data session over QUIC ended", "error", err)
				}
			}()
		}
	}()
	o.Logger.Info("gateway running", "gateway", id.AgentID, "tcp", tcp.Addr().String(), "udp", pc.LocalAddr().String())
	if o.Listening != nil {
		o.Listening()
	}

	var result error
	select {
	case <-ctx.Done():
	case result = <-errs:
	}
	// Drain: no new public connections or data sessions; the open streams get the drain period,
	// and the gateway stops earlier once none is left.
	_ = tcp.Close()
	_ = qln.Close()
	routes.Drain()
	sessions.Drain(o.Now().Add(o.DrainPeriod))
	deadline := time.Now().Add(o.DrainPeriod)
	for result == nil && time.Now().Before(deadline) && (routes.Conns() > 0 || sessions.Streams() > 0) {
		select {
		case <-time.After(100 * time.Millisecond):
		case result = <-errs:
		}
	}
	routes.Close()
	sessions.Close()
	stop()
	return result
}
