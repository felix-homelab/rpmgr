// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// ResetKeyFile is the gateway's stateless reset key in its state directory, and ResourcesDir the
// directory of the items it fetched, route certificates with their keys (docs/10-operations.md,
// "Filesystem layout").
const (
	ResetKeyFile = "quic-reset.key"
	ResourcesDir = "resources"
)

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
	// Controller, if set, takes the connections for the controller's names, still encrypted:
	// all-in-one's in-process controller. ControllerNames are its UI hostnames.
	Controller      func(net.Conn)
	ControllerNames []string
	// Dial connects the control plane to a controller endpoint; nil dials TCP.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// ForwardDial connects to the controller for what the gateway forwards to it: connections to
	// the private controller of controller.passthrough, and the control sessions connectors carry
	// through their data sessions; nil dials TCP.
	ForwardDial func(ctx context.Context, addr string) (net.Conn, error)
	// Port80Fallback takes port-80 requests for names no route serves: all-in-one's controller
	// redirect; nil answers 404.
	Port80Fallback http.Handler
	// Registry, if set, receives the gateway's metrics and Run serves no admin listener;
	// Readiness then gets the gateway's readiness check.
	Registry  *prometheus.Registry
	Readiness func(check func(context.Context) error)
}

// Run runs a gateway from its boot file until ctx ends (docs/02-architecture.md): its control
// plane, the multiplexer on TCP port 443, the QUIC listener for data sessions, the tcp and udp
// routes on their ports, the forwarding to a private controller and the admin listener. When ctx ends it stops accepting public connections, tells
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
	if cfg.Controller.Passthrough.Address != "" && o.Controller != nil {
		return errors.New("gateway: controller.passthrough and an in-process controller exclude each other")
	}
	applier, assign := NewApplier()
	var sessions *Sessions
	challenges := NewChallenges()
	ctl, err := agent.NewControl(agent.ControlOptions{IdentityDir: cfg.IdentityDir, StateDir: cfg.StateDir, Version: o.Version,
		Capabilities: Capabilities, Applier: applier, Now: o.Now, Logger: o.Logger, Dial: o.Dial, OnAcmeChallenge: challenges.Apply,
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
	// The controller, for the connections to its names and for the control sessions connectors
	// carry through their data sessions: the in-process one (all-in-one), the private one of
	// controller.passthrough, or for the carried sessions the gateway's own controller endpoint.
	toController, controllerNames := o.Controller, o.ControllerNames
	if pt := cfg.Controller.Passthrough; pt.Address != "" {
		forward := NewForward(pt.Address, o.ForwardDial, o.Logger)
		defer forward.Close()
		toController, controllerNames = forward.Serve, pt.Hostnames
	}
	carried := toController
	if carried == nil {
		own := NewForwardTo(ctl.ControllerAddr, o.ForwardDial, o.Logger)
		defer own.Close()
		carried = own.Serve
	}
	sessions = NewSessions(SessionsOptions{TrustDomain: id.TrustDomain, GatewayID: id.AgentID, Assignment: assign,
		Denied: ctl.DenyList().Denied, Capabilities: Capabilities, Now: o.Now, Logger: o.Logger,
		OnOpenRequest: NewControlStreams(carried).Decide})
	host, _, err := net.SplitHostPort(cfg.Listen.TCP)
	if err != nil {
		return err
	}
	routes := NewTCPRoutes(TCPOptions{Host: host, Sessions: sessions, Revision: applier.Revision, Logger: o.Logger})
	defer routes.Close()
	pass := NewPassthrough(sessions, applier.Revision, o.Logger)
	defer pass.Close()
	udpHost, _, err := net.SplitHostPort(cfg.Listen.UDP)
	if err != nil {
		return err
	}
	reg := o.Registry
	if reg == nil {
		reg = telemetry.NewRegistry()
	}
	udpMetrics, err := tunnel.NewUDPMetrics(reg)
	if err != nil {
		return err
	}
	udpRoutes := NewUDPRoutes(UDPOptions{Host: udpHost, Sessions: sessions, Revision: applier.Revision, Metrics: udpMetrics,
		Logger: o.Logger})
	defer udpRoutes.Close()
	certificates := NewCertificates(CertificatesOptions{Dir: filepath.Join(cfg.StateDir, ResourcesDir), Fetch: ctl.Fetch,
		Now: o.Now, Logger: o.Logger})
	def, err := DefaultTLS()
	if err != nil {
		return err
	}
	httpRoutes := NewHTTPRoutes(HTTPOptions{Sessions: sessions, Certificates: certificates, Default: &def.Certificates[0],
		Revision: applier.Revision, Fallback80: o.Port80Fallback, Challenges: challenges.HTTP01, Logger: o.Logger})
	defer httpRoutes.Close()
	applier.Bind(Served{TCP: routes, UDP: udpRoutes, Passthrough: pass, HTTP: httpRoutes, Certificates: certificates, Sessions: sessions})

	tunnelTLS := pki.ServerConfig(ctl.Certificate(), id.Roots, pki.Expect{TrustDomain: id.TrustDomain,
		Kinds: []pki.Kind{pki.KindConnector}, Denied: ctl.DenyList().Denied}, o.Now)
	tunnelTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := ctl.Certificate()
		return &c, nil
	}
	h2TLS := tunnelTLS.Clone()
	h2TLS.NextProtos = []string{tunnel.ALPNH2}
	budget := tunnel.NewBudget(tunnel.DefaultWindowBudget)
	run, stop := context.WithCancel(context.Background()) // outlives ctx by the drain period
	defer stop()
	router := &Router{ACME: challenges.ALPN, TrustDomain: id.TrustDomain, GatewayID: id.AgentID, TunnelTLS: h2TLS, DefaultTLS: def, Logger: o.Logger,
		Controller: toController, ControllerNames: controllerNames, Routes: NewRouteTable(pass, httpRoutes),
		HTTP: httpRoutes.Serve, HTTPTLS: httpRoutes.TLSConfig(),
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
	var plain net.Listener // port 80
	if cfg.Listen.HTTP != nil && *cfg.Listen.HTTP != "" {
		if plain, err = net.Listen("tcp", *cfg.Listen.HTTP); err != nil {
			_ = qln.Close()
			_ = tcp.Close()
			return err
		}
	}

	if err := ctl.Register(reg); err != nil {
		return err
	}
	errs := make(chan error, 4)
	go func() {
		if err := ctl.Run(run); err != nil && !errors.Is(err, context.Canceled) {
			errs <- fmt.Errorf("gateway: control plane: %w", err)
		}
	}()
	if o.Registry == nil {
		go func() {
			if err := telemetry.ServeAdmin(run, cfg.Listen.Admin, reg, ctl.Ready); err != nil {
				errs <- fmt.Errorf("gateway: admin listener: %w", err)
			}
		}()
	} else if o.Readiness != nil {
		o.Readiness(ctl.Ready)
	}
	go func() { _ = router.Serve(tcp) }()
	if plain != nil {
		go func() {
			if err := httpRoutes.Serve80(plain); err != nil && !errors.Is(err, net.ErrClosed) {
				o.Logger.Warn("port 80 stopped", "error", err)
			}
		}()
	}
	go certificates.Run(run)
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
	if plain != nil {
		_ = plain.Close()
	}
	_ = qln.Close()
	routes.Drain()
	httpRoutes.Drain()
	sessions.Drain(o.Now().Add(o.DrainPeriod))
	deadline := time.Now().Add(o.DrainPeriod)
	for result == nil && time.Now().Before(deadline) && (routes.Conns() > 0 || pass.Conns() > 0 || httpRoutes.Active() > 0 ||
		sessions.Streams() > 0) {
		select {
		case <-time.After(100 * time.Millisecond):
		case result = <-errs:
		}
	}
	routes.Close()
	httpRoutes.Close()
	udpRoutes.Close()
	sessions.Close()
	stop()
	return result
}
