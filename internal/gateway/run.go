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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/handoff"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
	"github.com/felix-homelab/rpmgr/internal/version"
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
var Capabilities = []string{agentproto.CapTunnelQUIC, agentproto.CapTunnelH2, agentproto.CapHTTPHeaderMatch, agentproto.CapRouteLimits,
	agentproto.CapHTTPRequireHeader, agentproto.CapPagesCustom, agentproto.CapTCPHTTPConnect, agentproto.CapTunnelWSS}

// RunOptions configure Run.
type RunOptions struct {
	Config  config.Gateway
	Version string
	Now     func() time.Time
	Logger  *slog.Logger
	// LiveLog, if set, is Logger's live log: the agent then runs live-log operations from it
	// (docs/03-connections.md, "Control session"). The built-in agents of an all-in-one have
	// none, as their log is the controller's.
	LiveLog *telemetry.LiveLog
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
	// Port80Fallback takes port-80 requests for ControllerNames when no route serves them:
	// all-in-one's controller, which answers ACME HTTP-01 for its own name and redirects the rest.
	// Other names no route serves get the 404 page.
	Port80Fallback http.Handler
	// Registry, if set, receives the gateway's metrics and Run serves no admin listener;
	// Readiness then gets the gateway's readiness check.
	Registry  telemetry.Registry
	Readiness func(check func(context.Context) error)
	// Tunnels, if set, accepts in-memory connections that can only be data sessions to this
	// gateway: all-in-one's connector's (Router.HandleTunnel). Run closes it when it drains or
	// fails, so that a dial to it does not wait for a gateway that is gone.
	Tunnels net.Listener
	// RoutePorts, if set, gets a function that reports whether a tcp or udp route of the gateway
	// listens on a port, so that all-in-one's connector never dials one (ADR-0019).
	RoutePorts func(bound func(port uint16) bool)
	// Update, if set, stages the releases the controller offers for the root updater, in update/
	// of the state directory, as the host's local policy file allows (OTA): a gateway on Linux
	// that runs on its own, never all-in-one's.
	Update bool
	// Handoff, if set, is the gateway's link to socket hand-offs: Run adopts the TCP listeners
	// the old process handed over, hands its own over on request, and reports ready through it
	// (docs/03-connections.md, "Restarts with socket hand-off"). Only a gateway on its own has one.
	Handoff *handoff.Link
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
	// Every log line and metric names the process generation: 1 after a plain start, one more
	// after each hand-off, so that the old and the new process of a hand-off stay apart.
	generation := strconv.FormatUint(o.Handoff.Generation(), 10)
	o.Logger = o.Logger.With("generation", generation)
	if o.Tunnels != nil {
		defer func() { _ = o.Tunnels.Close() }()
	}
	var oldAlive atomic.Bool // the old process of the hand-off that started this one runs
	cfg := o.Config
	held := &listeners{link: o.Handoff, log: o.Logger}
	adopted := o.Handoff != nil && o.Handoff.Inherited != nil
	if adopted {
		held.take = o.Handoff.Inherited.Listener
		oldAlive.Store(true)
	}
	if cfg.Controller.Passthrough.Address != "" && o.Controller != nil {
		return errors.New("gateway: controller.passthrough and an in-process controller exclude each other")
	}
	applier, assign := NewApplier()
	var sessions *Sessions
	var toOld atomic.Pointer[handoff.Pipe] // set in a process a hand-off started, once it is ready
	var toOldCuts cuts                     // the routes this process changed, for the old one
	applier.OnCut = toOldCuts.send
	challenges, report := NewChallenges(), newReporter()
	var update *agent.UpdateOptions
	if o.Update {
		// A gateway reads the host's policy file for auto_update and update_channel only, as the
		// root updater does; a missing file is the defaults.
		update = &agent.UpdateOptions{Dir: filepath.Join(cfg.StateDir, "update"), Variant: version.Variant,
			Policy: func() *policy.Policy { p, _ := policy.Load(policy.DefaultPath); return p }}
	}
	ctl, err := agent.NewControl(agent.ControlOptions{IdentityDir: cfg.IdentityDir, StateDir: cfg.StateDir, Version: o.Version,
		Capabilities: Capabilities, Applier: applier, Now: o.Now, Logger: o.Logger, LiveLog: o.LiveLog, Dial: o.Dial, OnAcmeChallenge: challenges.Apply,
		Update: update,
		OnDenyList: func() {
			if sessions != nil {
				sessions.Recheck()
			}
			if p := toOld.Load(); p != nil {
				_ = p.Send(msgRevoked, "") // the old process of a hand-off cuts what the list revokes
			}
		},
		SessionStatus: func() *agentv1.Status {
			if sessions == nil {
				return &agentv1.Status{}
			}
			return &agentv1.Status{DataSessions: sessions.Report(), Counters: sessions.metrics().Counters(),
				Readiness: applier.Readiness(), ReadinessComplete: true}
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
	reg := o.Registry
	if reg == nil {
		reg = telemetry.NewRegistry()
	}
	// Only the gateway's own series: those other roles register too share one registry in an
	// all-in-one and need one label set.
	metrics, err := NewMetrics(withGeneration(reg, generation))
	if err != nil {
		return err
	}
	sessions = NewSessions(SessionsOptions{TrustDomain: id.TrustDomain, GatewayID: id.AgentID, Assignment: assign,
		Denied: ctl.DenyList().Denied, Capabilities: Capabilities, Now: o.Now, Logger: o.Logger, Metrics: metrics,
		AwaitSession:  oldAlive.Load,
		OnOpenRequest: NewControlStreams(carried).Decide, OnChange: report.change})
	host, _, err := net.SplitHostPort(cfg.Listen.TCP)
	if err != nil {
		return err
	}
	pass := NewPassthrough(sessions, applier.Revision, o.Logger)
	defer pass.Close()
	udpHost, _, err := net.SplitHostPort(cfg.Listen.UDP)
	if err != nil {
		return err
	}
	udpMetrics, err := tunnel.NewUDPMetrics(reg)
	if err != nil {
		return err
	}
	udpRoutes := NewUDPRoutes(UDPOptions{Host: udpHost, Sessions: sessions, Revision: applier.Revision, Metrics: udpMetrics,
		OnChange: report.change, Logger: o.Logger})
	defer udpRoutes.Close()
	certificates := NewCertificates(CertificatesOptions{Dir: filepath.Join(cfg.StateDir, ResourcesDir), Fetch: ctl.Fetch,
		OnChange: report.change, Now: o.Now, Logger: o.Logger})
	pages := NewPages(PagesOptions{Fetch: ctl.Fetch, OnChange: report.change, OnLogDropped: metrics.PageLogDropped, Now: o.Now,
		Logger: o.Logger})
	def, err := DefaultTLS()
	if err != nil {
		return err
	}
	routes := NewTCPRoutes(TCPOptions{Host: host, Sessions: sessions, Revision: applier.Revision, OnChange: report.change,
		Listen:       func(port uint16, addr string) (net.Listener, error) { return held.listen(routeName(port), addr) },
		Certificates: certificates, Default: &def.Certificates[0], Logger: o.Logger})
	defer routes.Close()
	httpRoutes := NewHTTPRoutes(HTTPOptions{Sessions: sessions, Certificates: certificates, Default: &def.Certificates[0],
		Revision: applier.Revision, Fallback80: o.Port80Fallback, FallbackNames: o.ControllerNames, Challenges: challenges.HTTP01,
		Pages: pages, Logger: o.Logger})
	defer httpRoutes.Close()
	if o.RoutePorts != nil {
		o.RoutePorts(func(port uint16) bool { return routes.Bound(port) || udpRoutes.Bound(port) })
	}
	wss := &WSSHostname{}
	applier.Bind(Served{TCP: routes, UDP: udpRoutes, Passthrough: pass, HTTP: httpRoutes, Certificates: certificates, Pages: pages, WSS: wss,
		Sessions: sessions, DrainPeriod: o.DrainPeriod})

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
	// The WSS hostname's public certificate is one of the route certificates; the upgrade speaks
	// HTTP/1.1 only.
	wssTLS := httpRoutes.TLSConfig().Clone()
	wssTLS.NextProtos = []string{"http/1.1"}
	var serveTunnel func(*tls.Conn)
	router := &Router{ACME: challenges.ALPN, TrustDomain: id.TrustDomain, GatewayID: id.AgentID, TunnelTLS: h2TLS, DefaultTLS: def, Logger: o.Logger,
		Controller: toController, ControllerNames: controllerNames, Routes: NewRouteTable(pass, httpRoutes),
		HTTP: httpRoutes.Serve, HTTPTLS: httpRoutes.TLSConfig(), Unrouted: httpRoutes.ServeUnrouted, UnroutedTLS: httpRoutes.UnroutedTLSConfig(),
		WSSHostname: wss.Get, WSSTLS: wssTLS, WSS: func(c *tls.Conn) { ServeWSS(c, h2TLS, serveTunnel) },
		Tunnel: func(c *tls.Conn) {
			defer func() { _ = c.Close() }()
			over := "TCP" // or memory: all-in-one's connector (ServeTunnels), or WSS
			switch c.RemoteAddr().Network() {
			case "memory":
				over = "memory"
			case "wss":
				over = "WSS"
			}
			hctx, cancel := context.WithTimeout(run, tunnelHandshake)
			err := c.HandshakeContext(hctx)
			cancel()
			if err != nil {
				return
			}
			windows, release, err := budget.AdmitH2(tunnel.DefaultH2Windows())
			if err != nil {
				o.Logger.Warn("refusing a data session over "+over, "error", err)
				return
			}
			defer release()
			s, err := tunnel.NewH2Gateway(c, windows)
			if err != nil {
				return
			}
			if err := sessions.Serve(run, s, c.ConnectionState().PeerCertificates[0]); err != nil {
				o.Logger.Debug("data session over "+over+" ended", "error", err)
			}
		}}
	serveTunnel = router.Tunnel

	resetKey, err := tunnel.LoadResetKey(filepath.Join(cfg.StateDir, ResetKeyFile))
	if err != nil {
		return err
	}
	udp := cfg.Listen.UDP
	if cfg.Listen.TunnelUDP != "" {
		udp = cfg.Listen.TunnelUDP
	}
	// The QUIC listener's UDP socket is not handed over: only the old process of a hand-off reads
	// it until it exits, so a process a hand-off started opens it then (docs/03-connections.md,
	// "UDP and QUIC").
	qs := &quicSide{addr: udp, key: resetKey, tls: QUICTLS(id.TrustDomain, id.AgentID, tunnelTLS), budget: budget, reg: reg,
		serve: func(s *tunnel.QUICSession) {
			if err := sessions.Serve(run, s, s.PeerCertificate()); err != nil {
				o.Logger.Debug("data session over QUIC ended", "error", err)
			}
		}}
	defer qs.close()
	if err := qs.register(); err != nil {
		return err
	}
	udpAddr := "none (until the old process exits)"
	if !adopted {
		if err := qs.open(run); err != nil {
			return err
		}
		udpAddr = qs.localAddr()
	}
	closeQUIC := qs.stopAccepting
	// freed runs in a process a hand-off started once the old one exited and its UDP sockets are
	// free: the QUIC listener and the pending udp routes bind now.
	freed := func() {
		go func() {
			udpRoutes.Rebind()
			err := qs.openUntilBound(run, func(err error) {
				o.Logger.Error("cannot listen for data sessions over QUIC after the hand-off; connectors use TCP, and it tries again", "udp", udp, "error", err)
			})
			if err == nil {
				o.Logger.Info("listening for data sessions over QUIC", "udp", qs.localAddr())
			}
		}()
	}
	tcp, err := held.listen("tcp", cfg.Listen.TCP)
	if err != nil {
		closeQUIC()
		return err
	}
	var plain net.Listener // port 80
	if cfg.Listen.HTTP != nil && *cfg.Listen.HTTP != "" {
		if plain, err = held.listen("http", *cfg.Listen.HTTP); err != nil {
			closeQUIC()
			_ = tcp.Close()
			return err
		}
	}

	if err := ctl.Register(reg); err != nil {
		return err
	}
	errs := make(chan error, 4)
	switched := make(chan *handoff.Child, 1)
	// Run returns only once these have ended: the control plane writes the last-known-good snapshot
	// and the deny-list into the state directory, and the certificates their files.
	var background sync.WaitGroup
	background.Go(func() {
		if err := ctl.Run(run); err != nil && !errors.Is(err, context.Canceled) {
			errs <- fmt.Errorf("gateway: control plane: %w", err)
		}
	})
	var admin sync.WaitGroup
	if o.Registry == nil {
		admin.Go(func() {
			if err := telemetry.ServeAdminOn(run, cfg.Listen.Admin, func(addr string) (net.Listener, error) { return held.listen("admin", addr) }, reg, ctl.Ready); err != nil {
				errs <- fmt.Errorf("gateway: admin listener: %w", err)
			}
		})
		// Run returns only once the admin listener is closed, so that its address is free again.
		defer func() { stop(); admin.Wait() }()
	} else if o.Readiness != nil {
		o.Readiness(ctl.Ready)
	}
	go func() { _ = router.Serve(tcp) }()
	if o.Tunnels != nil {
		go func() {
			if err := router.ServeTunnels(o.Tunnels); err != nil {
				o.Logger.Warn("in-memory data sessions stopped", "error", err)
			}
		}()
	}
	if plain != nil {
		go func() {
			if err := httpRoutes.Serve80(plain); err != nil && !errors.Is(err, net.ErrClosed) {
				o.Logger.Warn("port 80 stopped", "error", err)
			}
		}()
	}
	background.Go(func() { certificates.Run(run) })
	background.Go(func() { pages.Run(run) })
	background.Go(func() {
		report.run(run, ReportEvery, ctl.Send, func() *agentv1.Status {
			return &agentv1.Status{DataSessions: sessions.Report(), Counters: metrics.Counters(), Readiness: applier.Readiness(),
				ReadinessComplete: true}
		})
	})
	o.Logger.Info("gateway running", "gateway", id.AgentID, "tcp", tcp.Addr().String(), "udp", udpAddr)
	if o.Listening != nil {
		o.Listening()
	}
	if o.Handoff != nil {
		var rest func() []handoff.Entry
		if adopted {
			rest = o.Handoff.Inherited.Rest
		}
		o.Handoff.Serve(func(c context.Context) (*handoff.Child, error) {
			end := ctl.BeginHandoff() // the new process's control session supersedes this one's
			child, err := held.start(c)
			end(err == nil)
			if err != nil {
				return nil, err
			}
			if adopted {
				_ = o.Handoff.Inherited.Pipe().Send(msgSuccessor, "") // ends the predecessor's drain
			}
			o.Handoff.Serve(nil) // this process only drains now
			switched <- child
			return child, nil
		})
		background.Go(func() {
			if err := held.ready(run, o.Handoff, rest, ctl.Ready); err != nil {
				errs <- err
				return
			}
			if adopted {
				pipe := o.Handoff.Inherited.Pipe()
				toOld.Store(pipe)
				toOldCuts.attach(pipe.Send)
				// The old process runs until it closes its end of the pipe; until then a new
				// connection of a route without a session waits for one.
				go func() {
					for {
						if _, _, err := pipe.Recv(); err != nil {
							oldAlive.Store(false)
							freed()
							return
						}
					}
				}()
				_ = pipe.Send(msgRevoked, "") // a revocation between this process's start and now
				reportSessions(run, pipe.Send, sessions, o.Logger)
			}
		})
	}

	var result error
	var child *handoff.Child
	select {
	case <-ctx.Done():
	case result = <-errs:
	case child = <-switched:
	}
	period := o.DrainPeriod
	deadline := time.Now().Add(period) // one deadline for the wait for the connectors and the drain
	var successor <-chan struct{}      // closed when a hand-off of the new process ends the drain early
	if child != nil {
		// Switched: connectors move to the new process and this one keeps accepting until they
		// have, then drains its open connections for the hand-off drain.
		period = cfg.Handoff.DrainPeriod()
		deadline = time.Now().Add(period)
		closeQUIC() // no new QUIC session; the open ones stay until the drain ends
		reload := func() {
			if err := ctl.DenyList().Load(); err != nil {
				o.Logger.Warn("reading the deny-list after a hand-off", "error", err)
			}
			sessions.Recheck()
		}
		cut := func(id string) {
			o.Logger.Info("cutting the connections of a route the new process changed", "route", id)
			routes.CutRoute(id)
			udpRoutes.CutRoute(id)
			pass.CutRoute(id)
			httpRoutes.CutRoute(id)
		}
		successor = followNew(ctx, child.Pipe.Recv, child.Exited(), sessions, deadline, reload, cut, o.Logger)
		o.Logger.Info("stopping accepting: the new process took over", "generation", held.link.Generation())
	}
	// Drain: no new public connections or data sessions; the open streams get the drain period,
	// and the gateway stops earlier once none is left.
	_ = tcp.Close()
	if plain != nil {
		_ = plain.Close()
	}
	if o.Tunnels != nil {
		_ = o.Tunnels.Close() // no new data sessions in memory either; closing twice is harmless
	}
	closeQUIC()
	routes.Drain()
	httpRoutes.Drain()
	sessions.Drain(o.Now().Add(time.Until(deadline)))
	for result == nil && !closed(successor) && time.Now().Before(deadline) && (routes.Conns() > 0 || pass.Conns() > 0 || httpRoutes.Active() > 0 ||
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
	background.Wait()
	return result
}

// closed reports whether c is closed; a nil channel is not.
func closed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// withGeneration adds the process generation as a constant label to every metric registered
// through reg, which is the gateway's own metrics; an all-in-one's role label is another name, so both stay.
func withGeneration(reg telemetry.Registry, generation string) telemetry.Registry {
	return telemetry.WithLabels(reg, prometheus.Labels{"generation": generation})
}
