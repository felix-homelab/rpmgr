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
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
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

// Capabilities are what this connector version implements (docs/03-connections.md, "Versioning
// and capabilities").
var Capabilities = []string{agentproto.CapTunnelQUIC, agentproto.CapTunnelH2, agentproto.CapProxyProtoV1,
	agentproto.CapProxyProtoV2, agentproto.CapProbeTarget, agentproto.CapHealthActive, agentproto.CapTunnelWSS}

// RunOptions configure Run.
type RunOptions struct {
	Config  config.Connector
	Version string
	Getenv  func(string) string // os.Getenv; for the proxy variables
	Now     func() time.Time
	Logger  *slog.Logger
	// LiveLog, if set, is Logger's live log: the agent then runs live-log operations from it
	// (docs/03-connections.md, "Control session"). The built-in agents of an all-in-one have
	// none, as their log is the controller's.
	LiveLog *telemetry.LiveLog
	// Listening, if set, is called once the connector runs.
	Listening func()
	// ControlDial connects the control plane to a controller endpoint; nil dials TCP.
	ControlDial func(ctx context.Context, addr string) (net.Conn, error)
	// Registry, if set, receives the connector's metrics instead of a new registry.
	Registry telemetry.Registry
	// Readiness, if set, gets the connector's readiness check, and Run serves no admin listener:
	// the caller's serves Registry. Unlike a gateway's, a Registry alone keeps the connector's own
	// admin listener, which then serves it.
	Readiness func(check func(context.Context) error)
	// InProcess, if set, is a gateway in the same process, which the data sessions reach in memory;
	// the connector then opens no UDP socket for QUIC, so it reaches other gateways over h2 only.
	InProcess *InProcess
	// Own, if set, reports the addresses and ports the connector never dials, whatever its local
	// policy allows: all-in-one's own listeners (ADR-0019).
	Own func(netip.AddrPort) bool
	// Update, if set, stages the releases the controller offers for the root updater, in update/
	// of the state directory, as its local policy allows (OTA): a connector on Linux that runs on
	// its own, never all-in-one's.
	Update bool
	// Handoff, if set, is the connector's link to restarts with socket hand-off: a process a
	// hand-off started opens its sessions naming the old process's boot_id and reports ready once
	// they are up, and Run hands the sessions to a new process on request, without sockets to
	// pass (docs/03-connections.md, "Restarts with socket hand-off").
	Handoff *handoff.Link
}

// HandoffFromEnv names the environment variable through which the old process of a hand-off tells
// the new one its boot_id: the new process names it as handoff_from in its SessionHello. Only a
// process a hand-off started reads it, and only a hex string of at most 64 digits.
const HandoffFromEnv = "RPMGR_HANDOFF_FROM"

// handoffFrom returns the boot_id the old process named, "" after a plain start or if the value
// is no boot_id.
func handoffFrom(link *handoff.Link, getenv func(string) string) string {
	v := getenv(HandoffFromEnv)
	if link == nil || link.Inherited == nil || len(v) == 0 || len(v) > 64 || strings.Trim(v, "0123456789abcdef") != "" {
		return ""
	}
	return v
}

// handoffEnv is this process's environment for the new process, naming boot as the old boot_id.
func handoffEnv(boot string) []string {
	env := slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, HandoffFromEnv+"=") })
	return append(env, HandoffFromEnv+"="+boot)
}

// readyEvery is how often a process a hand-off started looks whether it can report ready.
const readyEvery = 100 * time.Millisecond

// reportReady reports the connector ready through link. After a plain start that is at once. A
// process a hand-off started waits until its control session is up and its first snapshot applied,
// and every gateway has a data session or failed to open one: the old process keeps serving until
// then, and the readiness window bounds the wait. It returns nil if ctx ends first.
func reportReady(ctx context.Context, link *handoff.Link, controlReady func(context.Context) error, settled func() bool) error {
	if link.Inherited != nil {
		t := time.NewTicker(readyEvery)
		defer t.Stop()
		for controlReady(ctx) != nil || !settled() {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
			}
		}
	}
	if err := link.Ready(); err != nil {
		return fmt.Errorf("connector: hand-off: %w", err)
	}
	return nil
}

// Run runs a connector from its boot file until ctx ends (docs/02-architecture.md): its control
// plane, its data sessions to the gateways of its routes, the targets those routes deliver to as
// its local policy allows, the policy watcher, and the admin listener unless Readiness is set.
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
	watcher := policy.NewGuardedWatcher(cfg.PolicyFile, o.Own, func(p *policy.Policy, err error) {
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
	reg := o.Registry
	if reg == nil {
		reg = telemetry.NewRegistry()
	}
	udpMetrics, err := tunnel.NewUDPMetrics(reg)
	if err != nil {
		return err
	}
	metrics, err := NewMetrics(reg)
	if err != nil {
		return err
	}
	targets = NewTargets(TargetsOptions{Policy: watcher.Current, Logger: o.Logger, UDPMetrics: udpMetrics, Metrics: metrics,
		OnTargetHealth: func(s []*agentv1.ResourceStatus) {
			if ctl != nil {
				ctl.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Readiness: s}}})
			}
		},
		OnHealth: func(h *tunnelv1.RouteHealth) {
			sessions.SetReady(h)
			if ctl != nil { // a change before the control plane exists goes out with its first session
				ctl.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{
					Readiness: []*agentv1.ResourceStatus{{ResourceId: h.GetRouteId(), Reason: h.GetReason(), Detail: h.GetDetail()}}}}})
			}
		}})
	defer targets.Close() // the health checks
	// The UDP socket of QUIC sessions; all-in-one's connector has none, so it opens no port
	// (ADR-0019): it reaches its own gateway in memory and other gateways of its group over h2.
	var tr *quic.Transport
	if o.InProcess == nil {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return err
		}
		tr = &quic.Transport{Conn: pc}
		defer func() { _ = tr.Close(); _ = pc.Close() }() // a Transport does not close a conn it was given
		if err := tunnel.RegisterHostMetrics(reg, pc); err != nil {
			return err
		}
	}
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		return err
	}
	from := handoffFrom(o.Handoff, o.Getenv)
	sessions = New(Options{QUIC: tr, Dial: dial, InProcess: o.InProcess, Streams: targets.Handle, Now: o.Now, Logger: o.Logger, Metrics: metrics,
		Hello: func() *tunnelv1.SessionHello {
			return &tunnelv1.SessionHello{AgentVersion: o.Version, Capabilities: Capabilities, BootId: hex.EncodeToString(boot),
				HandoffFrom: from}
		},
		TLS: func(gatewayID string) (*tls.Config, error) { return gatewayTLS(ctl, gatewayID, o.Now) }})
	defer sessions.Close()
	applier := NewApplier(targets, sessions)
	var toOld atomic.Pointer[handoff.Pipe] // set in a process a hand-off started, once it is ready
	var update *agent.UpdateOptions
	if o.Update {
		update = &agent.UpdateOptions{Dir: filepath.Join(cfg.StateDir, "update"), Policy: watcher.Current, Variant: version.Variant}
	}
	ctl, err = agent.NewControl(agent.ControlOptions{IdentityDir: cfg.IdentityDir, StateDir: cfg.StateDir, Version: o.Version,
		Capabilities: Capabilities, Applier: applier, Now: o.Now, Logger: o.Logger, LiveLog: o.LiveLog, Update: update,
		Dial: o.ControlDial, Fallback: sessions.ControlConn, OnProbeTarget: targets.Probe,
		OnEndDrain: func(context.Context) error {
			if p := toOld.Load(); p != nil {
				return handoff.EndOld(p)
			}
			return errors.New("no old process drains")
		},
		SessionStatus: func() *agentv1.Status {
			return &agentv1.Status{Readiness: applier.Readiness(), ReadinessComplete: true}
		}})
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
	var admin sync.WaitGroup
	if o.Readiness == nil {
		admin.Go(func() {
			if err := telemetry.ServeAdmin(run, cfg.Listen.Admin, reg, ctl.Ready); err != nil {
				errs <- fmt.Errorf("connector: admin listener: %w", err)
			}
		})
		// Run returns only once the admin listener is closed, so that its address is free again.
		defer func() { stop(); admin.Wait() }()
	} else {
		o.Readiness(ctl.Ready)
	}
	done := make(chan error, 1)
	go func() { done <- ctl.Run(run) }()
	o.Logger.Info("connector running", "connector", ctl.Identity().AgentID, "policy", cfg.PolicyFile)
	if o.Listening != nil {
		o.Listening()
	}
	switched := make(chan *handoff.Child, 1)
	if o.Handoff != nil {
		o.Handoff.Serve(func(c context.Context) (*handoff.Child, error) {
			// The new process's sessions supersede this one's, and the gateways then drain these.
			endSessions, endControl := sessions.BeginHandoff(), ctl.BeginHandoff()
			child, err := handoff.Start(c, handoff.Config{Generation: o.Handoff.Generation() + 1, Env: handoffEnv(hex.EncodeToString(boot))}, nil)
			endSessions(err == nil)
			endControl(err == nil)
			if err != nil {
				return nil, err
			}
			o.Handoff.Serve(nil) // this process only drains now
			switched <- child
			return child, nil
		})
		go func() {
			if err := reportReady(run, o.Handoff, ctl.Ready, sessions.Settled); err != nil {
				errs <- err
				return
			}
			if o.Handoff.Inherited != nil && run.Err() == nil {
				// The old process runs until it closes its end of the pipe; what it reports is the
				// drain the controller shows.
				pipe := o.Handoff.Inherited.Pipe()
				toOld.Store(pipe)
				var seen bool // an old process of an earlier release never reports
				_ = handoff.Watch(pipe, func(d handoff.Drain) {
					seen = true
					ctl.SetDraining(agent.DrainingProcessOf(d))
				}, nil)
				toOld.Store(nil)
				if seen {
					ctl.SetDraining(agent.DrainGone())
				}
			}
		}()
	}
	select {
	case <-ctx.Done():
		stop()
		<-done
		return nil
	case child := <-switched:
		o.Logger.Info("the new process took over: keeping the open streams for the hand-off drain", "generation", o.Handoff.Generation())
		since := time.Now()
		deadline := since.Add(cfg.Handoff.DrainPeriod())
		// The new process shows the drain and can end it: it reports what is open and may ask to end.
		dctx, endDrain := context.WithCancel(ctx)
		go handoff.ReportDrain(dctx, child.Pipe.Send, 0, since, deadline, func() (int64, int64, int64) {
			return int64(sessions.Streams()), 0, int64(sessions.OpenSessions())
		})
		go func() {
			for {
				typ, _, err := child.Pipe.Recv()
				if err != nil {
					return // the new process exited
				}
				if typ == handoff.MsgEnd {
					o.Logger.Info("the new process asked to end the drain")
					endDrain()
					return
				}
			}
		}()
		drainHandoff(dctx, sessions, deadline)
		endDrain()
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

// drainHandoff waits until the old process of a hand-off has no open stream left, ctx ends or the
// deadline, the hand-off drain, passes; the caller then ends the sessions.
func drainHandoff(ctx context.Context, sessions *Sessions, deadline time.Time) {
	t := time.NewTicker(readyEvery)
	defer t.Stop()
	for time.Now().Before(deadline) && sessions.Streams() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
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
