// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// ControlOptions configure an agent's control plane.
type ControlOptions struct {
	IdentityDir  string
	StateDir     string
	Version      string
	Capabilities []string
	Applier      Applier // runs the role's resources
	Now          func() time.Time
	Logger       *slog.Logger
	Backoff      *Backoff // nil is ControlBackoff
	// OnDenyList, if set, is called after the deny-list changed: loaded at start or merged from
	// the controller, so the role can close the sessions of peers it now names.
	OnDenyList func()
	// Dial connects to a controller endpoint; nil dials TCP.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Fallback, if set, carries the control session through a data session when every
	// controller endpoint failed (ClientOptions.Fallback).
	Fallback func(ctx context.Context) (net.Conn, error)
	// OnAcmeChallenge, if set, applies the ACME challenges gateways answer; its error goes back
	// in the OpResult. Without it every challenge is refused.
	OnAcmeChallenge func(*agentv1.AcmeChallenge) error
	// OnProbeTarget, if set, reads the certificate a target presents and returns it, DER; it
	// runs apart from the control session, and its result or error goes back in the OpResult.
	// Without it every probe is refused.
	OnProbeTarget func(context.Context, *agentv1.ProbeTarget) ([]byte, error)
	// OnOperation, if set, runs an imperative operation the controller opened, until ctx ends
	// (its deadline, or the controller ending it), sending its frames with send; its error ends
	// the operation with that reason. Operations it does not run it refuses with
	// ErrUnsupportedOperation. Without it every operation is refused.
	OnOperation func(ctx context.Context, open *agentv1.Open, send func(*agentv1.AttachFrame) error) error
	// LiveLog, if set, is the role's log with live-log subscriptions: the agent announces
	// logs.stream and runs live-log operations from it.
	LiveLog *telemetry.LiveLog
	// SessionStatus, if set, returns the Status the agent sends at the start of each session, so
	// that what changed while there was none is not lost: a connector's complete readiness, a
	// gateway's data sessions.
	SessionStatus func() *agentv1.Status
	// Update, if set, stages the releases the controller offers for the root updater and
	// announces the capability ota (docs/04-security.md, "Over-the-air updates"): gateways and
	// connectors on Linux that run on their own, never all-in-one's.
	Update *UpdateOptions
}

// Control is an agent's control plane: its identity, the control session with certificate
// renewal, the snapshot runtime and the deny-list.
type Control struct {
	o      ControlOptions
	id     Loaded
	client *Client
	rt     *Runtime
	deny   *DenyList
	stager *Stager // nil without ControlOptions.Update
}

// NewControl loads the identity and wires the control plane; Run starts it.
func NewControl(o ControlOptions) (*Control, error) {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	id, err := Load(o.IdentityDir)
	if err != nil {
		return nil, err
	}
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		return nil, err
	}
	c := &Control{o: o, id: id}
	caps := o.Capabilities
	if o.LiveLog != nil {
		caps = append(slices.Clone(caps), agentproto.CapLogsStream)
	}
	var onOffer func(*agentv1.ReleaseOffer)
	if o.Update != nil {
		now := o.Now
		if now == nil {
			now = time.Now
		}
		c.stager = newStager(*o.Update, o.Version, func(st *agentv1.UpdateState) {
			c.client.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Update: st}}})
		}, now, o.Logger)
		caps = append(slices.Clone(caps), agentproto.CapOTA)
		onOffer = c.stager.Offer
	}
	c.deny = NewDenyList(DenyListOptions{StateDir: o.StateDir, Root: id.Root, Now: o.Now,
		Signers: func() []*x509.Certificate { return c.rt.Signers() }})
	c.rt = NewRuntime(RuntimeOptions{Identity: id, StateDir: o.StateDir, Applier: o.Applier, Now: o.Now, Logger: o.Logger,
		Send:        func(m *agentv1.AgentMessage) bool { return c.client.Send(m) },
		OnEndpoints: func(eps []string) { c.client.SetEndpoints(eps) }, OnOffer: onOffer})
	c.client = NewClient(ClientOptions{Identity: id, Endpoints: id.Endpoints, Version: o.Version, Capabilities: caps,
		BootID: hex.EncodeToString(boot), Now: o.Now, Logger: o.Logger, Backoff: o.Backoff, Dial: o.Dial, Fallback: o.Fallback,
		Hello: func(h *agentv1.Hello) {
			c.rt.Hello(h)
			h.DenyListDigest = c.deny.Digest()
		},
		OnWelcome: func(w *agentv1.Welcome) {
			c.rt.Welcome(w)
			var st *agentv1.Status
			if o.SessionStatus != nil {
				st = o.SessionStatus()
			}
			if c.stager != nil {
				if u := c.stager.State(); u != nil {
					if st == nil {
						st = &agentv1.Status{}
					}
					st.Update = u
				}
			}
			if st != nil {
				c.client.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: st}})
			}
		},
		OnMessage: func(m *agentv1.ControllerMessage) {
			if p := m.GetProbeTarget(); p != nil {
				go c.probe(p) // a dial must not hold up the control session
				return
			}
			if op := m.GetOpenOperation(); op != nil {
				go c.operate(op)
				return
			}
			if ch := m.GetAcmeChallenge(); ch != nil {
				err := errors.New("this agent answers no ACME challenges")
				if o.OnAcmeChallenge != nil {
					err = o.OnAcmeChallenge(ch)
				}
				r := &agentv1.OpResult{OpId: ch.GetOpId()}
				if err != nil {
					r.Error = err.Error()
				}
				c.client.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_OpResult{OpResult: r}})
				return
			}
			if m.GetDenyList() == nil {
				c.rt.Message(m)
				return
			}
			// Applied whatever happens to snapshots.
			if err := c.deny.Apply(m.GetDenyList()); err != nil {
				o.Logger.Error("cannot apply a deny-list", "error", err)
			} else if o.OnDenyList != nil {
				o.OnDenyList()
			}
		},
		SaveCertificate: func(key *ecdsa.PrivateKey, chain [][]byte) error { return SaveCertificate(id.Dir, key, chain) }})
	return c, nil
}

// RunControl runs an agent's control plane until ctx ends (NewControl, Control.Run).
func RunControl(ctx context.Context, o ControlOptions) error {
	c, err := NewControl(o)
	if err != nil {
		return err
	}
	return c.Run(ctx)
}

// probe answers a ProbeTarget with the certificate the role read, or why it could not.
func (c *Control) probe(p *agentv1.ProbeTarget) {
	r := &agentv1.OpResult{OpId: p.GetOpId()}
	if c.o.OnProbeTarget == nil {
		r.Error = "this agent reads no target certificates"
	} else if der, err := c.o.OnProbeTarget(context.Background(), p); err != nil {
		r.Error = err.Error()
	} else {
		r.Certificate = der
	}
	c.client.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_OpResult{OpResult: r}})
}

// ErrUnsupportedOperation is an operation an agent does not run.
var ErrUnsupportedOperation = errors.New("agent: this agent does not run the operation")

// operate runs an imperative operation (docs/03-connections.md, "Control session"): it attaches
// on the control session's connection with the operation's ticket and runs OnOperation until the
// deadline, the controller ending it or the stream breaking. An operation the role does not run,
// or one it cannot attach, is refused with an OpResult.
func (c *Control) operate(open *agentv1.Open) {
	refuse := func(err error) {
		c.client.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_OpResult{OpResult: &agentv1.OpResult{OpId: open.GetOpId(),
			Error: err.Error()}}})
	}
	run := c.o.OnOperation
	if open.GetKind() == agentv1.OperationKind_OPERATION_KIND_LOGS && c.o.LiveLog != nil {
		run = func(ctx context.Context, open *agentv1.Open, send func(*agentv1.AttachFrame) error) error {
			return serveLogs(ctx, c.o.LiveLog, open.GetLogs(), send)
		}
	}
	if run == nil {
		refuse(ErrUnsupportedOperation)
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), open.GetDeadline().AsTime())
	defer cancel()
	st, err := c.client.Attach(ctx)
	if err == nil {
		err = st.Send(&agentv1.AttachFrame{Frame: &agentv1.AttachFrame_Hello{Hello: &agentv1.AttachHello{OpId: open.GetOpId(),
			Ticket: open.GetTicket()}}})
	}
	if err != nil {
		refuse(fmt.Errorf("agent: cannot attach the operation: %w", err))
		return
	}
	// The controller's AttachEnd, or the end of the stream, ends the operation.
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer cancel()
		for {
			f, err := st.Recv()
			if err != nil || f.GetEnd() != nil {
				return
			}
		}
	}()
	var mu sync.Mutex
	send := func(f *agentv1.AttachFrame) error {
		mu.Lock()
		defer mu.Unlock()
		return st.Send(f)
	}
	err = run(ctx, open, send)
	reason := ""
	if err != nil && ctx.Err() == nil {
		reason = err.Error()
	}
	_ = send(&agentv1.AttachFrame{Frame: &agentv1.AttachFrame_End{End: &agentv1.AttachEnd{Reason: reason}}})
	_ = st.CloseSend()
	// Cancelling the stream at once could reset it before the controller read the last frames:
	// wait until the controller ends it, a short while at most.
	select {
	case <-finished:
	case <-time.After(attachLinger):
	}
}

// attachLinger is how long an agent waits for the controller to end an Attach stream after its
// own end.
const attachLinger = 5 * time.Second

// Run runs the control plane until ctx ends: it loads the stored deny-list and the last-known-good
// snapshot, so the role runs before any controller answers, then keeps the control session,
// renews the certificate, applies the snapshots it receives and merges every deny-list. A
// last-known-good copy that does not verify is logged and skipped; the agent then waits for the
// controller.
func (c *Control) Run(ctx context.Context) error {
	if err := c.deny.Load(); err != nil {
		c.o.Logger.Error("starting with part of the stored deny-list", "error", err)
	}
	if c.o.OnDenyList != nil {
		c.o.OnDenyList()
	}
	if err := c.rt.LoadLastKnownGood(ctx); errors.Is(err, ErrBadLastKnownGood) {
		c.o.Logger.Error("starting without the last-known-good snapshot", "error", err)
	} else if err != nil {
		return err
	}
	rctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() { c.rt.Run(rctx) })
	if c.stager != nil {
		wg.Go(func() { c.stager.Run(rctx) })
	}
	defer func() { cancel(); wg.Wait() }()
	return c.client.Run(ctx)
}

// Errors of Ready.
var (
	ErrNoSession  = errors.New("no control session")
	ErrNoSnapshot = errors.New("no snapshot applied")
)

// Ready is the readiness of the control plane (docs/10-operations.md, "Health"): an established
// control session and an applied snapshot. A role adds its own conditions.
func (c *Control) Ready(context.Context) error {
	switch {
	case !c.client.Connected():
		return ErrNoSession
	case !c.rt.Applied():
		return ErrNoSnapshot
	}
	return nil
}

// Send sends the role's own message, such as a Status, on the current control session; it reports
// false if there is none.
func (c *Control) Send(m *agentv1.AgentMessage) bool { return c.client.Send(m) }

// Identity returns the agent's identity as it was loaded; the certificate in it is the one at
// start, Certificate the current one.
func (c *Control) Identity() Loaded { return c.id }

// Certificate returns the agent's current certificate, which renewal replaces, for the role's
// TLS configurations.
func (c *Control) Certificate() tls.Certificate { return c.client.Certificate() }

// ControllerAddr returns host:port of the endpoint of the current or last control session, or of
// the first endpoint before any session: where a gateway sends the control sessions that
// connectors carry through its data sessions.
func (c *Control) ControllerAddr() (string, error) {
	_, _, ep := c.client.Stats()
	if ep == "" || ep == DataSessionEndpoint {
		eps := c.client.Endpoints()
		if len(eps) == 0 {
			return "", errors.New("agent: no controller endpoint")
		}
		ep = eps[0]
	}
	return dialAddr(ep)
}

// DenyList returns the agent's deny-list, for the role's TLS peers.
func (c *Control) DenyList() *DenyList { return c.deny }

// Register adds the agent's metrics to reg (docs/10-operations.md, "Metrics").
func (c *Control) Register(reg prometheus.Registerer) error {
	return errors.Join(
		reg.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "rpmgr_agent_applied_revision",
			Help: "The seq of the last applied revision."}, func() float64 { return float64(c.rt.AppliedSeq()) })),
		reg.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "rpmgr_agent_cert_expiry_timestamp_seconds",
			Help: "When the agent's own certificate expires, in Unix seconds."}, func() float64 {
			if leaf := c.client.Certificate().Leaf; leaf != nil {
				return float64(leaf.NotAfter.Unix())
			}
			return 0
		})),
	)
}
