// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
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
}

// Control is an agent's control plane: its identity, the control session with certificate
// renewal, the snapshot runtime and the deny-list.
type Control struct {
	o      ControlOptions
	client *Client
	rt     *Runtime
	deny   *DenyList
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
	c := &Control{o: o}
	c.deny = NewDenyList(DenyListOptions{StateDir: o.StateDir, Root: id.Root, Now: o.Now,
		Signers: func() []*x509.Certificate { return c.rt.Signers() }})
	c.rt = NewRuntime(RuntimeOptions{Identity: id, StateDir: o.StateDir, Applier: o.Applier, Now: o.Now, Logger: o.Logger,
		Send:        func(m *agentv1.AgentMessage) bool { return c.client.Send(m) },
		OnEndpoints: func(eps []string) { c.client.SetEndpoints(eps) }})
	c.client = NewClient(ClientOptions{Identity: id, Endpoints: id.Endpoints, Version: o.Version, Capabilities: o.Capabilities,
		BootID: hex.EncodeToString(boot), Now: o.Now, Logger: o.Logger, Backoff: o.Backoff,
		Hello: func(h *agentv1.Hello) {
			c.rt.Hello(h)
			h.DenyListDigest = c.deny.Digest()
		},
		OnWelcome: c.rt.Welcome,
		OnMessage: func(m *agentv1.ControllerMessage) {
			if m.GetDenyList() == nil {
				c.rt.Message(m)
				return
			}
			// Applied whatever happens to snapshots.
			if err := c.deny.Apply(m.GetDenyList()); err != nil {
				o.Logger.Error("cannot apply a deny-list", "error", err)
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

// Run runs the control plane until ctx ends: it loads the stored deny-list and the last-known-good
// snapshot, so the role runs before any controller answers, then keeps the control session,
// renews the certificate, applies the snapshots it receives and merges every deny-list. A
// last-known-good copy that does not verify is logged and skipped; the agent then waits for the
// controller.
func (c *Control) Run(ctx context.Context) error {
	if err := c.deny.Load(); err != nil {
		c.o.Logger.Error("starting with part of the stored deny-list", "error", err)
	}
	if err := c.rt.LoadLastKnownGood(ctx); errors.Is(err, ErrBadLastKnownGood) {
		c.o.Logger.Error("starting without the last-known-good snapshot", "error", err)
	} else if err != nil {
		return err
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { c.rt.Run(rctx); close(done) }()
	defer func() { cancel(); <-done }()
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
