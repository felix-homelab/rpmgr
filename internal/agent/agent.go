// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// ControlOptions configure RunControl.
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

// RunControl runs an agent's control plane until ctx ends: it loads the identity and the
// last-known-good snapshot, so the role runs before any controller answers, then keeps the control
// session, renews the certificate and applies the snapshots it receives. A last-known-good copy
// that does not verify is logged and skipped; the agent then waits for the controller.
func RunControl(ctx context.Context, o ControlOptions) error {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	id, err := Load(o.IdentityDir)
	if err != nil {
		return err
	}
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		return err
	}
	var client *Client
	rt := NewRuntime(RuntimeOptions{Identity: id, StateDir: o.StateDir, Applier: o.Applier, Now: o.Now, Logger: o.Logger,
		Send:        func(m *agentv1.AgentMessage) bool { return client.Send(m) },
		OnEndpoints: func(eps []string) { client.SetEndpoints(eps) }})
	client = NewClient(ClientOptions{Identity: id, Endpoints: id.Endpoints, Version: o.Version, Capabilities: o.Capabilities,
		BootID: hex.EncodeToString(boot), Now: o.Now, Logger: o.Logger, Backoff: o.Backoff,
		Hello: rt.Hello, OnWelcome: rt.Welcome, OnMessage: rt.Message,
		SaveCertificate: func(key *ecdsa.PrivateKey, chain [][]byte) error { return SaveCertificate(id.Dir, key, chain) }})
	if err := rt.LoadLastKnownGood(ctx); errors.Is(err, ErrBadLastKnownGood) {
		o.Logger.Error("starting without the last-known-good snapshot", "error", err)
	} else if err != nil {
		return err
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { rt.Run(rctx); close(done) }()
	defer func() { cancel(); <-done }()
	return client.Run(ctx)
}
