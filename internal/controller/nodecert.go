// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// The node certificate's renewal (docs/04-security.md, "Leaf certificates"; docs/03-connections.md,
// "Timeouts, keepalive and backoff").
const (
	nodeRetry       = time.Minute // after a failed renewal
	nodeMinInterval = time.Minute // between two renewals, so that a clock far ahead cannot loop
)

// NodeCertOptions are the inputs of RenewNodeCertificate.
type NodeCertOptions struct {
	CA     *pki.CA
	DB     *store.DB
	Sys    context.Context // the system scope that records the certificates
	NodeID string
	Holder *pki.Holder // the node certificate the agent endpoint presents
	Now    func() time.Time
	Logger *slog.Logger
}

// RenewNodeCertificate renews the node certificate in o.Holder at half its lifetime, with a new key,
// until ctx ends; a failed renewal is retried every minute. New handshakes present the new
// certificate at once; open connections keep theirs.
func RenewNodeCertificate(ctx context.Context, o NodeCertOptions) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	for {
		leaf := o.Holder.Certificate().Leaf
		due := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
		if !sleepCtx(ctx, due.Sub(o.Now())) {
			return
		}
		cert, err := o.CA.NodeCertificate(o.Sys, o.DB, o.NodeID)
		if err != nil {
			o.Logger.Error("cannot renew the node certificate; retrying", "error", err, "not_after", leaf.NotAfter)
			if !sleepCtx(ctx, nodeRetry) {
				return
			}
			continue
		}
		o.Holder.Set(cert)
		o.Logger.Info("renewed the node certificate", "not_after", cert.Leaf.NotAfter)
		if !sleepCtx(ctx, nodeMinInterval) {
			return
		}
	}
}

// sleepCtx waits d, or returns false when ctx ends first; d <= 0 does not wait.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
