// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The CA rotation timing (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	CARotationEvery = time.Hour   // how often the singleton job checks the schedule
	CAReloadEvery   = time.Minute // how often every replica looks for rotated keys
)

// CAOptions are the inputs of CARotation and ReloadCA.
type CAOptions struct {
	DB     *store.DB
	CA     *pki.CA
	Sealer *secret.Sealer
	Leases *lease.Leases
	Now    func() time.Time
	Logger *slog.Logger
}

func (o *CAOptions) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
}

// CARotation is the singleton job that keeps the CA's keys on schedule (pki.Rotate): it commits a
// rotation with an audit record in a transaction fenced by its lease, and then reloads the CA.
func CARotation(o CAOptions) lease.Job {
	o.defaults()
	return lease.Job{Name: "ca-rotation", Reason: "rotate the CA's keys on schedule", Every: CARotationEvery,
		Run: func(ctx context.Context, l lease.Lease) error {
			var done []string
			err := store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
				if err := o.Leases.Fence(ctx, tx, l); err != nil {
					return err
				}
				var err error
				if done, err = pki.Rotate(ctx, tx, o.Sealer, o.Now()); err != nil {
					return err
				}
				for _, d := range done {
					if _, err := audit.Append(ctx, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "ca-rotation",
						Action: "ca.rotate", TargetType: "ca", Result: audit.Success, Reason: d}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil || len(done) == 0 {
				return err
			}
			o.Logger.Info("rotated CA keys", "changes", done)
			_, err = o.CA.Reload(ctx, o.DB, o.Sealer, o.Now)
			return err
		}}
}

// ReloadCA reloads the CA every CAReloadEvery until ctx ends, so that a rotation another replica
// committed takes effect here; ctx must carry the system scope.
func ReloadCA(ctx context.Context, o CAOptions) {
	o.defaults()
	t := time.NewTicker(CAReloadEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if changed, err := o.CA.Reload(ctx, o.DB, o.Sealer, o.Now); err != nil {
				o.Logger.Error("cannot reload the CA", "error", err)
			} else if changed {
				o.Logger.Info("reloaded rotated CA keys")
			}
		}
	}
}
