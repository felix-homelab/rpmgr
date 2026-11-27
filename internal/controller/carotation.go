// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
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
	CA     *castore.CA
	Sealer *secret.Sealer
	Leases *lease.Leases
	Now    func() time.Time
	Logger *slog.Logger
	// RevLog receives the marker of a root switch or drop; nil records none.
	RevLog *revlog.Log
}

func (o *CAOptions) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
}

// CARotation is the singleton job that keeps the CA's keys on schedule (castore.PlanRotation): it
// commits a rotation with an audit record in a transaction fenced by its lease, and then reloads
// the CA.
func CARotation(o CAOptions) lease.Job {
	o.defaults()
	return lease.Job{Name: "ca-rotation", Reason: "rotate the CA's keys on schedule", Every: CARotationEvery,
		Run: func(ctx context.Context, l lease.Lease) error {
			var done []string
			// Planned before the transaction: opening and sealing keys may wait for a key service.
			plan, err := castore.PlanRotation(ctx, o.DB.ReadClient().CAKey, o.Sealer, o.Now())
			if err != nil {
				return err
			}
			// A switch records the overlap of this moment as the earliest drop date of the old root.
			overlap, err := RotationOverlap(ctx, o.DB.ReadClient())
			if err != nil {
				return err
			}
			plan.WithOverlap(overlap)
			write := func(tx *ent.Tx) error {
				if err := o.Leases.Fence(ctx, tx, l); err != nil {
					return err
				}
				var err error
				if done, err = plan.Apply(ctx, tx); err != nil {
					return err
				}
				for _, d := range done {
					if _, err := audit.Append(ctx, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "ca-rotation",
						Action: "ca.rotate", TargetType: "ca", Result: audit.Success, Reason: d}); err != nil {
						return err
					}
				}
				// A switch of issuing to a new root is marked for a restore of an older archive.
				from, to := plan.RootSwitch()
				return markRoot(o.RevLog, revlog.RootSwitched, from, to, "ca-rotation")
			}
			if plan.Config() {
				// Issuing moved to a new root: the trust bundle changed, so the write is a configuration
				// change and agents get snapshots of a new revision that carry it.
				_, err = store.ConfigTx(ctx, o.DB, func(tx *ent.Tx) ([]string, error) { return []string{"pki"}, write(tx) })
			} else {
				err = store.WriteTx(ctx, o.DB, write)
			}
			if err != nil {
				return err
			}
			o.warnSigning(ctx)
			dropped, err := o.dropOldRoot(ctx, l)
			if err != nil {
				return err
			}
			if len(done) == 0 && !dropped {
				return nil
			}
			o.Logger.Info("rotated CA keys", "changes", done, "old_root_dropped", dropped)
			_, err = o.CA.Reload(ctx, o.DB, o.Sealer, o.Now)
			return err
		}}
}

// dropOldRoot drops the old root of a root rotation once the overlap has passed, unless enabled
// agents that were seen since still lack the new root: it then logs the alert "root rotation
// stalled" at each run and leaves the root, so that no agent is stranded without the operator's
// choice (`rpmgr ca drop-root --strand-stragglers`, docs/04-security.md, "Root rotation"). It
// reports whether it dropped the root.
func (o *CAOptions) dropOldRoot(ctx context.Context, l lease.Lease) (bool, error) {
	overlap, err := RotationOverlap(ctx, o.DB.ReadClient())
	if err != nil {
		return false, err
	}
	plan, err := castore.PlanDropRoot(ctx, o.DB.ReadClient().CAKey, o.Now(), castore.DropOptions{Overlap: overlap, Stragglers: stragglerCount})
	var early *castore.DropEarlyError
	var stalled *castore.StragglersError
	if errors.Is(err, castore.ErrNoRotation) || errors.As(err, &early) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	disabled, err := disabledLacking(ctx, o.DB, o.Now(), overlap)
	if err != nil {
		return false, err
	}
	reason := "the overlap of the root rotation has passed"
	if len(disabled) > 0 {
		reason += "; " + disabledDetail(disabled)
	}
	_, err = applyDrop(ctx, o.DB, plan, o.RevLog, "ca-rotation", reason, func(tx *ent.Tx) error { return o.Leases.Fence(ctx, tx, l) })
	if errors.As(err, &stalled) {
		o.Logger.Error("root rotation stalled: the old root is not dropped while enabled agents lack the new one; update, "+
			"re-enroll or decommission them, or run `rpmgr ca drop-root --strand-stragglers`", "agents", stalled.N)
		return false, nil
	}
	if err == nil && len(disabled) > 0 {
		o.Logger.Warn("the old root is dropped; disabled agents that lack the new root have to re-enroll before they can connect again",
			"agents", disabled)
	}
	return err == nil, err
}

// warnSigning logs, on every run, that the next intermediate waits for the signature of an offline
// root: a warning at first, an error when the active intermediate expires within 30 days or the
// signed one is not valid now
// (docs/04-security.md, "Offline root CA").
func (o *CAOptions) warnSigning(ctx context.Context) {
	switch a, err := castore.IntermediateSigningAlert(ctx, o.DB, o.Now()); {
	case err != nil:
		o.Logger.Error("cannot check whether the intermediate waits for a signature", "error", err)
	case a == castore.AlertNextNotValid:
		o.Logger.Error("the signed intermediate is not valid now and is not activated; sign a new request with the offline root")
	case a == castore.AlertCritical:
		o.Logger.Error("the intermediate needs the offline root's signature and the active one expires within 30 days")
	case a == castore.AlertNeedsSigning:
		o.Logger.Warn("the intermediate needs the offline root's signature")
	}
	// The intermediate is not rotated while a root rotation runs: one that stalls must not run into the
	// expiry of the active intermediate unseen.
	if !rotationRuns(ctx, o.DB) {
		return
	}
	st, err := rotationStatus(ctx, o.DB, o.Now())
	if err != nil {
		o.Logger.Error("cannot check the root rotation against the intermediate's expiry", "error", err)
		return
	}
	if st.IntermediateExpiring {
		o.Logger.Error("the active intermediate expires within 30 days and cannot be rotated during a root rotation: finish it "+
			"(rpmgr ca status) or give it up with rpmgr ca new-root --abort", "expires", st.IntermediateExpires)
	}
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
