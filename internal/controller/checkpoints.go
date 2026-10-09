// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// CheckpointCheckEvery is how often the checkpoint job looks for a chain that is due
// (docs/03-connections.md, "Timeouts, keepalive and backoff").
const CheckpointCheckEvery = time.Minute

// CheckpointOptions are the inputs of CheckpointJob and FinalCheckpoints.
type CheckpointOptions struct {
	DB     *store.DB
	CA     *pki.CA
	Log    *audit.CheckpointLog
	Leases *lease.Leases
	Now    func() time.Time
	Logger *slog.Logger
}

// CheckpointJob is the singleton job that signs audit checkpoints (docs/04-security.md, "Audit
// log"): each chain that is due (audit.Due) gets one in a transaction fenced by the job's lease,
// and once committed it goes to the local log too.
func CheckpointJob(o CheckpointOptions) lease.Job {
	return lease.Job{Name: "audit-checkpoints", Reason: "sign audit checkpoints", Every: CheckpointCheckEvery,
		Run: func(ctx context.Context, l lease.Lease) error {
			return writeCheckpoints(ctx, o, func(tx *ent.Tx) error { return o.Leases.Fence(ctx, tx, l) }, audit.Due(o.Now()))
		}}
}

// FinalCheckpoints gives every chain with entries after its last checkpoint one more, when the
// controller stops; sys is a system scope.
func FinalCheckpoints(sys context.Context, o CheckpointOptions) error {
	return writeCheckpoints(sys, o, nil, audit.Pending)
}

func writeCheckpoints(ctx context.Context, o CheckpointOptions, fence func(*ent.Tx) error, due func(audit.Head, *audit.Checkpoint) bool) error {
	var cps []audit.Checkpoint
	err := store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
		if fence != nil {
			if err := fence(tx); err != nil {
				return err
			}
		}
		var err error
		cps, err = audit.WriteCheckpoints(ctx, tx, o.CA.AuditSigner(), o.Now(), due)
		return err
	})
	if err != nil || len(cps) == 0 {
		return err
	}
	return o.Log.Append(cps)
}

// RetentionCheckEvery is how often the retention job prunes the audit chains
// (docs/03-connections.md, "Timeouts, keepalive and backoff").
const RetentionCheckEvery = time.Hour

// RetentionJob is the singleton job that keeps audit entries for the instance's audit retention
// (docs/04-security.md, "Audit log"): it prunes each chain to its newest checkpoint older than the
// retention (audit.Prune) and records that in the chain, in one transaction fenced by its lease.
func RetentionJob(o CheckpointOptions) lease.Job {
	return lease.Job{Name: "audit-retention", Reason: "remove audit entries past their retention", Every: RetentionCheckEvery,
		Run: func(ctx context.Context, l lease.Lease) error {
			set, _, err := settings.Instance(ctx, o.DB.ReadClient())
			if err != nil {
				return err
			}
			cutoff := o.Now().Add(-set.GetAuditRetention().AsDuration())
			return store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
				if err := o.Leases.Fence(ctx, tx, l); err != nil {
					return err
				}
				chains, err := audit.Chains(ctx, tx)
				if err != nil {
					return err
				}
				for _, org := range chains {
					seq, err := audit.Prune(ctx, tx, org, cutoff)
					if err != nil {
						return err
					}
					if seq == 0 {
						continue
					}
					if _, err := audit.Append(ctx, tx, audit.Entry{OrgID: org, ActorType: audit.ActorSystem, ActorID: "audit-retention",
						Action: "audit.prune", Result: audit.Success,
						Reason: fmt.Sprintf("entries up to %d removed; the chain verifies from the checkpoint at %d", seq, seq)}); err != nil {
						return err
					}
				}
				return nil
			})
		}}
}
