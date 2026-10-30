// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// AuditSinkOptions configure the audit sink job.
type AuditSinkOptions struct {
	DB     *store.DB
	Leases *lease.Leases
	Sealer *secret.Sealer
	Sender *webhook.Sender
	Now    func() time.Time
	Logger *slog.Logger
}

// AuditSinkJob is the singleton job that ships the audit log to the enabled sinks
// (docs/04-security.md, "Audit log"): every auditsink.Every, each sink from its cursor, a cursor
// moving only in a transaction fenced by the job's lease, so a replica that lost the lease records
// nothing and the new holder ships again, which is at least once. It never takes a chain's head
// lock, so an append never waits for it.
func AuditSinkJob(o AuditSinkOptions) lease.Job {
	r := auditsink.NewRunner(auditsink.Options{DB: o.DB, Sealer: o.Sealer, Sender: o.Sender, Now: o.Now, Logger: o.Logger})
	return lease.Job{Name: "audit-sinks", Reason: "ship the audit log to its sinks", Every: auditsink.Every,
		Run: func(ctx context.Context, l lease.Lease) error {
			return r.Pass(ctx, func(tx *ent.Tx) error { return o.Leases.Fence(ctx, tx, l) })
		}}
}
