// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"context"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditsink"
)

// Backlog is what an enabled sink has not acknowledged yet.
type Backlog struct {
	SinkID string
	Sink   string
	// Items counts the checkpoints and, for a sink that gets them, the entries after its cursors.
	Items int64
	// Oldest is when the oldest of them was appended, the zero time when there is none.
	Oldest time.Time
}

// Backlogs returns the backlog of every enabled sink, by name, from one read snapshot. It reads
// the cursors the job keeps, so every replica reports the same.
func Backlogs(ctx context.Context, db *store.DB) ([]Backlog, error) {
	var out []Backlog
	err := store.ReadTx(ctx, db, func(tx *ent.Tx, _ store.Revision) error {
		sinks, err := tx.AuditSink.Query().Where(auditsink.Enabled(true)).Order(ent.Asc(auditsink.FieldName)).All(ctx)
		if err != nil || len(sinks) == 0 {
			return err
		}
		heads, err := audit.Heads(ctx, tx)
		if err != nil {
			return err
		}
		cursors, err := tx.AuditSinkCursor.Query().All(ctx)
		if err != nil {
			return err
		}
		type key struct{ sink, chain string }
		byKey := map[key]*ent.AuditSinkCursor{}
		for _, c := range cursors {
			byKey[key{c.SinkID, c.Chain}] = c
		}
		for _, s := range sinks {
			b := Backlog{SinkID: s.ID, Sink: s.Name}
			for chain, head := range heads {
				cur := byKey[key{s.ID, chain}]
				if cur == nil {
					cur = &ent.AuditSinkCursor{}
				}
				org := chain
				if chain == audit.InstanceChain {
					org = ""
				}
				n, err := audit.CountCheckpointsAfter(ctx, tx, org, cur.CheckpointSeq)
				if err != nil {
					return err
				}
				b.Items += n
				if s.Entries && head > cur.EntrySeq {
					b.Items += head - cur.EntrySeq
				}
				if cur.OldestUnshippedAt != nil && (b.Oldest.IsZero() || cur.OldestUnshippedAt.Before(b.Oldest)) {
					b.Oldest = cur.OldestUnshippedAt.UTC()
				}
			}
			out = append(out, b)
		}
		return nil
	})
	return out, err
}
