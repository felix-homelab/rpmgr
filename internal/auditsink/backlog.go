// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"context"
	"sort"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Backlog is what a sink has not acknowledged yet.
type Backlog struct {
	SinkID  string
	Sink    string
	Enabled bool
	// Items counts the checkpoints and, for a sink that gets them, the entries after its cursors.
	Items int64
	// Oldest is when the oldest of them was appended, the zero time when there is none.
	Oldest time.Time
	// Chains is the same per chain that has entries, by name.
	Chains []ChainBacklog
}

// ChainBacklog is the cursors of a sink on one chain and what lies after them.
type ChainBacklog struct {
	Chain         string
	CheckpointSeq int64
	EntrySeq      int64
	Items         int64
	Oldest        time.Time
}

// Backlogs returns the backlog of every sink, by name, from one read snapshot. It counts from the
// audit tables and the cursors, never from what the job last wrote, so every replica reports the
// same, and an item that no replica ships, because none holds the job's lease, still ages. It
// counts the checkpoints after the cursors in two aggregate queries, whatever the number of
// checkpoints, sinks and chains, and reads the time of an unshipped entry only where a sink that gets entries is behind.
func Backlogs(ctx context.Context, db *store.DB) ([]Backlog, error) {
	var out []Backlog
	err := store.ReadTx(ctx, db, func(tx *ent.Tx, _ store.Revision) error {
		out = nil
		sinks, err := tx.AuditSink.Query().Order(ent.Asc("name")).All(ctx)
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
		chains := make([]string, 0, len(heads))
		for c := range heads {
			chains = append(chains, c)
		}
		sort.Strings(chains)
		all, after, err := audit.CheckpointBacklog(ctx, tx)
		if err != nil {
			return err
		}
		for _, s := range sinks {
			b := Backlog{SinkID: s.ID, Sink: s.Name, Enabled: s.Enabled}
			for _, chain := range chains {
				cb := ChainBacklog{Chain: chain}
				if c := byKey[key{s.ID, chain}]; c != nil {
					cb.CheckpointSeq, cb.EntrySeq = c.CheckpointSeq, c.EntrySeq
				}
				st := all[chain]
				if byKey[key{s.ID, chain}] != nil {
					st = after[audit.SinkChain{Sink: s.ID, Chain: chain}]
				}
				cb.Items, cb.Oldest = st.Count, st.Oldest
				if s.Entries && heads[chain] > cb.EntrySeq {
					cb.Items += heads[chain] - cb.EntrySeq
					t, ok, err := audit.EntryTimeAfter(ctx, tx, orgOfChain(chain), cb.EntrySeq)
					if err != nil {
						return err
					}
					if ok && (cb.Oldest.IsZero() || t.Before(cb.Oldest)) {
						cb.Oldest = t
					}
				}
				b.Items += cb.Items
				if !cb.Oldest.IsZero() && (b.Oldest.IsZero() || cb.Oldest.Before(b.Oldest)) {
					b.Oldest = cb.Oldest
				}
				b.Chains = append(b.Chains, cb)
			}
			out = append(out, b)
		}
		return nil
	})
	return out, err
}
