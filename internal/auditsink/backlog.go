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
// reads the checkpoints after the slowest cursor in one query, whatever the number of sinks and
// chains, and the time of an unshipped entry only where a sink that gets entries is behind.
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
		// The checkpoints after the slowest cursor: a pair without a cursor starts at 0.
		from := int64(-1)
		for _, s := range sinks {
			for _, chain := range chains {
				seq := int64(0)
				if c := byKey[key{s.ID, chain}]; c != nil {
					seq = c.CheckpointSeq
				}
				if from < 0 || seq < from {
					from = seq
				}
			}
		}
		var stamps map[string][]audit.Stamp
		if from >= 0 {
			if stamps, err = audit.CheckpointStamps(ctx, tx, from); err != nil {
				return err
			}
		}
		for _, s := range sinks {
			b := Backlog{SinkID: s.ID, Sink: s.Name, Enabled: s.Enabled}
			for _, chain := range chains {
				cb := ChainBacklog{Chain: chain}
				if c := byKey[key{s.ID, chain}]; c != nil {
					cb.CheckpointSeq, cb.EntrySeq = c.CheckpointSeq, c.EntrySeq
				}
				list := stamps[chain]
				i := sort.Search(len(list), func(i int) bool { return list[i].Seq > cb.CheckpointSeq })
				cb.Items = int64(len(list) - i)
				if i < len(list) {
					cb.Oldest = list[i].Time
				}
				if s.Entries && heads[chain] > cb.EntrySeq {
					cb.Items += heads[chain] - cb.EntrySeq
					org := chain
					if chain == audit.InstanceChain {
						org = ""
					}
					t, ok, err := audit.EntryTimeAfter(ctx, tx, org, cb.EntrySeq)
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
