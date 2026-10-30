// SPDX-License-Identifier: Apache-2.0

// Package auditsink ships the audit log to its external sinks (docs/04-security.md, "Audit log").
// Every enabled sink receives every chain's checkpoints and, if it is set to, the entries too.
// Each sink keeps a cursor per chain, advanced only after the sink acknowledged an item, so
// shipping is at least once, and a sink that was down catches up from its cursor. The package only
// reads the audit tables and never takes a chain's head lock, so an append never waits for a sink.
package auditsink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditsink"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditsinkcursor"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// The schedule of the sinks (docs/03-connections.md, "Timeouts, keepalive and backoff"): each sink
// is shipped every Every, at most Batch items of a chain at a time; after a failure it is tried
// again after BackoffMin, doubling up to BackoffMax.
const (
	Every      = 10 * time.Second
	Batch      = 500
	BackoffMin = 10 * time.Second
	BackoffMax = 5 * time.Minute
)

// Item is one checkpoint or entry to ship. Body is its JSON.
type Item struct {
	ID    string
	Type  string // EventCheckpoint or EventEntry
	Chain string
	Seq   int64
	Time  time.Time
	Body  []byte
}

// The types of item.
const (
	EventCheckpoint = "audit.checkpoint"
	EventEntry      = "audit.entry"
)

// Sink delivers items to one destination. Ship returns nil only when the destination acknowledged
// the item.
type Sink interface {
	Ship(ctx context.Context, it Item) error
}

// Options configure a Runner.
type Options struct {
	DB     *store.DB
	Sealer *secret.Sealer
	Sender *webhook.Sender
	Now    func() time.Time
	Logger *slog.Logger
}

// Runner ships to every enabled sink. It is used by one job at a time.
type Runner struct {
	o    Options
	mu   sync.Mutex
	back map[string]*backoff
}

// backoff is when a failing sink is tried again.
type backoff struct {
	fails int
	next  time.Time
}

// NewRunner returns a Runner.
func NewRunner(o Options) *Runner { return &Runner{o: o, back: map[string]*backoff{}} }

// Pass ships what every enabled sink is behind with, the sinks concurrently, so that a sink that
// hangs delays no other. fence is the job's lease check, run first in every write transaction.
func (r *Runner) Pass(ctx context.Context, fence func(*ent.Tx) error) error {
	sinks, err := r.o.DB.ReadClient().AuditSink.Query().Where(auditsink.Enabled(true)).Order(ent.Asc(auditsink.FieldName)).All(ctx)
	if err != nil {
		return err
	}
	r.forget(sinks)
	if len(sinks) == 0 {
		return nil
	}
	var heads map[string]int64
	if err := store.ReadTx(ctx, r.o.DB, func(tx *ent.Tx, _ store.Revision) (err error) {
		heads, err = audit.Heads(ctx, tx)
		return err
	}); err != nil {
		return err
	}
	chains := make([]string, 0, len(heads))
	for c := range heads {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	errs := make([]error, len(sinks))
	var wg sync.WaitGroup
	for i, s := range sinks {
		wg.Go(func() { errs[i] = r.shipSink(ctx, s, chains, fence) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// forget drops the backoff of sinks that are gone or disabled.
func (r *Runner) forget(live []*ent.AuditSink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := map[string]bool{}
	for _, s := range live {
		keep[s.ID] = true
	}
	for id := range r.back {
		if !keep[id] {
			delete(r.back, id)
		}
	}
}

// shipSink ships s's chains until one fails, then records the outcome on the sink. A failure of the
// sink is recorded and backs it off; only a failure of the database is returned.
func (r *Runner) shipSink(ctx context.Context, s *ent.AuditSink, chains []string, fence func(*ent.Tx) error) error {
	now := r.o.Now().UTC()
	r.mu.Lock()
	b := r.back[s.ID]
	r.mu.Unlock()
	if b != nil && now.Before(b.next) {
		return nil
	}
	var sinkErr error
	shipped := 0
	sink, err := r.open(s)
	if err != nil {
		sinkErr = err
	} else {
		for _, chain := range chains {
			n, serr, derr := r.shipChain(ctx, s, sink, chain, fence)
			shipped += n
			if derr != nil {
				return derr
			}
			if serr != nil {
				sinkErr = serr
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.backoff(s.ID, sinkErr, now)
	if sinkErr != nil {
		r.o.Logger.Warn("audit sink failing", "sink", s.Name, "kind", s.Kind, "error", describe(sinkErr))
	}
	if sinkErr == nil && shipped == 0 && s.LastError == "" {
		return nil
	}
	return store.WriteTx(ctx, r.o.DB, func(tx *ent.Tx) error {
		if err := fence(tx); err != nil {
			return err
		}
		u := tx.AuditSink.UpdateOneID(s.ID).SetLastError("")
		if sinkErr != nil {
			u.SetLastError(describe(sinkErr))
		}
		if shipped > 0 {
			u.SetLastSuccessAt(now)
		}
		return u.Exec(ctx)
	})
}

// backoff moves s's retry time: cleared by a success, doubled by a failure.
func (r *Runner) backoff(id string, failure error, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if failure == nil {
		delete(r.back, id)
		return
	}
	b := r.back[id]
	if b == nil {
		b = &backoff{}
		r.back[id] = b
	}
	b.fails++
	d := BackoffMax
	if b.fails <= 5 {
		d = min(BackoffMin<<(b.fails-1), BackoffMax)
	}
	b.next = now.Add(d)
}

// shipChain ships at most Batch items of one chain, in order and one at a time, then moves the
// cursor to the last one the sink acknowledged, in a transaction fenced by the job's lease. It
// returns how many items were acknowledged, the sink's failure and the database's failure apart.
func (r *Runner) shipChain(ctx context.Context, s *ent.AuditSink, sink Sink, chain string, fence func(*ent.Tx) error) (n int, sinkErr, dbErr error) {
	org := chain
	if chain == audit.InstanceChain {
		org = ""
	}
	var cur *ent.AuditSinkCursor
	var items []Item
	dbErr = store.ReadTx(ctx, r.o.DB, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		cur, err = tx.AuditSinkCursor.Query().Where(auditsinkcursor.SinkID(s.ID), auditsinkcursor.Chain(chain)).Only(ctx)
		if ent.IsNotFound(err) {
			cur, err = &ent.AuditSinkCursor{}, nil
		}
		if err != nil {
			return err
		}
		cps, err := audit.CheckpointsAfter(ctx, tx, org, cur.CheckpointSeq, Batch)
		if err != nil {
			return err
		}
		for _, c := range cps {
			items = append(items, checkpointItem(c))
		}
		if !s.Entries {
			return nil
		}
		es, err := audit.EntriesAfter(ctx, tx, org, cur.EntrySeq, Batch-len(items))
		if err != nil {
			return err
		}
		for _, e := range es {
			items = append(items, entryItem(e))
		}
		return nil
	})
	if dbErr != nil {
		return 0, nil, dbErr
	}
	cp, en := cur.CheckpointSeq, cur.EntrySeq
	for _, it := range items {
		if sinkErr = sink.Ship(ctx, it); sinkErr != nil {
			break
		}
		n++
		if it.Type == EventCheckpoint {
			cp = it.Seq
		} else {
			en = it.Seq
		}
	}
	if ctx.Err() != nil {
		return n, nil, ctx.Err()
	}
	var oldest *time.Time
	dbErr = store.ReadTx(ctx, r.o.DB, func(tx *ent.Tx, _ store.Revision) error {
		t, ok, err := audit.OldestAfter(ctx, tx, org, cp, en, s.Entries)
		if ok {
			oldest = &t
		}
		return err
	})
	if dbErr != nil {
		return n, sinkErr, dbErr
	}
	if n == 0 && sameTime(cur.OldestUnshippedAt, oldest) {
		return n, sinkErr, nil
	}
	dbErr = store.WriteTx(ctx, r.o.DB, func(tx *ent.Tx) error {
		if err := fence(tx); err != nil {
			return err
		}
		if cur.ID == "" {
			c := tx.AuditSinkCursor.Create().SetSinkID(s.ID).SetChain(chain).SetCheckpointSeq(cp).SetEntrySeq(en)
			if oldest != nil {
				c.SetOldestUnshippedAt(*oldest)
			}
			return c.Exec(ctx)
		}
		u := tx.AuditSinkCursor.UpdateOneID(cur.ID).SetCheckpointSeq(cp).SetEntrySeq(en)
		if oldest != nil {
			u.SetOldestUnshippedAt(*oldest)
		} else {
			u.ClearOldestUnshippedAt()
		}
		return u.Exec(ctx)
	})
	return n, sinkErr, dbErr
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// open returns the sink s describes.
func (r *Runner) open(s *ent.AuditSink) (Sink, error) {
	switch s.Kind {
	case auditsink.KindWebhook:
		return openWebhook(r.o, s)
	default:
		return nil, fmt.Errorf("the %s sink is not available yet", s.Kind)
	}
}

// describe is the text of a failure for the sink's status: no text names the sink's URL.
func describe(err error) string { return webhook.Describe(err) }
