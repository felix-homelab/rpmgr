// SPDX-License-Identifier: Apache-2.0

// Package apply writes a zone's plan (internal/dns/plan) to the provider through the ownership
// ledger (docs/15-dns.md, "Ownership ledger", "Batches, failures and the rate budget",
// "Fail-static"). The ledger decides what rpmgr may change; this package keeps it true:
//
//   - A create has its ledger row, in state creating, committed before the provider is called; the
//     ID is in the record's marker comment. A delete marks its row deleting first.
//   - The operations go in batches of at most cloudflare.MaxBatchOps. A batch that the provider
//     refuses record by record (HTTP 4xx other than 401, 403 and 429) is retried one operation at
//     a time, so one bad record fails only its own name.
//   - Anything else that goes wrong, an unreachable provider, a rate limit, a refused token, a lost
//     lease, stops the pass: nothing further is written, no record is deleted, and the rows stay as
//     they are (fail-static).
//   - What was written is recorded in one transaction that first checks the lease's fencing token,
//     with an audit entry per write.
package apply

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
)

// Actor is the audit actor of the DNS job's writes.
const Actor = "dns"

// maxReason bounds the provider's words kept in a ledger row.
const maxReason = 512

// commitWithin bounds the transaction that records what was written, which must still run when
// the pass was cancelled after the provider changed.
const commitWithin = 10 * time.Second

// Zone is the managed zone a plan is applied to.
type Zone struct {
	ID         string // dns_zones.id
	OrgID      string
	Name       string // the apex, normalised
	ProviderID string // the provider's zone ID
}

// Failure is a record the provider refused, with the provider's reason.
type Failure struct {
	Name   string
	Type   string
	Reason string
}

// Result is what a pass wrote.
type Result struct {
	Created, Updated, Deleted int
	// Failed are the records the provider refused one by one; the others were applied.
	Failed []Failure
}

// Engine applies plans.
type Engine struct {
	DB     *store.DB
	Leases *lease.Leases
	// TrustDomain is this instance's, in every marker.
	TrustDomain string
	// Guard, if set, is called before every request that writes to the provider; an error stops the
	// pass before the request is sent. The DNS job uses it to refuse a batch the lease will not
	// outlast (docs/15-dns.md, "The DNS job").
	Guard func(ctx context.Context) error
	Now   func() time.Time
}

// Marker returns the comment of the record that ledger row id owns.
func Marker(trustDomain, id string) string { return "rpmgr " + trustDomain + " " + id }

// Owned returns the ledger rows of a zone in the form the planner reads.
func Owned(ctx context.Context, db *store.DB, zoneID string) ([]plan.Owned, error) {
	rows, err := db.ReadClient().DNSRecord.Query().Where(dnsrecord.DNSZoneID(zoneID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]plan.Owned, 0, len(rows))
	for _, r := range rows {
		o := plan.Owned{LedgerID: r.ID, Adopted: r.AdoptedFrom != "", Type: string(r.Type), Content: r.Content}
		if r.ProviderRecordID != nil {
			o.RecordID = *r.ProviderRecordID
		}
		out = append(out, o)
	}
	return out, nil
}

type opKind int

const (
	opDelete opKind = iota
	opUpdate
	opCreate
)

// op is one write: the record to send, and the ledger row it belongs to.
type op struct {
	kind   opKind
	rec    dns.Record
	row    *ent.DNSRecord // the row as it was before the write
	rowID  string
	reason string // set when the provider refused the op
	// correction: the update puts back a change someone else made (see Correct).
	correction bool
}

// Apply writes pl to the provider. The lease must be held; its token is checked in the
// transaction that records the writes. On an error that is not a refusal of single records the
// pass stops: what was written until then is recorded, and the error is returned.
func (e *Engine) Apply(ctx context.Context, l lease.Lease, p dns.Provider, z Zone, pl plan.Plan) (Result, error) {
	return e.apply(ctx, l, p, z, pl, nil)
}

func (e *Engine) apply(ctx context.Context, l lease.Lease, p dns.Provider, z Zone, pl plan.Plan, corr Correction) (Result, error) {
	var res Result
	if pl.Empty() {
		return res, nil
	}
	ops, err := e.writeAhead(ctx, l, z, pl, corr)
	if err != nil {
		return res, err
	}
	var done, failed []op
	var stop error
	size := cloudflare.MaxBatchOps
	if !p.Caps().Batch {
		size = 1
	}
send:
	for _, g := range slices.Collect(slices.Chunk(ops, size)) {
		err := e.send(ctx, p, z, g)
		switch {
		case err == nil:
			done = append(done, g...)
			continue
		case !refusal(err):
			stop = err
			break send
		case len(g) == 1:
			g[0].reason = reasonOf(err)
			failed = append(failed, g[0])
			continue
		}
		for _, o := range g { // the batch failed all-or-nothing: one by one
			err := e.send(ctx, p, z, []op{o})
			switch {
			case err == nil:
				done = append(done, o)
			case refusal(err):
				o.reason = reasonOf(err)
				failed = append(failed, o)
			default:
				stop = err
				break send
			}
		}
	}
	cerr := e.commit(ctx, l, p, z, &res, done, failed)
	return res, errors.Join(stop, cerr)
}

// writeAhead commits the rows of the creates (state creating) and marks the rows of the deletes
// (state deleting), before the provider is called, and returns the operations in the order the
// provider applies them: deletes, updates, creates.
func (e *Engine) writeAhead(ctx context.Context, l lease.Lease, z Zone, pl plan.Plan, corr Correction) ([]op, error) {
	var ops []op
	err := store.WriteTx(ctx, e.DB, func(tx *ent.Tx) error {
		ops = ops[:0]
		if err := e.Leases.Fence(ctx, tx, l); err != nil {
			return err
		}
		rows, err := tx.DNSRecord.Query().Where(dnsrecord.DNSZoneID(z.ID)).All(ctx)
		if err != nil {
			return err
		}
		byRecord := map[string]*ent.DNSRecord{}
		var open []*ent.DNSRecord // rows of a create that never got a record: reused, never duplicated
		for _, r := range rows {
			switch {
			case r.ProviderRecordID != nil:
				byRecord[*r.ProviderRecordID] = r
			case r.State == dnsrecord.StateCreating || r.State == dnsrecord.StateError:
				open = append(open, r)
			}
		}
		for _, d := range pl.Deletes {
			row := byRecord[d.ID]
			if row == nil {
				return fmt.Errorf("apply: the plan deletes record %s, which has no ledger row", d.ID)
			}
			if _, err := tx.DNSRecord.UpdateOneID(row.ID).SetState(dnsrecord.StateDeleting).SetReason("").Save(ctx); err != nil {
				return err
			}
			ops = append(ops, op{kind: opDelete, rec: d, row: row, rowID: row.ID})
		}
		for _, u := range pl.Updates {
			row := byRecord[u.ID]
			if row == nil {
				return fmt.Errorf("apply: the plan changes record %s, which has no ledger row", u.ID)
			}
			ops = append(ops, op{kind: opUpdate, rec: u, row: row, rowID: row.ID, correction: corr[u.ID]})
		}
		for _, c := range pl.Creates {
			id, err := e.createRow(ctx, tx, z, c, &open)
			if err != nil {
				return err
			}
			c.Comment = Marker(e.TrustDomain, id)
			ops = append(ops, op{kind: opCreate, rec: c, rowID: id})
		}
		return nil
	})
	return ops, err
}

// createRow writes the row of a record about to be created, or takes one that an earlier pass left
// without a record: the same content first, then the same name and type.
func (e *Engine) createRow(ctx context.Context, tx *ent.Tx, z Zone, c dns.Record, open *[]*ent.DNSRecord) (string, error) {
	pick := func(match func(*ent.DNSRecord) bool) *ent.DNSRecord {
		i := slices.IndexFunc(*open, match)
		if i < 0 {
			return nil
		}
		r := (*open)[i]
		*open = slices.Delete(*open, i, i+1)
		return r
	}
	sameName := func(r *ent.DNSRecord) bool { return r.Name == c.Name && string(r.Type) == c.Type }
	if r := pick(func(r *ent.DNSRecord) bool { return sameName(r) && r.Content == c.Content }); r != nil {
		return r.ID, e.reset(ctx, tx, r.ID, c)
	}
	if r := pick(sameName); r != nil {
		return r.ID, e.reset(ctx, tx, r.ID, c)
	}
	row, err := tx.DNSRecord.Create().SetOrgID(z.OrgID).SetDNSZoneID(z.ID).SetName(c.Name).SetType(dnsrecord.Type(c.Type)).
		SetContent(c.Content).SetTTL(c.TTL).SetProxied(c.Proxied).SetState(dnsrecord.StateCreating).Save(ctx)
	if err != nil {
		return "", err
	}
	return row.ID, nil
}

func (e *Engine) reset(ctx context.Context, tx *ent.Tx, id string, c dns.Record) error {
	return tx.DNSRecord.UpdateOneID(id).SetContent(c.Content).SetTTL(c.TTL).SetProxied(c.Proxied).
		SetState(dnsrecord.StateCreating).SetReason("").Exec(ctx)
}

// send sends the operations as one batch, after the guard.
func (e *Engine) send(ctx context.Context, p dns.Provider, z Zone, ops []op) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.Guard != nil {
		if err := e.Guard(ctx); err != nil {
			return err
		}
	}
	var b dns.Batch
	for _, o := range ops {
		switch o.kind {
		case opDelete:
			b.Deletes = append(b.Deletes, o.rec.ID)
		case opUpdate:
			b.Patches = append(b.Patches, o.rec)
		case opCreate:
			b.Posts = append(b.Posts, o.rec)
		}
	}
	return p.Apply(ctx, z.ProviderID, b)
}

// refusal reports whether the provider refused a record, rather than the pass: a request it
// understood and declined (HTTP 400 to 499 other than 401, 403, 404 and 429), or one it refused
// before it was sent. Everything else is fail-static.
func refusal(err error) bool {
	if errors.Is(err, dns.ErrInvalid) {
		return true
	}
	var pe *dns.ProviderError
	return errors.As(err, &pe) && pe.Err == nil && pe.Status >= 400 && pe.Status < 500
}

// reasonOf is the provider's own words for a refusal, bounded. It never holds a credential.
func reasonOf(err error) string {
	var pe *dns.ProviderError
	s := err.Error()
	if errors.As(err, &pe) && len(pe.Messages) > 0 {
		s = strings.Join(pe.Messages, "; ")
	}
	if len(s) > maxReason {
		s = strings.ToValidUTF8(s[:maxReason], "")
	}
	return s
}

// commit records what was written: in one transaction, after the lease's fencing token was checked.
func (e *Engine) commit(ctx context.Context, l lease.Lease, p dns.Provider, z Zone, res *Result, done, failed []op) error {
	if len(done) == 0 && len(failed) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitWithin)
	defer cancel()
	// The provider answers a batch without the IDs of what it created; they are found by marker.
	idByMarker := map[string]string{}
	var listErr error
	if slices.ContainsFunc(done, func(o op) bool { return o.kind == opCreate }) {
		var live []dns.Record
		if live, listErr = p.ListRecords(ctx, z.ProviderID); listErr == nil {
			for _, r := range live {
				idByMarker[r.Comment] = r.ID
			}
		}
	}
	now := e.now()
	var out Result
	err := store.WriteTx(ctx, e.DB, func(tx *ent.Tx) error {
		out = Result{}
		if err := e.Leases.Fence(ctx, tx, l); err != nil {
			return err
		}
		for _, o := range done {
			if err := e.record(ctx, tx, z, o, idByMarker, now, &out); err != nil {
				return err
			}
		}
		for _, o := range failed {
			out.Failed = append(out.Failed, Failure{Name: o.rec.Name, Type: o.rec.Type, Reason: o.reason})
			if err := tx.DNSRecord.UpdateOneID(o.rowID).SetState(dnsrecord.StateError).SetReason(o.reason).Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	*res = out
	return listErr
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// record commits one write to its row and audits it.
func (e *Engine) record(ctx context.Context, tx *ent.Tx, z Zone, o op, idByMarker map[string]string, now time.Time, out *Result) error {
	var action string
	var before, after *snapshot
	switch o.kind {
	case opDelete:
		action, before = "dns_record.delete", snap(o.row)
		if err := tx.DNSRecord.DeleteOneID(o.rowID).Exec(ctx); err != nil {
			return err
		}
		out.Deleted++
	case opUpdate:
		action, before = "dns_record.update", snap(o.row)
		u := tx.DNSRecord.UpdateOneID(o.rowID).SetContent(o.rec.Content).SetTTL(o.rec.TTL).SetProxied(o.rec.Proxied).
			SetState(dnsrecord.StateSynced).SetReason("").SetLastSyncedAt(now)
		if o.correction {
			u.SetCorrectedAt(now)
		}
		r, err := u.Save(ctx)
		if err != nil {
			return err
		}
		after = snap(r)
		out.Updated++
	case opCreate:
		action = "dns_record.create"
		id, ok := idByMarker[o.rec.Comment]
		if !ok { // written, but not listed: the row stays creating, and the next pass links it
			return nil
		}
		r, err := tx.DNSRecord.UpdateOneID(o.rowID).SetProviderRecordID(id).SetState(dnsrecord.StateSynced).
			SetReason("").SetLastSyncedAt(now).Save(ctx)
		if err != nil {
			return err
		}
		after = snap(r)
		out.Created++
	}
	reason := "dns zone " + z.ID
	if o.correction {
		reason = "a change someone else made was put back, dns zone " + z.ID
	}
	return e.auditRow(ctx, tx, z, action, reason, before, after)
}
