// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
)

// StopWindow is how long after a correction a second change of the same record is not corrected
// (docs/15-dns.md, "Timers and limits"): another tool is probably writing it.
const StopWindow = time.Hour

// Report is what a pass found that a person should know of.
type Report struct {
	// Orphans are records with this instance's marker and no ledger row. They are never deleted.
	Orphans []dns.Record
	// Corrected are the names of owned records that were changed at the provider by someone else and
	// are put back.
	Corrected []string
	// Drifted are the names of owned records that changed again within the stop window, or that
	// stay changed after it: they are no longer corrected, and an alert is due.
	Drifted []string
	// Ambiguous are records that carry the marker of a row that cannot link them: at another name
	// or type, or more than one. They are never linked, so they stay foreign; the row is `error`.
	Ambiguous []dns.Record
	// Relinked counts the ledger rows that a crash left without their record's ID and that were
	// linked again by the marker.
	Relinked int
}

// Relink repairs the ledger after a crash, from the records the provider holds now
// (docs/15-dns.md, "Ownership ledger"). A row in state creating, or error, that has no provider ID
// is linked to the record that carries its marker: the crash fell between the provider call and the
// commit. A row in state deleting whose record is gone is finished and removed. A row that never
// got a record and that no desired record asks for any more is removed; one that is still wanted
// stays and the next create reuses it. A record that carries a marker of this instance and no row
// is not touched here: it is an orphan.
func (e *Engine) Relink(ctx context.Context, l lease.Lease, z Zone, live []dns.Record, desired []dns.Record) (int, error) {
	n, _, err := e.relink(ctx, l, z, live, desired)
	return n, err
}

func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func (e *Engine) relink(ctx context.Context, l lease.Lease, z Zone, live []dns.Record, desired []dns.Record) (int, []dns.Record, error) {
	var rep Report
	byMarker := map[string][]dns.Record{}
	liveIDs := map[string]bool{}
	for _, r := range live {
		byMarker[r.Comment] = append(byMarker[r.Comment], r)
		liveIDs[r.ID] = true
	}
	wanted := map[string]bool{}
	for _, d := range desired {
		wanted[d.Name+"/"+d.Type] = true
	}
	n := 0
	err := store.WriteTx(ctx, e.DB, func(tx *ent.Tx) error {
		n, rep = 0, Report{}
		rows, err := tx.DNSRecord.Query().Where(dnsrecord.DNSZoneID(z.ID)).All(ctx)
		if err != nil {
			return err
		}
		fenced := false
		fence := func() error {
			if fenced {
				return nil
			}
			fenced = true
			return e.Leases.Fence(ctx, tx, l)
		}
		linked := map[string]bool{}
		for _, r := range rows {
			if r.ProviderRecordID != nil {
				linked[*r.ProviderRecordID] = true
			}
		}
		now := e.now()
		for _, r := range rows {
			switch {
			case r.ProviderRecordID == nil && (r.State == dnsrecord.StateCreating || r.State == dnsrecord.StateError):
				// Only a record at the row's own name and of its type is linked: anything else that
				// carries the marker was written by someone else, and stays foreign. Two records with
				// the marker are ambiguous: none is linked.
				cands := byMarker[Marker(e.TrustDomain, r.ID)]
				var same []dns.Record
				for _, c := range cands {
					if sameName(c.Name, r.Name) && c.Type == string(r.Type) {
						same = append(same, c)
					}
				}
				if len(cands) > 1 || (len(cands) == 1 && len(same) == 0) {
					const reason = "a record carries this row's marker but is not unique or not at the row's name and type; not linked"
					if r.State != dnsrecord.StateError || r.Reason != reason {
						if err := fence(); err != nil {
							return err
						}
						if err := tx.DNSRecord.UpdateOneID(r.ID).SetState(dnsrecord.StateError).SetReason(reason).Exec(ctx); err != nil {
							return err
						}
					}
					rep.Ambiguous = append(rep.Ambiguous, cands...)
					continue
				}
				var rec dns.Record
				ok := len(same) == 1
				if ok {
					rec = same[0]
				}
				switch {
				case ok && !linked[rec.ID]:
					if err := fence(); err != nil {
						return err
					}
					linked[rec.ID] = true
					u, err := tx.DNSRecord.UpdateOneID(r.ID).SetProviderRecordID(rec.ID).SetContent(rec.Content).SetTTL(rec.TTL).
						SetProxied(rec.Proxied).SetState(dnsrecord.StateSynced).SetReason("").SetLastSyncedAt(now).Save(ctx)
					if err != nil {
						return err
					}
					if err := e.auditRow(ctx, tx, z, "dns_record.link", "linked by its marker after an interrupted write", nil, snap(u)); err != nil {
						return err
					}
					n++
				case !ok && !wanted[r.Name+"/"+string(r.Type)]:
					if err := fence(); err != nil {
						return err
					}
					if err := tx.DNSRecord.DeleteOneID(r.ID).Exec(ctx); err != nil {
						return err
					}
				}
			case r.State == dnsrecord.StateDeleting && r.ProviderRecordID != nil && !liveIDs[*r.ProviderRecordID]:
				if err := fence(); err != nil {
					return err
				}
				if err := tx.DNSRecord.DeleteOneID(r.ID).Exec(ctx); err != nil {
					return err
				}
				if err := e.auditRow(ctx, tx, z, "dns_record.delete", "the record was already gone at the provider", snap(r), nil); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return n, rep.Ambiguous, err
}

// Correction marks the records whose update puts back a change someone else made, so that the
// correction is counted when it is committed.
type Correction map[string]bool

// Correct finds the owned records that were changed at the provider since the job wrote them, by
// comparing the provider's records with the ledger, and returns the plan to carry out
// (docs/15-dns.md, "Ownership ledger"):
//
//   - A changed record is put back: the plan's update for it stands and restores the marker; a record
//     whose marker alone was edited gets an update of its own. The change is audited when the update
//     is committed, and counted: the row's corrected_at is set.
//   - If the same record changed again within StopWindow of its last correction, or still differs
//     after it was stopped, it is marked drifted and left alone: its updates are dropped from the plan,
//     and the report names it. Its deletion, when its source is gone, stays.
//   - A drifted record that matches the ledger again is in sync again.
//
// The plan's hash is not recomputed: only a pass that writes uses the result, and a held zone's plan
// is not changed here.
func (e *Engine) Correct(ctx context.Context, l lease.Lease, z Zone, live []dns.Record, pl plan.Plan) (plan.Plan, Correction, Report, error) {
	var rep Report
	corr := Correction{}
	liveByID := map[string]dns.Record{}
	for _, r := range live {
		liveByID[r.ID] = r
	}
	now := e.now()
	err := store.WriteTx(ctx, e.DB, func(tx *ent.Tx) error {
		rep, corr = Report{}, Correction{}
		out := pl
		out.Updates = slices.Clone(pl.Updates)
		rows, err := tx.DNSRecord.Query().Where(dnsrecord.DNSZoneID(z.ID), dnsrecord.ProviderRecordIDNotNil()).All(ctx)
		if err != nil {
			return err
		}
		fenced := false
		for _, r := range rows {
			rec, ok := liveByID[*r.ProviderRecordID]
			if !ok || (r.State != dnsrecord.StateSynced && r.State != dnsrecord.StateDrifted) {
				continue
			}
			marker := Marker(e.TrustDomain, r.ID)
			changed := !plan.SameContent(dns.Record{Type: string(r.Type), Content: r.Content}, rec) || r.TTL != rec.TTL || r.Proxied != rec.Proxied
			if !changed && rec.Comment == marker {
				if r.State == dnsrecord.StateDrifted { // someone put it back
					if err := tx.DNSRecord.UpdateOneID(r.ID).SetState(dnsrecord.StateSynced).SetReason("").Exec(ctx); err != nil {
						return err
					}
				}
				continue
			}
			if !fenced {
				fenced = true
				if err := e.Leases.Fence(ctx, tx, l); err != nil {
					return err
				}
			}
			ui := slices.IndexFunc(out.Updates, func(u dns.Record) bool { return u.ID == rec.ID })
			if ui < 0 && rec.Comment == marker { // changed to what the sources want: the ledger learns it
				if err := tx.DNSRecord.UpdateOneID(r.ID).SetContent(rec.Content).SetTTL(rec.TTL).SetProxied(rec.Proxied).
					SetState(dnsrecord.StateSynced).SetReason("").Exec(ctx); err != nil {
					return err
				}
				continue
			}
			stopped := r.State == dnsrecord.StateDrifted
			if !stopped && r.CorrectedAt != nil && now.Sub(*r.CorrectedAt) < StopWindow {
				stopped = true
				if err := tx.DNSRecord.UpdateOneID(r.ID).SetState(dnsrecord.StateDrifted).
					SetReason("changed again within the stop window; no longer corrected").Exec(ctx); err != nil {
					return err
				}
				if err := e.auditRow(ctx, tx, z, "dns_record.drifted", "changed again within the stop window", snap(r), snapOf(r, rec)); err != nil {
					return err
				}
			}
			switch {
			case stopped:
				if ui >= 0 {
					out.Updates = slices.Delete(out.Updates, ui, ui+1)
				}
				rep.Drifted = append(rep.Drifted, rec.Name)
				continue
			case changed:
				if err := e.auditRow(ctx, tx, z, "dns_record.drift", "changed at the provider", snap(r), snapOf(r, rec)); err != nil {
					return err
				}
			}
			// Put it back. The update the plan holds stands; a change that left the record as the
			// plan wants it, or only its marker, needs one of its own.
			switch {
			case ui >= 0:
				out.Updates[ui].Comment = marker
			default: // the marker alone was edited
				u := rec
				u.Comment = marker
				out.Updates = append(out.Updates, u)
			}
			corr[rec.ID] = true
			rep.Corrected = append(rep.Corrected, rec.Name)
		}
		pl = out
		return nil
	})
	slices.Sort(rep.Corrected)
	slices.Sort(rep.Drifted)
	return pl, corr, rep, err
}

// snapOf is the record as the provider holds it, in the shape of the ledger's snapshot.
func snapOf(r *ent.DNSRecord, rec dns.Record) *snapshot {
	return &snapshot{Name: r.Name, Type: rec.Type, Content: rec.Content, TTL: rec.TTL, Proxied: rec.Proxied, ID: rec.ID, row: r.ID}
}

// Wanted is what a zone should hold.
type Wanted struct {
	Desired  []dns.Record // compile.Result.Desired
	Keep     []string     // compile.Result.Keep()
	Reserved []string
	// Gate, if set, is asked about the plan before anything is written: a reason (HeldDeletionGuard,
	// HeldPlanChanged) holds the zone, and the pass writes nothing; approved says that the plan is
	// the one an Owner or Admin approved.
	Gate func(plan.Plan) (hold string, approved bool)
}

// Outcome is what a pass planned and did.
type Outcome struct {
	// Plan is what was applied. It is empty, with no hash, if the provider's records could not be
	// listed.
	Plan   plan.Plan
	Result Result
	Report Report
	// Held is why the pass wrote nothing and the zone must be held, if Wanted.Gate said so.
	Held string
	// Approved: the plan applied was the approved one, so the approval is used up.
	Approved bool
}

// Reconcile is one pass over a zone: list the provider's records, repair the ledger after a crash
// (Relink), plan, put back what someone else changed (Correct), and apply. A failure to list is
// fail-static like any other: nothing was written.
func (e *Engine) Reconcile(ctx context.Context, l lease.Lease, p dns.Provider, z Zone, w Wanted) (Outcome, error) {
	var out Outcome
	live, err := p.ListRecords(ctx, z.ProviderID)
	if err != nil {
		return out, err
	}
	if out.Report.Relinked, out.Report.Ambiguous, err = e.relink(ctx, l, z, live, w.Desired); err != nil {
		return out, err
	}
	owned, err := Owned(ctx, e.DB, z.ID)
	if err != nil {
		return out, err
	}
	pl := plan.Diff(plan.Input{Zone: z.Name, Desired: w.Desired, Keep: w.Keep, Reserved: w.Reserved, Live: live, Owned: owned, TrustDomain: e.TrustDomain})
	out.Report.Orphans = pl.Orphans
	if w.Gate != nil {
		if out.Held, out.Approved = w.Gate(pl); out.Held != "" {
			out.Plan = pl
			return out, nil
		}
	}
	var corr Correction
	var rep Report
	if pl, corr, rep, err = e.Correct(ctx, l, z, live, pl); err != nil {
		out.Plan = pl
		return out, err
	}
	out.Plan = pl
	out.Report.Corrected, out.Report.Drifted = rep.Corrected, rep.Drifted
	out.Result, err = e.apply(ctx, l, p, z, pl, corr)
	return out, err
}
