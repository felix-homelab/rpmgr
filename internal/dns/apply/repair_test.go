// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package apply_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// reconcile is one pass as the job runs it.
func (e *env) reconcile(want ...dns.Record) (apply.Outcome, error) {
	e.t.Helper()
	return e.eng.Reconcile(e.sys, e.lease, e.prov, e.zone, apply.Wanted{Desired: want})
}

func (e *env) byName(name string) cftest.Record {
	e.t.Helper()
	for _, r := range e.snapshot() {
		if r.Name == name {
			return r
		}
	}
	e.t.Fatalf("no record %s in %v", name, e.snapshot())
	return cftest.Record{}
}

// otherTool changes a record at the provider as a person or another tool would.
func (e *env) otherTool(r cftest.Record, edit func(*dns.Record)) {
	e.t.Helper()
	rec := dns.Record{ID: r.ID, Type: r.Type, Name: r.Name, Content: r.Content, TTL: r.TTL, Proxied: r.Proxied, Comment: r.Comment}
	edit(&rec)
	if err := e.prov.Apply(e.sys, e.zone.ProviderID, dns.Batch{Patches: []dns.Record{rec}}); err != nil {
		e.t.Fatal(err)
	}
}

// TestDNS_CrashRelinksByMarker: a crash after the provider call and before the commit leaves a
// creating row; the next pass links the record by its marker instead of reporting a conflict, and
// does not create it again. A record with this instance's marker and no ledger row is an orphan:
// reported, and never deleted, however many passes follow and whatever the sources say.
func TestDNS_CrashRelinksByMarker(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		want := []dns.Record{a("a.example.com", "192.0.2.1"), a("b.example.com", "192.0.2.2")}
		// The crash: the lease is lost while the batch is on its way, so nothing is committed.
		e.eng.Guard = func(ctx context.Context) error {
			_, err := e.db.Client().ExecContext(ctx, "UPDATE leases SET fencing_token = fencing_token + 1")
			return err
		}
		if _, err := e.reconcile(want...); !errors.Is(err, lease.ErrLost) {
			t.Fatalf("the crash: %v", err)
		}
		e.eng.Guard = nil
		rows := e.rows()
		if len(rows) != 2 || rows[0].State != dnsrecord.StateCreating || rows[0].ProviderRecordID != nil || len(e.snapshot()) != 2 {
			t.Fatalf("after the crash: rows %+v, %d records", rows, len(e.snapshot()))
		}
		// Without the repair the records are in the way: foreign address records at the names.
		live, _ := e.prov.ListRecords(e.sys, e.zone.ProviderID)
		owned, _ := apply.Owned(e.sys, e.db, e.zone.ID)
		if p := planOf(want, live, owned); len(p.Conflicts) != 2 {
			t.Fatalf("expected the conflicts that the relink prevents: %+v", p.Conflicts)
		}
		// The next holder of the lease.
		e.lease = takeOver(t, e)
		out, err := e.reconcile(want...)
		if err != nil || out.Report.Relinked != 2 || len(out.Plan.Conflicts) != 0 || !out.Plan.Empty() {
			t.Fatalf("relink: %+v %v", out, err)
		}
		recs := e.snapshot()
		if len(recs) != 2 {
			t.Fatalf("%d records, the relink created them again", len(recs))
		}
		for _, r := range e.rows() {
			if r.State != dnsrecord.StateSynced || r.ProviderRecordID == nil || r.LastSyncedAt == nil {
				t.Errorf("row %+v", r)
			}
			if i := slices.IndexFunc(recs, func(c cftest.Record) bool { return c.ID == *r.ProviderRecordID }); i < 0 || recs[i].Comment != apply.Marker(td, r.ID) {
				t.Errorf("row %+v does not own a record of its marker", r)
			}
		}
		links := 0
		for _, en := range e.audits() {
			if en.Action == "dns_record.link" {
				links++
			}
		}
		if links != 2 {
			t.Errorf("%d link entries", links)
		}

		// An orphan: this instance's marker, no row. It is reported and never deleted.
		orphan := e.fake.AddRecord(e.zone.ProviderID, cftest.Record{Type: "A", Name: "ghost.example.com", Content: "192.0.2.99", TTL: 300,
			Comment: apply.Marker(td, "dnr_01ARZ3NDEKTSV4RRFFQ69G5FAV")})
		for _, w := range [][]dns.Record{want, nil, {a("ghost.example.com", "192.0.2.5")}, nil} {
			out, err := e.reconcile(w...)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Report.Orphans) != 1 || out.Report.Orphans[0].ID != orphan.ID {
				t.Fatalf("orphans %+v", out.Report.Orphans)
			}
			if got := e.byName("ghost.example.com"); got != orphan {
				t.Fatalf("the orphan changed: %+v", got)
			}
		}
		// Gone sources delete what the ledger owns, and not the orphan.
		if got := e.names(); !slices.Equal(got, []string{"ghost.example.com"}) {
			t.Fatalf("records %v", got)
		}
	})
}

func takeOver(t *testing.T, e *env) lease.Lease {
	t.Helper()
	e.db.Client().Lease.Update().SetExpiresAt(0).ExecX(e.sys)
	l, ok, err := e.leases.TryAcquire(e.sys, "dns")
	if err != nil || !ok {
		t.Fatal("takeover", err)
	}
	return l
}

func (e *env) names() []string {
	var out []string
	for _, r := range e.snapshot() {
		out = append(out, r.Name)
	}
	slices.Sort(out)
	return out
}

// TestApply_RelinkRepairs: a deleting row whose record is gone is finished; a row that never got a
// record and is no longer wanted is removed, one that is still wanted is kept and reused; a marker
// that another row already holds links nothing.
func TestApply_RelinkRepairs(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	if _, err := e.reconcile(a("gone.example.com", "192.0.2.1"), a("kept.example.com", "192.0.2.2")); err != nil {
		t.Fatal(err)
	}
	// A crash after the delete: the row says deleting, the record is gone.
	gone := e.byName("gone.example.com")
	e.db.Client().DNSRecord.Update().Where(dnsrecord.ProviderRecordID(gone.ID)).SetState(dnsrecord.StateDeleting).ExecX(e.sys)
	if err := e.prov.Apply(e.sys, e.zone.ProviderID, dns.Batch{Deletes: []string{gone.ID}}); err != nil {
		t.Fatal(err)
	}
	// Two rows of creates that never happened: one still wanted, one not.
	c := e.db.Client()
	c.DNSRecord.Create().SetOrgID(e.zone.OrgID).SetDNSZoneID(e.zone.ID).SetName("wanted.example.com").SetType("A").SetContent("192.0.2.3").SetTTL(300).ExecX(e.sys)
	c.DNSRecord.Create().SetOrgID(e.zone.OrgID).SetDNSZoneID(e.zone.ID).SetName("stale.example.com").SetType("A").SetContent("192.0.2.4").SetTTL(300).
		SetState(dnsrecord.StateError).SetReason("refused").ExecX(e.sys)
	out, err := e.reconcile(a("kept.example.com", "192.0.2.2"), a("wanted.example.com", "192.0.2.3"))
	if err != nil || out.Report.Relinked != 0 {
		t.Fatalf("%+v %v", out, err)
	}
	var names []string
	for _, r := range e.rows() {
		names = append(names, r.Name)
		if r.State != dnsrecord.StateSynced {
			t.Errorf("row %+v", r)
		}
	}
	if !slices.Equal(names, []string{"kept.example.com", "wanted.example.com"}) {
		t.Fatalf("rows %v: the deleted and the stale row must go, the wanted one stays and is created", names)
	}
	if !slices.Equal(e.names(), []string{"kept.example.com", "wanted.example.com"}) {
		t.Fatalf("records %v", e.names())
	}
	// A lease that was lost writes none of it.
	l := e.lease
	l.Token++
	c.DNSRecord.Create().SetOrgID(e.zone.OrgID).SetDNSZoneID(e.zone.ID).SetName("stale2.example.com").SetType("A").SetContent("192.0.2.4").SetTTL(300).ExecX(e.sys)
	live, _ := e.prov.ListRecords(e.sys, e.zone.ProviderID)
	if _, err := e.eng.Relink(e.sys, l, e.zone, live, nil); !errors.Is(err, lease.ErrLost) {
		t.Fatalf("relink without the lease: %v", err)
	}
	if len(e.rows()) != 3 {
		t.Fatal("a replica that lost the lease changed the ledger")
	}
}

// TestDNS_DriftCorrectedThenStopped: a change someone else made to an owned record is put back and
// audited; the same record changed again within the stop window is marked drifted, left as the other
// tool wrote it, and reported; it is corrected again once it matches the ledger and changes outside
// the window, and a marker removed on its own is restored.
func TestDNS_DriftCorrectedThenStopped(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
		e.eng.Now = func() time.Time { return now }
		want := []dns.Record{a("a.example.com", "192.0.2.1"), a("b.example.com", "192.0.2.2")}
		if _, err := e.reconcile(want...); err != nil {
			t.Fatal(err)
		}
		a1 := e.byName("a.example.com")
		row := func(name string) *struct {
			state  dnsrecord.State
			reason string
		} {
			for _, r := range e.rows() {
				if r.Name == name {
					return &struct {
						state  dnsrecord.State
						reason string
					}{r.State, r.Reason}
				}
			}
			return nil
		}
		// 1: the first change is corrected.
		e.otherTool(a1, func(r *dns.Record) { r.Content = "198.51.100.1" })
		out, err := e.reconcile(want...)
		if err != nil || !slices.Equal(out.Report.Corrected, []string{"a.example.com"}) || len(out.Report.Drifted) != 0 {
			t.Fatalf("first drift: %+v %v", out, err)
		}
		if got := e.byName("a.example.com"); got.Content != "192.0.2.1" || got.Comment != a1.Comment || got.ID != a1.ID {
			t.Fatalf("not put back: %+v", got)
		}
		actions := []string{}
		for _, en := range e.audits() {
			if strings.HasPrefix(en.Action, "dns_record.") {
				actions = append(actions, en.Action)
			}
		}
		if !slices.Equal(actions[2:], []string{"dns_record.drift", "dns_record.update"}) {
			t.Fatalf("audit %v", actions)
		}
		// Nothing drifts, nothing is written.
		if out, err := e.reconcile(want...); err != nil || len(out.Report.Corrected)+len(out.Report.Drifted) != 0 || !out.Plan.Empty() {
			t.Fatalf("settled: %+v %v", out, err)
		}
		// 2: changed again within the window: no correction, drifted, reported.
		now = now.Add(10 * time.Minute)
		e.otherTool(a1, func(r *dns.Record) { r.Content = "198.51.100.2" })
		writes := e.fake.Count("POST")
		out, err = e.reconcile(want...)
		if err != nil || !slices.Equal(out.Report.Drifted, []string{"a.example.com"}) || len(out.Report.Corrected) != 0 || !out.Plan.Empty() {
			t.Fatalf("second drift: %+v %v", out, err)
		}
		if e.fake.Count("POST") != writes || e.byName("a.example.com").Content != "198.51.100.2" {
			t.Fatal("a record that drifted again was written")
		}
		if r := row("a.example.com"); r.state != dnsrecord.StateDrifted || !strings.Contains(r.reason, "stop window") {
			t.Fatalf("row %+v", r)
		}
		// Later passes stay away, also after the window, while it differs from the ledger.
		now = now.Add(3 * time.Hour)
		for range 2 {
			out, err = e.reconcile(want...)
			if err != nil || !slices.Equal(out.Report.Drifted, []string{"a.example.com"}) || e.byName("a.example.com").Content != "198.51.100.2" {
				t.Fatalf("stopped: %+v %v", out, err)
			}
		}
		// Its source going away still deletes it.
		if _, err := e.reconcile(want[1]); err != nil {
			t.Fatal(err)
		}
		if got := e.names(); !slices.Equal(got, []string{"b.example.com"}) {
			t.Fatalf("records %v", got)
		}
		// Put back by the other tool: in sync again, and a later change is corrected (outside the window).
		if _, err := e.reconcile(want...); err != nil {
			t.Fatal(err)
		}
		b1 := e.byName("b.example.com")
		e.otherTool(b1, func(r *dns.Record) { r.TTL = 60 })
		if out, err := e.reconcile(want...); err != nil || !slices.Equal(out.Report.Corrected, []string{"b.example.com"}) {
			t.Fatalf("ttl drift: %+v %v", out, err)
		}
		if e.byName("b.example.com").TTL != 300 {
			t.Fatal("ttl not put back")
		}
		now = now.Add(apply.StopWindow + time.Second)
		e.otherTool(e.byName("b.example.com"), func(r *dns.Record) { r.Content = "198.51.100.3" })
		if out, err := e.reconcile(want...); err != nil || !slices.Equal(out.Report.Corrected, []string{"b.example.com"}) || len(out.Report.Drifted) != 0 {
			t.Fatalf("a drift after the window: %+v %v", out, err)
		}
		// Drifted, then put back by the other tool to what the ledger holds: in sync again.
		now = now.Add(time.Minute)
		e.otherTool(e.byName("b.example.com"), func(r *dns.Record) { r.Content = "198.51.100.4" })
		if out, err := e.reconcile(want...); err != nil || !slices.Equal(out.Report.Drifted, []string{"b.example.com"}) {
			t.Fatalf("drift: %+v %v", out, err)
		}
		e.otherTool(e.byName("b.example.com"), func(r *dns.Record) { r.Content = "192.0.2.2" })
		if out, err := e.reconcile(want...); err != nil || len(out.Report.Drifted) != 0 || row("b.example.com").state != dnsrecord.StateSynced {
			t.Fatalf("recovered: %+v %v %+v", out, err, row("b.example.com"))
		}
		// A marker removed on its own is restored, once.
		now = now.Add(2 * time.Hour)
		e.otherTool(e.byName("b.example.com"), func(r *dns.Record) { r.Comment = "edited" })
		if out, err := e.reconcile(want...); err != nil || !slices.Equal(out.Report.Corrected, []string{"b.example.com"}) {
			t.Fatalf("marker: %+v %v", out, err)
		}
		if got := e.byName("b.example.com").Comment; !strings.HasPrefix(got, "rpmgr "+td+" dnr_") {
			t.Fatalf("marker %q", got)
		}
	})
}

// TestDNS_DriftIsNotASourceChange: a record changed by a source change (the plan's update) is not
// drift, and a change someone made to a record that the sources changed too is put back to what the
// sources want, not to the old value.
func TestDNS_DriftIsNotASourceChange(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	if _, err := e.reconcile(a("a.example.com", "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	out, err := e.reconcile(a("a.example.com", "192.0.2.7"))
	if err != nil || out.Result.Updated != 1 || len(out.Report.Corrected)+len(out.Report.Drifted) != 0 {
		t.Fatalf("a source change: %+v %v", out, err)
	}
	e.otherTool(e.byName("a.example.com"), func(r *dns.Record) { r.Content = "198.51.100.1" })
	out, err = e.reconcile(a("a.example.com", "192.0.2.8"))
	if err != nil || len(out.Report.Corrected) != 1 || e.byName("a.example.com").Content != "192.0.2.8" {
		t.Fatalf("%+v %v", out, err)
	}
	// Someone changes it to exactly what the sources want: nothing to write, and the ledger learns it.
	e.otherTool(e.byName("a.example.com"), func(r *dns.Record) { r.Content = "192.0.2.9" })
	writes := e.fake.Count("POST")
	if out, err := e.reconcile(a("a.example.com", "192.0.2.9")); err != nil || e.fake.Count("POST") != writes || len(out.Report.Corrected) != 0 {
		t.Fatalf("%+v %v", out, err)
	}
	if out, err := e.reconcile(a("a.example.com", "192.0.2.9")); err != nil || len(out.Report.Corrected)+len(out.Report.Drifted) != 0 {
		t.Fatalf("the ledger did not learn it: %+v %v", out, err)
	}
}

func planOf(want, live []dns.Record, owned []plan.Owned) plan.Plan {
	return plan.Diff(plan.Input{Zone: apex, Desired: want, Live: live, Owned: owned, TrustDomain: td})
}
