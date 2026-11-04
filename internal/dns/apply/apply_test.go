// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package apply_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsprovider"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const (
	token = "a-token-of-the-test-0123456789"
	td    = "rpmgr-teststor"
	apex  = "example.com"
)

// env is one org with one zone at the fake provider, and the engine that writes it.
type env struct {
	t      *testing.T
	db     *store.DB
	sys    context.Context
	fake   *cftest.Server
	prov   dns.Provider
	zone   apply.Zone
	leases *lease.Leases
	lease  lease.Lease
	eng    *apply.Engine
}

func newEnv(t *testing.T, db *store.DB) *env {
	t.Helper()
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	fake := cftest.New(t, token)
	cz := fake.AddZone(apex)
	prov, err := cloudflare.NewForTest(cloudflare.Config{Token: secret.New(token)}, fake.URL(), fake.RootCAs())
	if err != nil {
		t.Fatal(err)
	}
	c := db.Client()
	dp := c.DNSProvider.Create().SetOrgID(org).SetKind(dnsprovider.KindCloudflare).SetName("cf").SetCredentialEnc([]byte("sealed")).SaveX(sys)
	z := c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(dp.ID).SetProviderZoneID(cz.ID).SetName(apex).SaveX(sys)
	leases := lease.New(db, "ctn_test", nil)
	l, ok, err := leases.TryAcquire(sys, "dns")
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	return &env{t: t, db: db, sys: sys, fake: fake, prov: prov, zone: apply.Zone{ID: z.ID, OrgID: org, Name: apex, ProviderID: cz.ID},
		leases: leases, lease: l, eng: &apply.Engine{DB: db, Leases: leases, TrustDomain: td}}
}

// pass lists the provider and the ledger, plans against want and applies.
func (e *env) pass(want []dns.Record) (apply.Result, plan.Plan, error) {
	e.t.Helper()
	live, err := e.prov.ListRecords(e.sys, e.zone.ProviderID)
	if err != nil {
		e.t.Fatal(err)
	}
	owned, err := apply.Owned(e.sys, e.db, e.zone.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	p := plan.Diff(plan.Input{Zone: apex, Desired: want, Live: live, Owned: owned, TrustDomain: td})
	res, err := e.eng.Apply(e.sys, e.lease, e.prov, e.zone, p)
	return res, p, err
}

func (e *env) rows() []*ent.DNSRecord {
	return e.db.Client().DNSRecord.Query().Where(dnsrecord.DNSZoneID(e.zone.ID)).Order(ent.Asc(dnsrecord.FieldName, dnsrecord.FieldContent)).AllX(e.sys)
}

func (e *env) audits() []audit.Entry {
	var out []audit.Entry
	rows, err := e.db.ReadClient().QueryContext(e.sys, `SELECT action, target_id, diff, actor_id FROM audit_log WHERE org_id = $1 ORDER BY seq`, e.zone.OrgID)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var en audit.Entry
		var actor string
		if err := rows.Scan(&en.Action, &en.TargetID, &en.Diff, &actor); err != nil {
			e.t.Fatal(err)
		}
		en.ActorID = actor
		out = append(out, en)
	}
	return out
}

func a(name, content string) dns.Record {
	return dns.Record{Type: "A", Name: name, Content: content, TTL: 300}
}

// TestApply_CreateUpdateDelete: creates are written through the ledger (the row first, the
// provider's ID after), later passes update and delete owned records, and every write is audited in
// the org's chain with the record before and after.
func TestApply_CreateUpdateDelete(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		res, _, err := e.pass([]dns.Record{a("a.example.com", "192.0.2.1"), a("b.example.com", "192.0.2.2")})
		if err != nil || res.Created != 2 || len(res.Failed) != 0 {
			t.Fatalf("create: %+v %v", res, err)
		}
		live := e.fake.Records(e.zone.ProviderID)
		rows := e.rows()
		if len(live) != 2 || len(rows) != 2 {
			t.Fatalf("%d records, %d rows", len(live), len(rows))
		}
		for _, r := range rows {
			var rec cftest.Record
			for _, l := range live {
				if l.Name == r.Name {
					rec = l
				}
			}
			if r.State != dnsrecord.StateSynced || r.ProviderRecordID == nil || *r.ProviderRecordID != rec.ID || r.LastSyncedAt == nil {
				t.Errorf("row %+v does not match record %+v", r, rec)
			}
			if rec.Comment != apply.Marker(td, r.ID) {
				t.Errorf("marker %q for row %s", rec.Comment, r.ID)
			}
		}

		// b changes its TTL, a goes away, c appears.
		b := a("b.example.com", "192.0.2.2")
		b.TTL = 120
		res, _, err = e.pass([]dns.Record{b, a("c.example.com", "192.0.2.3")})
		if err != nil || res.Created != 1 || res.Updated != 1 || res.Deleted != 1 {
			t.Fatalf("change: %+v %v", res, err)
		}
		got := e.fake.Records(e.zone.ProviderID)
		if len(got) != 2 || len(e.rows()) != 2 {
			t.Fatalf("%d records, %d rows", len(got), len(e.rows()))
		}
		for _, r := range got {
			if r.Name == "b.example.com" && (r.TTL != 120 || !strings.HasPrefix(r.Comment, "rpmgr "+td+" dnr_")) {
				t.Errorf("updated record %+v", r)
			}
		}
		var actions []string
		for _, en := range e.audits() {
			if strings.HasPrefix(en.Action, "dns_record.") {
				actions = append(actions, en.Action)
				if en.ActorID != apply.Actor || en.Diff == "" {
					t.Errorf("entry %+v", en)
				}
			}
		}
		if want := []string{"dns_record.create", "dns_record.create", "dns_record.delete", "dns_record.update", "dns_record.create"}; !slices.Equal(actions, want) {
			t.Errorf("audit actions %v, want %v", actions, want)
		}
		if _, err := audit.Verify(e.sys, db, e.zone.OrgID); err != nil {
			t.Errorf("the chain does not verify: %v", err)
		}
		// Nothing to do: a further pass writes nothing and audits nothing.
		n := len(e.audits())
		if res, p, err := e.pass([]dns.Record{b, a("c.example.com", "192.0.2.3")}); err != nil || !p.Empty() || res.Created+res.Updated+res.Deleted != 0 || len(e.audits()) != n {
			t.Fatalf("a settled zone: %+v %+v %v", res, p, err)
		}
	})
}

// TestDNS_BatchFallbackPerRecord: a batch with one invalid record fails all-or-nothing at the
// fake API; the retry applies every other record and marks only the failing name error. The failed
// row is reused, not duplicated, once the record is valid.
func TestDNS_BatchFallbackPerRecord(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		want := []dns.Record{a("a.example.com", "192.0.2.1"), a("bad.example.com", ""), a("c.example.com", "192.0.2.3")}
		res, _, err := e.pass(want)
		if err != nil {
			t.Fatal(err)
		}
		if res.Created != 2 || len(res.Failed) != 1 || res.Failed[0].Name != "bad.example.com" || !strings.Contains(res.Failed[0].Reason, "9005") {
			t.Fatalf("result %+v", res)
		}
		if reqs := e.fake.Count("POST /client/v4/zones/" + e.zone.ProviderID + "/dns_records/batch"); reqs != 1+3 {
			t.Fatalf("%d batch requests, want the batch and one per record", reqs)
		}
		var names []string
		for _, r := range e.fake.Records(e.zone.ProviderID) {
			names = append(names, r.Name)
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"a.example.com", "c.example.com"}) {
			t.Fatalf("provider records %v", names)
		}
		states := map[string]dnsrecord.State{}
		for _, r := range e.rows() {
			states[r.Name] = r.State
			if r.State == dnsrecord.StateError && (r.Reason == "" || r.ProviderRecordID != nil) {
				t.Errorf("failed row %+v", r)
			}
		}
		if states["a.example.com"] != dnsrecord.StateSynced || states["c.example.com"] != dnsrecord.StateSynced || states["bad.example.com"] != dnsrecord.StateError {
			t.Fatalf("states %v", states)
		}
		creates := 0
		for _, en := range e.audits() {
			if en.Action == "dns_record.create" {
				creates++
			}
		}
		if creates != 2 {
			t.Errorf("%d create entries for two writes", creates)
		}
		// The next pass retries the failed name; its row is reused.
		want[1].Content = "192.0.2.9"
		if res, _, err := e.pass(want); err != nil || res.Created != 1 || len(res.Failed) != 0 {
			t.Fatalf("retry: %+v %v", res, err)
		}
		if n := len(e.rows()); n != 3 {
			t.Fatalf("%d rows after the retry, want 3", n)
		}
		for _, r := range e.rows() {
			if r.State != dnsrecord.StateSynced {
				t.Errorf("row %+v", r)
			}
		}
	})
}

// TestApply_OneByOneProvider: a provider without batches gets every operation alone, and one
// refusal does not stop the others.
func TestApply_OneByOneProvider(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	e.prov = noBatch{e.prov}
	res, _, err := e.pass([]dns.Record{a("a.example.com", "192.0.2.1"), a("bad.example.com", ""), a("c.example.com", "192.0.2.3")})
	if err != nil || res.Created != 2 || len(res.Failed) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := e.fake.Count("POST"); n != 3 { // one request per operation
		t.Fatalf("%d writes", n)
	}
}

type noBatch struct{ dns.Provider }

func (noBatch) Caps() dns.Capabilities { return dns.Capabilities{Comments: true} }

type snapshot []cftest.Record

func (e *env) snapshot() snapshot { return e.fake.Records(e.zone.ProviderID) }

// TestDNS_FailStatic: with the provider unreachable, rate-limited or refusing the token, no record
// is deleted or changed, the pass stops at the first such answer (also in the middle of a pass or
// of the per-record retry), and the next successful pass converges.
func TestDNS_FailStatic(t *testing.T) {
	cases := []struct {
		name   string
		faults []cftest.Fault
		is     func(error) bool
		// requests is how many requests the pass may make before it stops.
		requests int
	}{
		{"401", []cftest.Fault{{Status: 401}}, func(e error) bool { return errors.Is(e, dns.ErrUnauthorized) }, 1},
		{"403", []cftest.Fault{{Status: 403}}, func(e error) bool { return errors.Is(e, dns.ErrForbidden) }, 1},
		{"429", []cftest.Fault{{Status: 429, RetryAfter: "60"}}, func(e error) bool { var r dns.RateLimited; return errors.As(e, &r) }, 1},
		{"500", []cftest.Fault{{Status: 500}}, func(e error) bool { var p *dns.ProviderError; return errors.As(e, &p) && p.Status == 500 }, 1},
		{"401 after the batch was refused", []cftest.Fault{{Status: 400}, {Status: 401}}, func(e error) bool { return errors.Is(e, dns.ErrUnauthorized) }, 2},
		{"429 in the retry", []cftest.Fault{{Status: 400}, {Status: 429, RetryAfter: "60"}}, func(e error) bool { var r dns.RateLimited; return errors.As(e, &r) }, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, storetest.Migrated(t, store.SQLite))
			if _, _, err := e.pass([]dns.Record{a("keep.example.com", "192.0.2.1"), a("gone.example.com", "192.0.2.2"), a("move.example.com", "192.0.2.3")}); err != nil {
				t.Fatal(err)
			}
			before, rowsBefore := e.snapshot(), len(e.rows())
			audits := len(e.audits())
			want := []dns.Record{a("keep.example.com", "192.0.2.1"), a("move.example.com", "192.0.2.4"), a("new.example.com", "192.0.2.5")}
			// The listing is a request of its own; the faults hit the writes.
			live, _ := e.prov.ListRecords(e.sys, e.zone.ProviderID)
			owned, _ := apply.Owned(e.sys, e.db, e.zone.ID)
			p := plan.Diff(plan.Input{Zone: apex, Desired: want, Live: live, Owned: owned, TrustDomain: td})
			requests := e.fake.Count("")
			e.fake.Fail(c.faults...)
			res, err := e.eng.Apply(e.sys, e.lease, e.prov, e.zone, p)
			if err == nil || !c.is(err) {
				t.Fatalf("error %v", err)
			}
			if res.Created+res.Updated+res.Deleted != 0 {
				t.Errorf("result %+v", res)
			}
			if got := e.snapshot(); !slices.Equal(got, before) {
				t.Fatalf("the provider changed:\n%+v\n%+v", before, got)
			}
			if n := e.fake.Count("") - requests; n != c.requests {
				t.Errorf("%d requests after the first fault, want %d", n, c.requests)
			}
			if len(e.audits()) != audits {
				t.Error("an audit entry for a write that did not happen")
			}
			if len(e.rows()) != rowsBefore+1 { // the write-ahead row of the create
				t.Errorf("%d rows", len(e.rows()))
			}
			// The next successful pass converges.
			if _, _, err := e.pass(want); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range e.snapshot() {
				got = append(got, r.Name+" "+r.Content)
			}
			slices.Sort(got)
			if !slices.Equal(got, []string{"keep.example.com 192.0.2.1", "move.example.com 192.0.2.4", "new.example.com 192.0.2.5"}) {
				t.Errorf("after the next pass: %v", got)
			}
			for _, r := range e.rows() {
				if r.State != dnsrecord.StateSynced {
					t.Errorf("row %+v", r)
				}
			}
		})
	}
}

// TestApply_StopsBetweenBatches: a 401 on the second of two batches keeps what the first wrote,
// recorded in the ledger, and sends nothing more.
func TestApply_StopsBetweenBatches(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	var want []dns.Record
	for i := range cloudflare.MaxBatchOps + 1 {
		want = append(want, a(fmt.Sprintf("h%03d.example.com", i), "192.0.2.1"))
	}
	live, owned := []dns.Record(nil), []plan.Owned(nil)
	p := plan.Diff(plan.Input{Zone: apex, Desired: want, Live: live, Owned: owned, TrustDomain: td})
	e.fake.Fail() // none
	var batches int
	e.eng.Guard = func(context.Context) error {
		if batches++; batches == 2 {
			e.fake.Fail(cftest.Fault{Status: 401})
		}
		return nil
	}
	res, err := e.eng.Apply(e.sys, e.lease, e.prov, e.zone, p)
	if !errors.Is(err, dns.ErrUnauthorized) || res.Created != cloudflare.MaxBatchOps {
		t.Fatalf("%+v %v", res, err)
	}
	if n := len(e.snapshot()); n != cloudflare.MaxBatchOps {
		t.Fatalf("%d records at the provider", n)
	}
	synced := 0
	for _, r := range e.rows() {
		if r.State == dnsrecord.StateSynced {
			synced++
		}
	}
	if synced != cloudflare.MaxBatchOps || len(e.rows()) != cloudflare.MaxBatchOps+1 {
		t.Fatalf("%d synced of %d rows", synced, len(e.rows()))
	}
}

// TestApply_FencedCommit: a replica that lost the lease writes no row. Lost before the write-ahead
// nothing is sent; lost while the batch is on its way, the ledger keeps its creating rows, records no
// audit entry, and returns lease.ErrLost, so the next holder links the records by marker.
func TestApply_FencedCommit(t *testing.T) {
	want := []dns.Record{a("a.example.com", "192.0.2.1")}
	t.Run("before the write-ahead", func(t *testing.T) {
		e := newEnv(t, storetest.Migrated(t, store.SQLite))
		e.lease.Token++
		_, _, err := e.pass(want)
		if !errors.Is(err, lease.ErrLost) || len(e.rows()) != 0 || e.fake.Count("POST") != 0 {
			t.Fatalf("%v, %d rows, %d writes", err, len(e.rows()), e.fake.Count("POST"))
		}
	})
	t.Run("during the batch", func(t *testing.T) {
		e := newEnv(t, storetest.Migrated(t, store.SQLite))
		e.eng.Guard = func(ctx context.Context) error {
			_, err := e.db.Client().ExecContext(ctx, "UPDATE leases SET fencing_token = fencing_token + 1")
			return err
		}
		_, _, err := e.pass(want)
		if !errors.Is(err, lease.ErrLost) {
			t.Fatalf("%v", err)
		}
		rows := e.rows()
		if len(rows) != 1 || rows[0].State != dnsrecord.StateCreating || rows[0].ProviderRecordID != nil {
			t.Fatalf("rows %+v", rows)
		}
		if len(e.snapshot()) != 1 {
			t.Fatal("the record was not written")
		}
		for _, en := range e.audits() {
			if strings.HasPrefix(en.Action, "dns_record.") {
				t.Errorf("an audit entry %+v for a commit that did not happen", en)
			}
		}
	})
}

// TestApply_Guard: a guard that refuses stops the pass before anything is sent; the write-ahead row
// stays.
func TestApply_Guard(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	refused := errors.New("lease ends too soon")
	e.eng.Guard = func(context.Context) error { return refused }
	_, _, err := e.pass([]dns.Record{a("a.example.com", "192.0.2.1")})
	if !errors.Is(err, refused) || e.fake.Count("POST") != 0 || len(e.snapshot()) != 0 {
		t.Fatalf("%v, %d writes", err, e.fake.Count("POST"))
	}
	if rows := e.rows(); len(rows) != 1 || rows[0].State != dnsrecord.StateCreating {
		t.Fatalf("rows %+v", rows)
	}
}

// TestApply_PlanNamesARecordWithoutARow: an update or a delete of a record that is not in the
// ledger is refused before anything is written, whatever the plan says.
func TestApply_PlanNamesARecordWithoutARow(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	foreign := e.fake.AddRecord(e.zone.ProviderID, cftest.Record{Type: "A", Name: "f.example.com", Content: "192.0.2.9", TTL: 300})
	for _, p := range []plan.Plan{
		{Deletes: []dns.Record{{ID: foreign.ID, Type: "A", Name: foreign.Name, Content: foreign.Content}}},
		{Updates: []dns.Record{{ID: foreign.ID, Type: "A", Name: foreign.Name, Content: "192.0.2.10", TTL: 300}}},
	} {
		before := e.snapshot()
		if _, err := e.eng.Apply(e.sys, e.lease, e.prov, e.zone, p); err == nil || !strings.Contains(err.Error(), "no ledger row") {
			t.Fatalf("error %v", err)
		}
		if !slices.Equal(e.snapshot(), before) || e.fake.Count("POST") != 0 {
			t.Fatal("a foreign record was written")
		}
	}
}

// TestApply_CommitSurvivesCancel: a pass cancelled after the provider was written still records it.
func TestApply_CommitSurvivesCancel(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	ctx, cancel := context.WithCancel(e.sys)
	e.eng.Guard = func(context.Context) error { return nil }
	e.prov = cancelAfterApply{e.prov, cancel}
	live, _ := e.prov.ListRecords(e.sys, e.zone.ProviderID)
	p := plan.Diff(plan.Input{Zone: apex, Desired: []dns.Record{a("a.example.com", "192.0.2.1")}, Live: live, TrustDomain: td})
	e.eng.Now = func() time.Time { return time.Now() }
	res, err := e.eng.Apply(ctx, e.lease, e.prov, e.zone, p)
	if res.Created != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if rows := e.rows(); len(rows) != 1 || rows[0].State != dnsrecord.StateSynced {
		t.Fatalf("rows %+v", rows)
	}
}

type cancelAfterApply struct {
	dns.Provider
	cancel context.CancelFunc
}

func (c cancelAfterApply) Apply(ctx context.Context, z string, b dns.Batch) error {
	err := c.Provider.Apply(ctx, z, b)
	c.cancel()
	return err
}

func (c cancelAfterApply) ListRecords(ctx context.Context, z string) ([]dns.Record, error) {
	return c.Provider.ListRecords(context.WithoutCancel(ctx), z)
}
