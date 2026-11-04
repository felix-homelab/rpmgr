// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package dnsadapter_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/dnsadapter"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const (
	token  = "a-token-of-the-test-0123456789"
	td     = "rpmgr-teststor"
	marker = "rpmgr " + td + " acme"
)

type env struct {
	t      *testing.T
	db     *store.DB
	sys    context.Context
	fake   *cftest.Server
	orgA   string
	orgB   string
	zoneA  *ent.DNSZone
	cfZone cftest.Zone
	ad     *dnsadapter.Adapter
}

func newEnv(t *testing.T, state dnszone.SyncState) *env {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	e := &env{t: t, db: db, sys: storetest.SystemCtx(t), fake: cftest.New(t, token)}
	e.orgA, e.orgB = storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
	kek, _ := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	sealer, _ := secret.NewSealer(kek)
	pid := ids.New("dnp")
	sealed, err := sealer.Seal(providers.SecretContext(pid), secret.New(token))
	if err != nil {
		t.Fatal(err)
	}
	db.Client().DNSProvider.Create().SetID(pid).SetOrgID(e.orgA).SetKind("cloudflare").SetName("cf").SetCredentialEnc(sealed).ExecX(e.sys)
	e.cfZone = e.fake.AddZone("example.com")
	e.zoneA = db.Client().DNSZone.Create().SetOrgID(e.orgA).SetDNSProviderID(pid).SetProviderZoneID(e.cfZone.ID).SetName("example.com").
		SetSyncState(state).SaveX(e.sys)
	e.ad = &dnsadapter.Adapter{DB: db, Sys: e.sys, Sealer: sealer, TrustDomain: td, Org: e.orgA,
		Dial: func(_, _ string, tok secret.Value) (dns.Provider, error) {
			return cloudflare.NewForTest(cloudflare.Config{Token: tok}, e.fake.URL(), e.fake.RootCAs())
		}}
	return e
}

func txt(name, text string) libdns.Record {
	return libdns.TXT{Name: name, TTL: time.Minute, Text: text}
}

func (e *env) records() []cftest.Record { return e.fake.Records(e.cfZone.ID) }

// The adapter writes the challenge TXT with the marker, and deletes exactly that record: not a
// record of another type at the name, nor one with the same text and another comment, nor one with the same comment and another text, nor one at
// another name.
func TestAdapter_WritesMarkedTXTAndDeletesOnlyAnExactMatch(t *testing.T) {
	e := newEnv(t, dnszone.SyncStateActive)
	const name = "_acme-challenge.app.example.com"
	keep := []cftest.Record{
		{Type: "TXT", Name: name, Content: "value", Comment: ""},                    // same content, no comment
		{Type: "TXT", Name: name, Content: "value", Comment: "rpmgr other-td acme"}, // another instance's
		{Type: "TXT", Name: "_acme-challenge.web.example.com", Content: "value", Comment: marker},
		{Type: "CNAME", Name: name, Content: "elsewhere.example.net", Comment: marker}, // not a TXT
	}
	for i := range keep {
		keep[i] = e.fake.AddRecord(e.cfZone.ID, keep[i])
	}
	ctx := context.Background()
	out, err := e.ad.AppendRecords(ctx, "example.com.", []libdns.Record{txt("_acme-challenge.app", "value")})
	if err != nil || len(out) != 1 {
		t.Fatalf("append: %v %v", out, err)
	}
	var mine []cftest.Record
	for _, r := range e.records() {
		if !slices.ContainsFunc(keep, func(k cftest.Record) bool { return k.ID == r.ID }) {
			mine = append(mine, r)
		}
	}
	if len(mine) != 1 || mine[0].Type != "TXT" || mine[0].Name != name || mine[0].Content != "value" || mine[0].Comment != marker || mine[0].TTL < 60 {
		t.Fatalf("the record written: %+v", mine)
	}
	// Another order's record at the name, with the marker but another text, appears meanwhile.
	keep = append(keep, e.fake.AddRecord(e.cfZone.ID, cftest.Record{Type: "TXT", Name: name, Content: "other-value", Comment: marker}))
	if _, err := e.ad.DeleteRecords(ctx, "example.com.", out); err != nil {
		t.Fatal(err)
	}
	if got := e.records(); len(got) != len(keep) {
		t.Fatalf("records after the delete: %+v, want the %d that are not the adapter's", got, len(keep))
	}
	for _, k := range keep {
		if !slices.ContainsFunc(e.records(), func(r cftest.Record) bool { return r.ID == k.ID }) {
			t.Errorf("%+v was deleted", k)
		}
	}
	// Deleting again is no error: the record is gone.
	if _, err := e.ad.DeleteRecords(ctx, "example.com.", out); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

// A provider that quotes the text of a TXT record still has it deleted.
func TestAdapter_DeletesQuotedTXT(t *testing.T) {
	e := newEnv(t, dnszone.SyncStateActive)
	e.fake.AddRecord(e.cfZone.ID, cftest.Record{Type: "TXT", Name: "_acme-challenge.example.com", Content: `"value"`, Comment: marker})
	if _, err := e.ad.DeleteRecords(context.Background(), "example.com", []libdns.Record{txt("_acme-challenge", "value")}); err != nil {
		t.Fatal(err)
	}
	if got := e.records(); len(got) != 0 {
		t.Fatalf("records %+v", got)
	}
}

// A held zone takes the challenge; a disabled zone, a zone of another org and a zone that is gone
// are refused before any request, for the write and for the delete.
func TestAdapter_ZoneRules(t *testing.T) {
	ctx := context.Background()
	rec := []libdns.Record{txt("_acme-challenge", "v")}
	t.Run("held", func(t *testing.T) {
		e := newEnv(t, dnszone.SyncStateHeld)
		if _, err := e.ad.AppendRecords(ctx, "example.com.", rec); err != nil {
			t.Fatal(err)
		}
	})
	for name, tc := range map[string]struct {
		setup func(*env)
		want  error
	}{
		"disabled":      {func(e *env) { e.zoneA.Update().SetSyncState(dnszone.SyncStateDisabled).ExecX(e.sys) }, dnsadapter.ErrZoneDisabled},
		"another org's": {func(e *env) { e.ad.Org = e.orgB }, dnsadapter.ErrZoneNotManaged},
		"removed":       {func(e *env) { e.db.Client().DNSZone.DeleteOneID(e.zoneA.ID).ExecX(e.sys) }, dnsadapter.ErrZoneNotManaged},
		"another zone":  {func(e *env) {}, dnsadapter.ErrZoneNotManaged},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, dnszone.SyncStateActive)
			tc.setup(e)
			zone := "example.com."
			if name == "another zone" {
				zone = "example.org."
			}
			if _, err := e.ad.AppendRecords(ctx, zone, rec); !errors.Is(err, tc.want) {
				t.Errorf("append: %v, want %v", err, tc.want)
			}
			if _, err := e.ad.DeleteRecords(ctx, zone, rec); !errors.Is(err, tc.want) {
				t.Errorf("delete: %v, want %v", err, tc.want)
			}
			if n := e.fake.Count(""); n != 0 {
				t.Errorf("%d requests went to the provider", n)
			}
		})
	}
}

// Only a TXT at an _acme-challenge name is written or deleted.
func TestAdapter_OnlyChallengeTXT(t *testing.T) {
	e := newEnv(t, dnszone.SyncStateActive)
	for name, rec := range map[string]libdns.Record{
		"another name": txt("www", "v"),
		"an A record":  libdns.Address{Name: "_acme-challenge", IP: netip.MustParseAddr("192.0.2.1")},
	} {
		if _, err := e.ad.AppendRecords(context.Background(), "example.com.", []libdns.Record{rec}); err == nil {
			t.Errorf("%s: written", name)
		}
		if _, err := e.ad.DeleteRecords(context.Background(), "example.com.", []libdns.Record{rec}); err == nil {
			t.Errorf("%s: deleted", name)
		}
	}
	if n := e.fake.Count("POST"); n != 0 || len(e.records()) != 0 {
		t.Errorf("the provider was asked to write: %d, %+v", n, e.records())
	}
}

// The zone of a name is the longest zone of the org that holds it, a wildcard counts by its base,
// and another org's zone is never found.
func TestZoneFor(t *testing.T) {
	e := newEnv(t, dnszone.SyncStateActive)
	c := e.db.Client()
	pid := e.zoneA.DNSProviderID
	c.DNSZone.Create().SetOrgID(e.orgA).SetDNSProviderID(pid).SetProviderZoneID("sub").SetName("sub.example.com").SetSyncState(dnszone.SyncStateHeld).ExecX(e.sys)
	pb := c.DNSProvider.Create().SetID(ids.New("dnp")).SetOrgID(e.orgB).SetKind("cloudflare").SetName("cf").SetCredentialEnc([]byte("x")).SaveX(e.sys).ID
	c.DNSZone.Create().SetOrgID(e.orgB).SetDNSProviderID(pb).SetProviderZoneID("b").SetName("example.org").SetSyncState(dnszone.SyncStateActive).ExecX(e.sys)
	for host, want := range map[string]string{
		"example.com": "example.com", "a.example.com": "example.com", "*.example.com": "example.com", "A.Example.COM.": "example.com",
		"a.sub.example.com": "sub.example.com", "*.sub.example.com": "sub.example.com", "sub.example.com": "sub.example.com",
	} {
		z, err := dnsadapter.ZoneFor(e.sys, c, e.orgA, host)
		if err != nil || z.Name != want {
			t.Errorf("%s: %v %v, want %s", host, z, err, want)
		}
	}
	for _, host := range []string{"app.example.org", "badexample.com", "com", "other.test"} {
		if _, err := dnsadapter.ZoneFor(e.sys, c, e.orgA, host); !errors.Is(err, dnsadapter.ErrZoneNotManaged) {
			t.Errorf("%s: %v, want ErrZoneNotManaged", host, err)
		}
	}
}

// A TXT that a crashed order left at the name, which carries the marker, is removed by the next
// order's write; records of others at the name are not.
func TestAdapter_RemovesAnEarlierOrdersLeftover(t *testing.T) {
	e := newEnv(t, dnszone.SyncStateActive)
	const name = "_acme-challenge.example.com"
	left := e.fake.AddRecord(e.cfZone.ID, cftest.Record{Type: "TXT", Name: name, Content: "old", Comment: marker})
	foreign := e.fake.AddRecord(e.cfZone.ID, cftest.Record{Type: "TXT", Name: name, Content: "foreign"})
	elsewhere := e.fake.AddRecord(e.cfZone.ID, cftest.Record{Type: "TXT", Name: "_acme-challenge.web.example.com", Content: "old", Comment: marker})
	if _, err := e.ad.AppendRecords(context.Background(), "example.com.", []libdns.Record{txt("_acme-challenge", "new")}); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range e.records() {
		ids = append(ids, r.ID+"="+r.Content)
	}
	if slices.ContainsFunc(e.records(), func(r cftest.Record) bool { return r.ID == left.ID }) {
		t.Errorf("the leftover stayed: %v", ids)
	}
	for _, k := range []cftest.Record{foreign, elsewhere} {
		if !slices.ContainsFunc(e.records(), func(r cftest.Record) bool { return r.ID == k.ID }) {
			t.Errorf("%+v was deleted", k)
		}
	}
	if len(e.records()) != 3 {
		t.Errorf("records %v, want the two of others and the new one", ids)
	}
}
