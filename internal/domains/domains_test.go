// SPDX-License-Identifier: Apache-2.0

package domains_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestNormalize: the one stored form of a name, and the names that are refused.
func TestNormalize(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wildcard bool
		want     string
	}{
		{"Example.COM", false, "example.com"},
		{"app.example.com.", false, "app.example.com"},
		{" app.example.com ", false, "app.example.com"},
		{"bücher.example", false, "xn--bcher-kva.example"},
		{"xn--bcher-kva.example", false, "xn--bcher-kva.example"},
		{"*.Example.com", true, "*.example.com"},
		{"a-b.c0.example", false, "a-b.c0.example"},
		{strings.Repeat("a", 63) + ".example", false, strings.Repeat("a", 63) + ".example"},
		{strings.Repeat(strings.Repeat("a", 60)+".", 4) + "example12", false, strings.Repeat(strings.Repeat("a", 60)+".", 4) + "example12"}, // 253
	} {
		got, err := domains.Normalize(tc.in, tc.wildcard)
		if err != nil || got != tc.want {
			t.Errorf("%q: %q %v, want %q", tc.in, got, err, tc.want)
		}
	}
	long := strings.Repeat(strings.Repeat("a", 60)+".", 4) + "example1234" // 255 characters
	for _, tc := range []struct {
		in       string
		wildcard bool
	}{
		{"", false}, {"com", false}, {".", false}, {"a..example", false}, {"-a.example", false}, {"a-.example", false},
		{"under_score.example", false}, {"192.0.2.1", false}, {"2001:db8::1", false}, {"[::1]", false},
		{strings.Repeat("a", 64) + ".example", false}, {long, false}, {"*.example.com", false}, {"*.*.example.com", true},
		{"a.*.example.com", true}, {"exa mple.com", false}, {"*", true},
	} {
		if got, err := domains.Normalize(tc.in, tc.wildcard); !errors.Is(err, domains.ErrInvalid) {
			t.Errorf("%q (wildcard %v): %q %v, want ErrInvalid", tc.in, tc.wildcard, got, err)
		}
	}
}

// TestCovers: exact claims cover their name, wildcard claims every name below at any depth, and
// labels never match partly.
func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		fqdn     string
		wildcard bool
		host     string
		want     bool
	}{
		{"example.com", false, "example.com", true},
		{"example.com", false, "app.example.com", false},
		{"example.com", false, "*.example.com", false},
		{"example.com", true, "example.com", true},
		{"example.com", true, "app.example.com", true},
		{"example.com", true, "a.b.c.example.com", true},
		{"example.com", true, "*.example.com", true},
		{"example.com", true, "*.app.example.com", true},
		{"example.com", true, "badexample.com", false},
		{"example.com", true, "example.com.evil.net", false},
		{"app.example.com", true, "example.com", false},
		{"app.example.com", false, "app.example.com", true},
	} {
		if got := domains.Covers(tc.fqdn, tc.wildcard, tc.host); got != tc.want {
			t.Errorf("%s (wildcard %v) covers %s: %v, want %v", tc.fqdn, tc.wildcard, tc.host, got, tc.want)
		}
	}
}

// TestClaimAndCovering: a name is claimed once in the instance, normalised, with a fresh challenge;
// only verified claims of the same org cover a hostname, the most specific first.
func TestClaimAndCovering(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		claim := func(org, name string, wildcard bool) (*ent.Domain, error) {
			var d *ent.Domain
			err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				d, err = domains.Claim(sys, tx, org, name, wildcard)
				return err
			})
			return d, err
		}
		wild, err := claim(orgA, "Example.com.", true)
		if err != nil || wild.Fqdn != "example.com" || wild.Status != domain.StatusPending || len(wild.ChallengeValue) != 32 {
			t.Fatalf("claim %+v %v", wild, err)
		}
		exact, err := claim(orgA, "app.example.com", false)
		if err != nil || exact.ChallengeValue == wild.ChallengeValue {
			t.Fatalf("a second claim %+v %v", exact, err)
		}
		if _, err := claim(orgB, "EXAMPLE.com", false); !errors.Is(err, domains.ErrTaken) {
			t.Fatalf("another org's claim on the same name: %v", err)
		}
		if _, err := claim(orgA, "not a name", false); !errors.Is(err, domains.ErrInvalid) {
			t.Fatalf("an invalid name: %v", err)
		}
		other, err := claim(orgB, "other.example", true)
		if err != nil {
			t.Fatal(err)
		}

		covering := func(org, host string) (string, error) {
			var id string
			err := store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
				d, err := domains.Covering(sys, tx, org, host)
				if err == nil {
					id = d.ID
				}
				return err
			})
			return id, err
		}
		if _, err := covering(orgA, "app.example.com"); !errors.Is(err, domains.ErrNotOwned) {
			t.Fatalf("a pending claim covers: %v", err)
		}
		db.Client().Domain.Update().Where(domain.IDIn(wild.ID, exact.ID, other.ID)).SetStatus(domain.StatusVerified).ExecX(sys)
		for host, want := range map[string]string{
			"app.example.com": exact.ID, "x.app.example.com": wild.ID, "*.example.com": wild.ID, "example.com": wild.ID,
			"API.Example.com.": wild.ID,
		} {
			if got, err := covering(orgA, host); err != nil || got != want {
				t.Errorf("%s: %s %v, want %s", host, got, err, want)
			}
		}
		for _, host := range []string{"badexample.com", "other.example", "x.other.example", "example.net"} {
			if got, err := covering(orgA, host); !errors.Is(err, domains.ErrNotOwned) {
				t.Errorf("%s: %s %v, want ErrNotOwned", host, got, err)
			}
		}
		if got, err := covering(orgB, "x.other.example"); err != nil || got != other.ID {
			t.Errorf("org-b's own domain: %s %v", got, err)
		}
		if _, err := covering(orgA, "under_score.example.com"); !errors.Is(err, domains.ErrInvalid) {
			t.Errorf("an invalid hostname: %v", err)
		}
	})
}

// TestConflicts: a name conflicts with another org's verified domain above or below it, whatever
// the wildcard flags, and with nothing else: not the same org's, not a pending or held claim, not
// a sibling or a name that merely ends alike.
func TestConflicts(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		add := func(org, name string, status domain.Status) {
			t.Helper()
			err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				d, err := domains.Claim(sys, tx, org, name, false)
				if err != nil {
					return err
				}
				return tx.Domain.UpdateOne(d).SetStatus(status).Exec(sys)
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		add(orgA, "example.com", domain.StatusVerified)
		add(orgA, "deep.a.b.test", domain.StatusVerified)
		add(orgA, "held.example", domain.StatusPendingApproval)
		add(orgA, "waiting.example", domain.StatusPending)
		for name, want := range map[string]bool{
			"app.example.com": true, "x.y.example.com": true, // nested under
			"b.test": true, "a.b.test": true, // containing
			"badexample.com": false, "example.org": false, "other.test": false, "deep.a.b.tes": false,
			"sub.held.example": false, "waiting.example": false, "x.waiting.example": false, // not verified
		} {
			var got bool
			err := store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
				var err error
				got, err = domains.Conflicts(sys, tx, orgB, name)
				return err
			})
			if err != nil || got != want {
				t.Errorf("%s: %v %v, want %v", name, got, err, want)
			}
		}
		err := store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
			if got, err := domains.Conflicts(sys, tx, orgA, "app.example.com"); err != nil || got {
				t.Errorf("the same org's nested name: %v %v", got, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// TestDNS_CrossOrgPublishRefused_Nested is the nested clause of TestDNS_CrossOrgPublishRefused
// (docs/12-testing-and-quality.md, "Security testing"): the DNS publication helpers act only for a
// verified claim, found by Covering, and a claim nested under another org's domain is not one
// until the Instance Admin approves it; approved, it covers names for its own org only. The
// publication clause, that no record reaches the other org's zone, comes with the DNS automation.
func TestDNS_CrossOrgPublishRefused_Nested(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		var parent, nested *ent.Domain
		err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			if parent, err = domains.Claim(sys, tx, orgA, "zone.example", true); err != nil {
				return err
			}
			if parent, err = domains.Record(sys, tx, parent, nil, time.Now()); err != nil {
				return err
			}
			if nested, err = domains.Claim(sys, tx, orgB, "app.zone.example", false); err != nil {
				return err
			}
			nested, err = domains.Record(sys, tx, nested, nil, time.Now())
			return err
		})
		if err != nil || parent.Status != domain.StatusVerified || nested.Status != domain.StatusPendingApproval || nested.VerifiedAt != nil {
			t.Fatalf("parent %v nested %v: %v", parent, nested, err)
		}
		covering := func(org, host string) error {
			return store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
				_, err := domains.Covering(sys, tx, org, host)
				return err
			})
		}
		if err := covering(orgB, "app.zone.example"); !errors.Is(err, domains.ErrNotOwned) {
			t.Fatalf("a held claim covers: %v", err)
		}
		db.Client().Domain.UpdateOneID(nested.ID).SetStatus(domain.StatusVerified).ExecX(sys)
		if err := covering(orgB, "app.zone.example"); err != nil {
			t.Fatalf("an approved claim: %v", err)
		}
		if err := covering(orgB, "other.zone.example"); !errors.Is(err, domains.ErrNotOwned) {
			t.Fatalf("an approved claim covers more than its name: %v", err)
		}
		if err := covering(orgA, "zone.example"); err != nil {
			t.Fatalf("the parent's own org: %v", err)
		}
	})
}

// TestChallengeFor (issue #1144): a claim carries the managed zone its name is in: the closest one
// of its own org, with the provider's name, the nameservers it assigned and whether its challenge
// is published (a synced ledger row), and none for a claim outside any zone, in a zone of another
// org, or checked by HTTP.
func TestChallengeFor(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		c := db.Client()
		prov := func(org string) string {
			return c.DNSProvider.Create().SetOrgID(org).SetKind("cloudflare").SetName("cf").SetCredentialEnc([]byte("x")).SaveX(sys).ID
		}
		pa, pb := prov(orgA), prov(orgB)
		zone := func(org, p, pz, name string, ns ...string) *ent.DNSZone {
			return c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(p).SetProviderZoneID(pz).SetName(name).SetAssignedNameservers(ns).SaveX(sys)
		}
		outer := zone(orgA, pa, "z1", "example.com", "ada.ns.example.net")
		inner := zone(orgA, pa, "z2", "eu.example.com", "bob.ns.example.net")
		zone(orgB, pb, "z3", "other.example", "cat.ns.example.net")
		claim := func(org, fqdn string, method domain.Method) *ent.Domain {
			return c.Domain.Create().SetOrgID(org).SetFqdn(fqdn).SetMethod(method).SetChallengeValue("cv").SaveX(sys)
		}

		d := claim(orgA, "app.eu.example.com", domain.MethodDNSTxt)
		got := domains.ChallengeWithZone(sys, c, d)
		if z := got.Zone; z == nil || z.Name != "eu.example.com" || z.Provider != "Cloudflare" || z.Published ||
			len(z.NameServers) != 1 || z.NameServers[0] != "bob.ns.example.net" {
			t.Fatalf("the closest zone: %+v", got.Zone)
		}
		if got.FQDN != d.Fqdn || got.Value != "cv" || got.ID != d.ID {
			t.Fatalf("the challenge: %+v", got)
		}

		// A synced ledger row at the challenge name is published; one that is not synced is not.
		rec := c.DNSRecord.Create().SetOrgID(orgA).SetDNSZoneID(inner.ID).SetName(domains.ChallengeName(d.Fqdn)).SetType("TXT").
			SetContent("cv").SetTTL(300).SaveX(sys)
		if got := domains.ChallengeWithZone(sys, c, d); got.Zone.Published {
			t.Fatal("a record that is still being created is published")
		}
		c.DNSRecord.UpdateOne(rec).SetState("synced").ExecX(sys)
		if got := domains.ChallengeWithZone(sys, c, d); !got.Zone.Published {
			t.Fatal("a synced record is not published")
		}

		if z := domains.ChallengeWithZone(sys, c, claim(orgA, "www.example.com", domain.MethodDNSTxt)).Zone; z == nil || z.Name != outer.Name {
			t.Fatalf("the outer zone: %+v", z)
		}
		for name, d := range map[string]*ent.Domain{
			"outside any zone":   claim(orgA, "app.example.org", domain.MethodDNSTxt),
			"a zone of another":  claim(orgA, "app.other.example", domain.MethodDNSTxt),
			"checked by HTTP":    claim(orgA, "web.example.com", domain.MethodHTTP),
			"not below the apex": claim(orgA, "badexample.com", domain.MethodDNSTxt),
		} {
			if z := domains.ChallengeWithZone(sys, c, d).Zone; z != nil {
				t.Errorf("%s: a zone %+v", name, z)
			}
		}
	})
}
