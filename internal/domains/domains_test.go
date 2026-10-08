// SPDX-License-Identifier: Apache-2.0

package domains_test

import (
	"errors"
	"strings"
	"testing"

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
