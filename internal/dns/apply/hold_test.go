// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"testing"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
)

func rec(name, typ string) dns.Record {
	return dns.Record{Name: name, Type: typ, Content: "x", TTL: 300}
}

// A removal is the loss of a name's address records; a replacement, a record of another type, or a
// record that is only changed is none.
func TestRemovals(t *testing.T) {
	cases := []struct {
		name string
		p    plan.Plan
		want int
	}{
		{"empty", plan.Plan{}, 0},
		{"one name, two records", plan.Plan{Deletes: []dns.Record{rec("a.example.com", "A"), rec("a.example.com", "AAAA")}}, 1},
		{"three names", plan.Plan{Deletes: []dns.Record{rec("a.example.com", "A"), rec("b.example.com", "CNAME"), rec("c.example.com", "AAAA")}}, 3},
		{"an address replaced by a CNAME", plan.Plan{Deletes: []dns.Record{rec("a.example.com", "A")}, Creates: []dns.Record{rec("a.example.com", "CNAME")}}, 0},
		{"one of two names replaced", plan.Plan{Deletes: []dns.Record{rec("a.example.com", "A"), rec("b.example.com", "A")}, Creates: []dns.Record{rec("a.example.com", "A")}}, 1},
		{"a TXT is no address", plan.Plan{Deletes: []dns.Record{rec("_acme-challenge.example.com", "TXT")}}, 0},
		{"a TXT created is no replacement", plan.Plan{Deletes: []dns.Record{rec("a.example.com", "A")}, Creates: []dns.Record{rec("a.example.com", "TXT")}}, 1},
		{"updates are no removal", plan.Plan{Updates: []dns.Record{rec("a.example.com", "A")}}, 0},
	}
	for _, c := range cases {
		if got := Removals(c.p); got != c.want {
			t.Errorf("%s: %d removals, want %d", c.name, got, c.want)
		}
	}
}

func TestGuard(t *testing.T) {
	two := plan.Plan{Hash: "h2", Deletes: []dns.Record{rec("a.example.com", "A"), rec("b.example.com", "A")}}
	none := plan.Plan{Hash: "h0", Creates: []dns.Record{rec("a.example.com", "A")}}
	for _, c := range []struct {
		name      string
		threshold int
		approved  string
		p         plan.Plan
		hold      string
		used      bool
	}{
		{"at the threshold", 2, "", two, "", false},
		{"above it", 1, "", two, HeldDeletionGuard, false},
		{"threshold 0 holds on one removal", 0, "", plan.Plan{Deletes: two.Deletes[:1]}, HeldDeletionGuard, false},
		{"threshold 0 lets a plan without removals pass", 0, "", none, "", false},
		{"approved passes whatever it removes", 0, "h2", two, "", true},
		{"approved, but another plan", 10, "h2", none, HeldPlanChanged, false},
		{"an approval is no leave to remove more", 10, "h0", two, HeldPlanChanged, false},
	} {
		hold, used := Guard(c.threshold, c.approved)(c.p)
		if hold != c.hold || used != c.used {
			t.Errorf("%s: hold %q used %v, want %q %v", c.name, hold, used, c.hold, c.used)
		}
	}
}
