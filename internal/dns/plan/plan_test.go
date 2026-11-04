// SPDX-License-Identifier: Apache-2.0

package plan_test

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
)

const zone = "example.com"

func rec(id, typ, name, content string) dns.Record {
	return dns.Record{ID: id, Type: typ, Name: name, Content: content, TTL: 300}
}

func owned(ids ...string) []plan.Owned {
	var o []plan.Owned
	for _, id := range ids {
		o = append(o, plan.Owned{LedgerID: "dnr_" + id, RecordID: id})
	}
	return o
}

func diff(want, live []dns.Record, own ...string) plan.Plan {
	return plan.Diff(plan.Input{Zone: zone, Desired: want, Live: live, Owned: owned(own...), TrustDomain: "rpmgr-td"})
}

func names(rs []dns.Record) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID+":"+r.Type+" "+r.Name+" "+r.Content)
	}
	return out
}

func eq(t *testing.T, what string, got []dns.Record, want ...string) {
	t.Helper()
	if !slices.Equal(names(got), want) {
		t.Fatalf("%s: got %q, want %q", what, names(got), want)
	}
}

func TestDiff_CreateUpdateDelete(t *testing.T) {
	want := []dns.Record{rec("", "A", "new.example.com", "192.0.2.1"), rec("", "A", "same.example.com", "192.0.2.2"), rec("", "A", "ttl.example.com", "192.0.2.3"), rec("", "A", "move.example.com", "192.0.2.9")}
	want[2].TTL = 1
	want[2].Proxied = true
	live := []dns.Record{
		rec("r1", "A", "same.example.com", "192.0.2.2"),
		{ID: "r2", Type: "A", Name: "ttl.example.com", Content: "192.0.2.3", TTL: 300, Comment: "rpmgr rpmgr-td dnr_r2"},
		rec("r3", "A", "move.example.com", "192.0.2.4"),
		rec("r4", "A", "gone.example.com", "192.0.2.5"),
		rec("f1", "A", "foreign.example.com", "192.0.2.6"),
	}
	p := diff(want, live, "r1", "r2", "r3", "r4")
	eq(t, "creates", p.Creates, ":A new.example.com 192.0.2.1")
	eq(t, "updates", p.Updates, "r3:A move.example.com 192.0.2.9", "r2:A ttl.example.com 192.0.2.3")
	if u := p.Updates[1]; u.Comment != "rpmgr rpmgr-td dnr_r2" || !u.Proxied || u.TTL != 1 {
		t.Fatalf("an update keeps the marker: %+v", u)
	}
	eq(t, "deletes", p.Deletes, "r4:A gone.example.com 192.0.2.5")
	if len(p.Conflicts) != 0 || p.Empty() {
		t.Fatalf("%+v", p)
	}
	if !diff(want[1:2], live[:1], "r1").Empty() {
		t.Fatal("equal records give an empty plan")
	}
}

func TestDiff_AddressSetChanges(t *testing.T) {
	// CNAME to addresses: a delete and a create.
	p := diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1"), rec("", "AAAA", "a.example.com", "2001:db8::1")}, []dns.Record{rec("c", "CNAME", "a.example.com", "gw.example.net")}, "c")
	eq(t, "creates", p.Creates, ":A a.example.com 192.0.2.1", ":AAAA a.example.com 2001:db8::1")
	eq(t, "deletes", p.Deletes, "c:CNAME a.example.com gw.example.net")
	if len(p.Updates) != 0 {
		t.Fatal("a type change is not an update")
	}
	// A third address is a create, a dropped one a delete, a replaced one an update.
	p = diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1"), rec("", "A", "a.example.com", "192.0.2.2"), rec("", "A", "a.example.com", "192.0.2.3")},
		[]dns.Record{rec("1", "A", "a.example.com", "192.0.2.1"), rec("2", "A", "a.example.com", "192.0.2.9")}, "1", "2")
	eq(t, "creates", p.Creates, ":A a.example.com 192.0.2.3")
	eq(t, "updates", p.Updates, "2:A a.example.com 192.0.2.2")
	p = diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1")}, []dns.Record{rec("1", "A", "a.example.com", "192.0.2.1"), rec("2", "A", "a.example.com", "192.0.2.1")}, "1", "2")
	if len(p.Deletes) != 1 || len(p.Creates)+len(p.Updates) != 0 {
		t.Fatalf("a duplicate is deleted: %+v", p)
	}
	// IPv6 and CNAME spellings compare equal.
	p = diff([]dns.Record{rec("", "AAAA", "a.example.com", "2001:db8::1"), rec("", "CNAME", "b.example.com", "gw.example.net")},
		[]dns.Record{rec("1", "AAAA", "a.example.com", "2001:0db8:0:0:0:0:0:1"), rec("2", "CNAME", "B.example.com.", "GW.example.net.")}, "1", "2")
	if !p.Empty() {
		t.Fatalf("%+v", p)
	}
}

func TestDiff_ForeignAddressRecordIsConflict(t *testing.T) {
	for _, typ := range []string{"A", "AAAA", "CNAME"} {
		p := diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1")}, []dns.Record{rec("f", typ, "a.example.com", "x")})
		if !p.Empty() || len(p.Conflicts) != 1 || p.Conflicts[0].Kind != plan.ForeignAddress || p.Conflicts[0].Records[0].ID != "f" {
			t.Fatalf("%s: %+v", typ, p)
		}
	}
	// A foreign record beside an owned one still blocks the whole name.
	p := diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1")}, []dns.Record{rec("o", "A", "a.example.com", "192.0.2.7"), rec("f", "A", "a.example.com", "192.0.2.8")}, "o")
	if !p.Empty() || len(p.Conflicts) != 1 {
		t.Fatalf("%+v", p)
	}
	// Nothing is wanted there: the foreign record is left alone, with no conflict.
	if p := diff(nil, []dns.Record{rec("f", "A", "a.example.com", "x")}); !p.Empty() || len(p.Conflicts) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestDiff_OtherTypesCoexistAndCNAMEBesideMX(t *testing.T) {
	mx := rec("m", "MX", "a.example.com", "10 mail.example.com")
	txt := rec("t", "TXT", "a.example.com", "v=spf1 -all")
	p := diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1")}, []dns.Record{mx, txt})
	eq(t, "creates", p.Creates, ":A a.example.com 192.0.2.1")
	if len(p.Conflicts) != 0 || len(p.Deletes)+len(p.Updates) != 0 {
		t.Fatalf("%+v", p)
	}
	p = diff([]dns.Record{rec("", "CNAME", "a.example.com", "gw.example.net")}, []dns.Record{mx, txt})
	if !p.Empty() || len(p.Conflicts) != 1 || p.Conflicts[0].Kind != plan.CNAMEBesideData || len(p.Conflicts[0].Records) != 2 {
		t.Fatalf("%+v", p)
	}
	// An owned CNAME with a newly added MX next to it is a conflict too: no write.
	p = diff([]dns.Record{rec("", "CNAME", "a.example.com", "gw.example.net")}, []dns.Record{rec("c", "CNAME", "a.example.com", "old.example.net"), mx}, "c")
	if !p.Empty() || p.Conflicts[0].Kind != plan.CNAMEBesideData {
		t.Fatalf("%+v", p)
	}
}

func TestDiff_NSDelegationIsDelegated(t *testing.T) {
	ns := rec("n", "NS", "sub.example.com", "ns1.other.net")
	live := []dns.Record{ns, rec("apexns", "NS", "example.com", "ns1.cf.net"), rec("o", "A", "deep.sub.example.com", "192.0.2.9")}
	want := []dns.Record{rec("", "A", "sub.example.com", "192.0.2.1"), rec("", "A", "x.deep.sub.example.com", "192.0.2.1"), rec("", "A", "*.sub.example.com", "192.0.2.1"), rec("", "A", "fine.example.com", "192.0.2.1"), rec("", "A", "subx.example.com", "192.0.2.1")}
	p := diff(want, live, "o")
	eq(t, "creates", p.Creates, ":A fine.example.com 192.0.2.1", ":A subx.example.com 192.0.2.1")
	var got []string
	for _, c := range p.Conflicts {
		if c.Kind != plan.Delegated || len(c.Records) != 1 || c.Records[0].ID != "n" {
			t.Fatalf("%+v", c)
		}
		got = append(got, c.Name)
	}
	// The owned record under the delegation is neither deleted nor changed: it is not served anyway.
	if !slices.Equal(got, []string{"*.sub.example.com", "deep.sub.example.com", "sub.example.com", "x.deep.sub.example.com"}) || len(p.Deletes)+len(p.Updates) != 0 {
		t.Fatalf("%q %+v", got, p)
	}
	// The NS records of the apex are the zone's own and delegate nothing.
	if p := diff([]dns.Record{rec("", "A", "example.com", "192.0.2.1")}, []dns.Record{rec("apexns", "NS", "example.com", "ns1.cf.net")}); len(p.Conflicts) != 0 || len(p.Creates) != 1 {
		t.Fatalf("%+v", p)
	}
}

func TestDiff_KeepAndReservedAreUntouched(t *testing.T) {
	live := []dns.Record{rec("1", "A", "kept.example.com", "192.0.2.1"), rec("2", "A", "ctl.example.com", "192.0.2.2"), rec("3", "TXT", "_acme-challenge.a.example.com", "x"), rec("4", "A", "gone.example.com", "192.0.2.3")}
	p := plan.Diff(plan.Input{Zone: zone, Keep: []string{"KEPT.example.com."}, Reserved: []string{"ctl.example.com"},
		Desired: []dns.Record{rec("", "A", "kept.example.com", "192.0.2.77"), rec("", "A", "ctl.example.com", "192.0.2.77")},
		Live:    live, Owned: owned("1", "2", "3", "4")})
	eq(t, "deletes", p.Deletes, "4:A gone.example.com 192.0.2.3")
	if len(p.Creates)+len(p.Updates) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestDiff_TXT(t *testing.T) {
	c := "_rpmgr-challenge.new.example.com"
	// A provider may return a TXT value in quotes: equal, no update.
	p := diff([]dns.Record{rec("", "TXT", c, "v1")}, []dns.Record{rec("t", "TXT", c, `"v1"`)}, "t")
	if !p.Empty() {
		t.Fatalf("%+v", p)
	}
	// A foreign TXT at the name coexists; a claim that is gone deletes only the owned one.
	p = diff(nil, []dns.Record{rec("t", "TXT", c, "v1"), rec("f", "TXT", c, "other")}, "t")
	eq(t, "deletes", p.Deletes, "t:TXT _rpmgr-challenge.new.example.com v1")
	p = diff([]dns.Record{rec("", "TXT", c, "v2")}, []dns.Record{rec("f", "TXT", c, "other")})
	eq(t, "creates", p.Creates, ":TXT _rpmgr-challenge.new.example.com v2")
	p = diff([]dns.Record{rec("", "TXT", c, "v2")}, []dns.Record{rec("t", "TXT", c, "v1")}, "t")
	eq(t, "updates", p.Updates, "t:TXT _rpmgr-challenge.new.example.com v2")
}

func TestDiff_ShadowsLostAndOrphans(t *testing.T) {
	live := []dns.Record{
		rec("w", "A", "*.example.com", "192.0.2.1"),
		rec("ow", "A", "*.own.example.com", "192.0.2.1"),
		{ID: "o1", Type: "A", Name: "orphan.example.com", Content: "x", Comment: "rpmgr rpmgr-td dnr_unknown"},
		{ID: "o2", Type: "A", Name: "creating.example.com", Content: "x", Comment: "rpmgr rpmgr-td dnr_pending"},
		{ID: "o3", Type: "A", Name: "acme.example.com", Content: "x", Comment: "rpmgr rpmgr-td acme"},
		{ID: "o4", Type: "A", Name: "other.example.com", Content: "x", Comment: "rpmgr other-td dnr_unknown"},
		{ID: "o5", Type: "A", Name: "human.example.com", Content: "x", Comment: "rpmgr rpmgr-td dnr_unknown extra"},
		{ID: "o6", Type: "A", Name: "lost.example.com", Content: "x", Comment: "hello"},
	}
	in := plan.Input{Zone: zone, TrustDomain: "rpmgr-td", Live: live,
		Owned:   append(owned("ow", "gone"), plan.Owned{LedgerID: "dnr_pending"}),
		Desired: []dns.Record{rec("", "A", "shadow.example.com", "192.0.2.5"), rec("", "A", "x.own.example.com", "192.0.2.5"), rec("", "A", "gone.example.com", "192.0.2.5")}}
	p := plan.Diff(in)
	if !slices.Equal(p.Shadows, []string{"gone.example.com", "shadow.example.com"}) {
		t.Fatalf("shadows %q", p.Shadows)
	}
	if len(p.Orphans) != 1 || p.Orphans[0].ID != "o1" {
		t.Fatalf("orphans %+v", p.Orphans)
	}
	if len(p.Lost) != 1 || p.Lost[0].RecordID != "gone" {
		t.Fatalf("lost %+v", p.Lost)
	}
	if len(p.Creates) != 3 || len(p.Deletes) != 1 || p.Deletes[0].ID != "ow" {
		t.Fatalf("an orphan is never deleted: %+v", p)
	}
	in.TrustDomain = ""
	if len(plan.Diff(in).Orphans) != 0 {
		t.Fatal("no trust domain, no orphans")
	}
}

func shuffled(rng *rand.Rand, in plan.Input) plan.Input {
	in.Desired, in.Live, in.Owned = slices.Clone(in.Desired), slices.Clone(in.Live), slices.Clone(in.Owned)
	rng.Shuffle(len(in.Desired), func(a, b int) { in.Desired[a], in.Desired[b] = in.Desired[b], in.Desired[a] })
	rng.Shuffle(len(in.Live), func(a, b int) { in.Live[a], in.Live[b] = in.Live[b], in.Live[a] })
	rng.Shuffle(len(in.Owned), func(a, b int) { in.Owned[a], in.Owned[b] = in.Owned[b], in.Owned[a] })
	return in
}

func TestPlanHash(t *testing.T) {
	in := plan.Input{Zone: zone, TrustDomain: "td", Keep: []string{"k.example.com"},
		Desired: []dns.Record{rec("", "A", "a.example.com", "192.0.2.1"), rec("", "A", "a.example.com", "192.0.2.2"), rec("", "CNAME", "c.example.com", "gw.example.net"), rec("", "A", "n.example.com", "192.0.2.3"), rec("", "A", "d.example.com", "192.0.2.4"), rec("", "A", "sub.example.com", "192.0.2.4")},
		Live: []dns.Record{rec("1", "A", "a.example.com", "192.0.2.8"), rec("2", "A", "a.example.com", "192.0.2.9"), rec("3", "A", "gone.example.com", "192.0.2.1"), rec("4", "MX", "c.example.com", "10 m"), rec("5", "TXT", "c.example.com", "t"),
			rec("6", "A", "d.example.com", "x"), rec("7", "NS", "sub.example.com", "ns"), rec("8", "NS", "sub.example.com", "ns2"), {ID: "9", Type: "A", Name: "o.example.com", Content: "x", Comment: "rpmgr td dnr_z"}},
		Owned: owned("1", "2", "3")}
	want := plan.Diff(in)
	if len(want.Hash) != 64 || len(want.Creates) == 0 || len(want.Updates) == 0 || len(want.Deletes) == 0 || len(want.Conflicts) != 3 || len(want.Orphans) != 1 {
		t.Fatalf("the fixture must exercise every list: %+v", want)
	}
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 200; i++ {
		got := plan.Diff(shuffled(rng, in))
		if got.Hash != want.Hash || string(got.Encode()) != string(want.Encode()) {
			t.Fatalf("order changed the hash\n%s\n%s", got.Encode(), want.Encode())
		}
	}
	// Any change of the provider's records or the desired ones changes the hash.
	for name, mut := range map[string]func(*plan.Input){
		"desired": func(i *plan.Input) { i.Desired[0].Content = "192.0.2.99" },
		"live":    func(i *plan.Input) { i.Live[2].Content = "192.0.2.99" },
		"comment": func(i *plan.Input) { i.Live[2].Comment = "x" },
		"ttl":     func(i *plan.Input) { i.Desired[3].TTL = 5 },
		"foreign": func(i *plan.Input) { i.Live[3].Content = "20 m" },
	} {
		m := in
		m.Desired, m.Live = slices.Clone(m.Desired), slices.Clone(m.Live)
		mut(&m)
		if plan.Diff(m).Hash == want.Hash {
			t.Errorf("%s: the hash did not change", name)
		}
	}
	if !strings.HasPrefix(string(want.Encode()), plan.EncodingVersion+"\ncreate ") {
		t.Fatalf("%s", want.Encode())
	}
}

func TestPlanEncode_Golden(t *testing.T) {
	p := diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1")}, []dns.Record{rec("o", "A", "gone.example.com", "192.0.2.2"), rec("f", "A", "a.example.com", "x\"y")}, "o")
	want := "rpmgr-dns-plan/1\n" + `conflict "a.example.com" "foreign_address"` + "\n" + `conflict-record "a.example.com" "f" "A" "x\"y"` + "\n"
	want += ""
	got := string(plan.Plan{Conflicts: p.Conflicts}.Encode())
	if got != want {
		t.Fatalf("%q", got)
	}
	e := string(diff([]dns.Record{rec("", "A", "a.example.com", "192.0.2.1")}, nil).Encode())
	if e != "rpmgr-dns-plan/1\n"+`create "" "A" "a.example.com" "192.0.2.1" "300" "false" ""`+"\n" {
		t.Fatalf("%q", e)
	}
	if a, b := diff(nil, nil).Hash, diff(nil, nil).Hash; a != b || len(a) != 64 {
		t.Fatal("empty plan hash")
	}
}

// The property: over random zones, desired sets and ledgers, no write targets a record outside the
// ledger, nothing is written at a name with a foreign address record, beside a foreign record of a
// desired CNAME, below a delegation, at a kept or reserved name, and no plan creates a CNAME beside
// other data.
func TestDNS_ForeignRecordNeverModified(t *testing.T) {
	rng := rand.New(rand.NewSource(20261104))
	hosts := []string{"a.example.com", "b.example.com", "*.example.com", "sub.example.com", "x.sub.example.com", "ctl.example.com", "k.example.com", "_acme-challenge.a.example.com", "example.com"}
	types := []string{"A", "AAAA", "CNAME", "TXT", "MX", "NS"}
	for i := 0; i < 5000; i++ {
		var in plan.Input
		in.Zone, in.TrustDomain = zone, "td"
		in.Keep, in.Reserved = []string{"k.example.com"}, []string{"ctl.example.com"}
		isOwned := map[string]bool{}
		for j := rng.Intn(10); j > 0; j-- {
			id := fmt.Sprintf("r%d", j)
			r := dns.Record{ID: id, Type: types[rng.Intn(len(types))], Name: hosts[rng.Intn(len(hosts))], Content: fmt.Sprint(rng.Intn(3)), TTL: 300}
			if rng.Intn(3) == 0 {
				r.Comment = "rpmgr td dnr_" + fmt.Sprint(rng.Intn(3))
			}
			in.Live = append(in.Live, r)
			if rng.Intn(2) == 0 {
				isOwned[id] = true
				in.Owned = append(in.Owned, plan.Owned{LedgerID: "dnr_" + id, RecordID: id})
			}
		}
		for j := rng.Intn(6); j > 0; j-- {
			typ := []string{"A", "AAAA", "CNAME", "TXT"}[rng.Intn(4)]
			in.Desired = append(in.Desired, dns.Record{Type: typ, Name: hosts[rng.Intn(len(hosts))], Content: fmt.Sprint(rng.Intn(3)), TTL: 300})
		}
		p := plan.Diff(in)
		liveByID := map[string]dns.Record{}
		for _, r := range in.Live {
			liveByID[r.ID] = r
		}
		for _, r := range append(slices.Clone(p.Updates), p.Deletes...) {
			if !isOwned[r.ID] {
				t.Fatalf("iteration %d: wrote foreign record %+v\n%+v", i, r, in)
			}
			if liveByID[r.ID].Name != r.Name {
				t.Fatalf("iteration %d: a record moved to another name: %+v", i, r)
			}
		}
		for _, r := range p.Creates {
			if r.ID != "" {
				t.Fatalf("a create names a record: %+v", r)
			}
		}
		for _, r := range slices.Concat(p.Creates, p.Updates, p.Deletes) {
			if r.Name == "k.example.com" || r.Name == "ctl.example.com" || strings.Contains(r.Name, "_acme-challenge") {
				t.Fatalf("iteration %d: kept or reserved name written: %+v", i, r)
			}
			if r.Name == "sub.example.com" || r.Name == "x.sub.example.com" {
				if slices.ContainsFunc(in.Live, func(l dns.Record) bool { return l.Type == "NS" && l.Name == "sub.example.com" }) {
					t.Fatalf("iteration %d: written below a delegation: %+v", i, r)
				}
			}
		}
		for _, c := range p.Conflicts {
			if len(c.Records) == 0 {
				t.Fatalf("a conflict names a record: %+v", c)
			}
			for _, r := range slices.Concat(p.Creates, p.Updates, p.Deletes) {
				if r.Name == c.Name {
					t.Fatalf("iteration %d: wrote at conflicting name: %+v %+v", i, c, r)
				}
			}
		}
		// A foreign address record at a name with a create or update of address records.
		for _, r := range append(slices.Clone(p.Creates), p.Updates...) {
			for _, l := range in.Live {
				if l.Name == r.Name && !isOwned[l.ID] && (l.Type == "A" || l.Type == "AAAA" || l.Type == "CNAME") && (r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME") {
					t.Fatalf("iteration %d: wrote address records over foreign %+v: %+v", i, l, r)
				}
				if r.Type == "CNAME" && l.Name == r.Name && l.Type != "A" && l.Type != "AAAA" && l.Type != "CNAME" {
					t.Fatalf("iteration %d: CNAME created beside %+v", i, l)
				}
			}
		}
	}
}
