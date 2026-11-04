// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package apply_test

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/compile"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestDNS_ForeignRecordNeverModified, end to end: over generated zones, foreign records and
// changing sources, the whole path (compile, plan, apply through the ledger, against the fake
// provider) never updates or deletes a record outside the ledger, and writes nothing at a name where
// a foreign address record, or foreign data beside a desired CNAME, is in the way. The plan-level
// clause is the test of the same name in internal/dns/plan.
func TestDNS_ForeignRecordNeverModified(t *testing.T) {
	e := newEnv(t, storetest.Migrated(t, store.SQLite))
	rng := rand.New(rand.NewSource(20261104)) //nolint:gosec // G404: a seeded test generator, not a secret
	pick := func(s []string) string { return s[rng.Intn(len(s))] }
	conflicts, creates, updates, deletes := 0, 0, 0, 0
	for i := range 40 {
		zoneName := fmt.Sprintf("z%d.example.com", i)
		z := e.addZone(zoneName)
		hosts := []string{"a." + zoneName, "b." + zoneName, "*." + zoneName, "sub." + zoneName, "x.sub." + zoneName, "ctl." + zoneName, zoneName}
		// Foreign records: the instance never wrote them. Some carry a marker of a ledger row that
		// does not exist.
		foreign := map[string]cftest.Record{}
		for range rng.Intn(8) {
			r := cftest.Record{Type: pick([]string{"A", "AAAA", "CNAME", "TXT", "MX", "NS"}), Name: pick(append(hosts, "d."+zoneName)), TTL: 300, Content: fmt.Sprintf("192.0.2.%d", 1+rng.Intn(3))}
			switch r.Type {
			case "AAAA":
				r.Content = "2001:db8::1"
			case "CNAME", "MX", "NS":
				r.Content = "other.example.net"
			case "TXT":
				r.Content = "v=test"
			}
			if rng.Intn(4) == 0 {
				r.Comment = "rpmgr " + td + " dnr_01ARZ3NDEKTSV4RRFFQ69G5FAV"
			}
			f := e.fake.AddRecord(z.ProviderID, r)
			foreign[f.ID] = f
		}
		for pass := range 3 {
			in := compile.Input{
				Zone:     compile.Zone{Name: zoneName, OrgID: "orgA", State: compile.StateActive, PublishRouteHostnames: true, AllowWildcards: true, AllowProxied: true},
				Groups:   []compile.Group{{ID: "g1", Target: compile.Target{CNAME: "gw.example.net."}}, {ID: "g2", Target: compile.Target{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.77"), netip.MustParseAddr("2001:db8::77")}}}},
				Domains:  []compile.Domain{{OrgID: "orgA", FQDN: zoneName, Wildcard: true, Verified: true}},
				Reserved: []string{"ctl." + zoneName},
			}
			for range rng.Intn(5) {
				in.Routes = append(in.Routes, compile.Route{OrgID: "orgA", Hostname: pick(hosts), Kind: compile.HTTP, GroupID: pick([]string{"g1", "g2"}), Proxied: rng.Intn(2) == 0})
			}
			for range rng.Intn(3) {
				in.Names = append(in.Names, compile.Name{OrgID: "orgA", Name: pick(hosts), GroupID: pick([]string{"g1", "g2"})})
			}
			cr := compile.Compile(in)
			live, err := e.prov.ListRecords(e.sys, z.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := apply.Owned(e.sys, e.db, z.ID)
			if err != nil {
				t.Fatal(err)
			}
			p := plan.Diff(plan.Input{Zone: zoneName, Desired: cr.Desired, Keep: cr.Keep(), Reserved: in.Reserved, Live: live, Owned: owned, TrustDomain: td})
			res, err := e.eng.Apply(e.sys, e.lease, e.prov, z, p)
			if err != nil || len(res.Failed) != 0 {
				t.Fatalf("zone %d pass %d: %+v %v", i, pass, res, err)
			}
			conflicts += len(p.Conflicts)
			creates, updates, deletes = creates+len(p.Creates), updates+len(p.Updates), deletes+len(p.Deletes)

			after := map[string]cftest.Record{}
			for _, r := range e.fake.Records(z.ProviderID) {
				after[r.ID] = r
			}
			for id, f := range foreign {
				if after[id] != f {
					t.Fatalf("zone %d pass %d: foreign record %+v became %+v (present: %v)", i, pass, f, after[id], after[id].ID != "")
				}
			}
			for id, r := range after {
				if _, ok := foreign[id]; !ok && !strings.HasPrefix(r.Comment, "rpmgr "+td+" dnr_") {
					t.Fatalf("zone %d pass %d: a record written without a marker: %+v", i, pass, r)
				}
			}
			for _, c := range p.Conflicts { // nothing changes at a name in conflict
				var was, now []string
				for _, r := range live {
					if r.Name == c.Name {
						was = append(was, r.ID+r.Content+r.Comment)
					}
				}
				for _, r := range after {
					if r.Name == c.Name {
						now = append(now, r.ID+r.Content+r.Comment)
					}
				}
				slices.Sort(was)
				slices.Sort(now)
				if !slices.Equal(was, now) {
					t.Fatalf("zone %d pass %d: %s is in conflict and changed: %v -> %v", i, pass, c.Name, was, now)
				}
			}
			for _, r := range after {
				if r.Name == "ctl."+zoneName && !slices.Contains(foreignIDs(foreign), r.ID) {
					t.Fatalf("a reserved name was written: %+v", r)
				}
			}
		}
	}
	if conflicts == 0 || creates == 0 || updates == 0 || deletes == 0 {
		t.Fatalf("the generator is too tame: %d conflicts, %d creates, %d updates, %d deletes", conflicts, creates, updates, deletes)
	}
}

func foreignIDs(m map[string]cftest.Record) []string {
	var out []string
	for id := range m {
		out = append(out, id)
	}
	return out
}

// addZone adds a zone to the fake provider and to the database, in the env's org.
func (e *env) addZone(name string) apply.Zone {
	cz := e.fake.AddZone(name)
	prov := e.db.Client().DNSProvider.Query().OnlyX(e.sys)
	z := e.db.Client().DNSZone.Create().SetOrgID(e.zone.OrgID).SetDNSProviderID(prov.ID).SetProviderZoneID(cz.ID).SetName(name).SaveX(e.sys)
	return apply.Zone{ID: z.ID, OrgID: e.zone.OrgID, Name: name, ProviderID: cz.ID}
}

var _ dns.Record
