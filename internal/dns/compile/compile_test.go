// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/compile"
	"github.com/felix-homelab/rpmgr/internal/domains"
)

const zoneName = "example.com"

func baseInput() compile.Input {
	return compile.Input{
		Zone:    compile.Zone{Name: zoneName, OrgID: "orgA", State: compile.StateActive, PublishRouteHostnames: true},
		Groups:  []compile.Group{{ID: "g1", Target: compile.Target{CNAME: "gw.example.net."}}, {ID: "g2", Target: compile.Target{Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}}}, {ID: "none"}},
		Domains: []compile.Domain{{OrgID: "orgA", FQDN: zoneName, Wildcard: true, Verified: true}},
	}
}

func route(host string, g string, kind compile.RouteKind, proxied bool) compile.Route {
	return compile.Route{OrgID: "orgA", Hostname: host, Kind: kind, GroupID: g, Proxied: proxied}
}

func status(t *testing.T, r compile.Result, name string) compile.NameResult {
	t.Helper()
	for _, n := range r.Names {
		if n.Name == name {
			return n
		}
	}
	t.Fatalf("no result for %s in %+v", name, r.Names)
	return compile.NameResult{}
}

func TestCompile_Targets(t *testing.T) {
	in := baseInput()
	in.Routes = []compile.Route{route("a.example.com", "g1", compile.HTTP, false), route("B.Example.com.", "g2", compile.TLSPassthrough, false)}
	r := compile.Compile(in)
	var got []string
	for _, d := range r.Desired {
		got = append(got, fmt.Sprintf("%s %s %s %d %v", d.Type, d.Name, d.Content, d.TTL, d.Proxied))
	}
	want := []string{
		"CNAME a.example.com gw.example.net 300 false",
		"A b.example.com 192.0.2.1 300 false",
		"AAAA b.example.com 2001:db8::1 300 false",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if r.Held || len(r.Keep()) != 0 {
		t.Fatal("not held, nothing kept")
	}
}

func TestCompile_GroupWithoutTargetPublishesNothing(t *testing.T) {
	in := baseInput()
	in.Routes = []compile.Route{route("a.example.com", "none", compile.HTTP, false), route("b.example.com", "missing", compile.HTTP, false)}
	in.Names = []compile.Name{{OrgID: "orgA", Name: "c.example.com", GroupID: "none"}}
	r := compile.Compile(in)
	if len(r.Desired) != 0 {
		t.Fatalf("%+v", r.Desired)
	}
	for _, n := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if s := status(t, r, n).Status; s != compile.StatusNoTarget || !s.Keeps() {
			t.Fatalf("%s: %s", n, s)
		}
	}
}

func TestCompile_DNSNameWinsAndAmbiguous(t *testing.T) {
	in := baseInput()
	in.Routes = []compile.Route{
		route("x.example.com", "g1", compile.HTTP, true), route("x.example.com", "g2", compile.HTTP, true), // no DNS name: ambiguous
		route("y.example.com", "g1", compile.HTTP, true), route("y.example.com", "g2", compile.HTTP, true), // DNS name decides
		route("z.example.com", "g1", compile.HTTP, false), route("z.example.com", "g1", compile.TLSPassthrough, false), // one group
	}
	in.Names = []compile.Name{{OrgID: "orgA", Name: "y.example.com", GroupID: "g2"}}
	in.Zone.AllowProxied = true
	r := compile.Compile(in)
	if s := status(t, r, "x.example.com").Status; s != compile.StatusAmbiguous {
		t.Fatal(s)
	}
	if !slices.Contains(r.Keep(), "x.example.com") {
		t.Fatal("ambiguous names keep their records")
	}
	for _, d := range r.Desired {
		switch d.Name {
		case "x.example.com":
			t.Fatalf("ambiguous name published: %+v", d)
		case "y.example.com":
			if d.Type == "CNAME" || d.Proxied {
				t.Fatalf("DNS name must win and be DNS-only: %+v", d)
			}
		}
	}
	if status(t, r, "y.example.com").Status != compile.StatusOk || status(t, r, "z.example.com").Status != compile.StatusOk {
		t.Fatal("y and z publish")
	}
	// Two DNS names for one name in two groups are ambiguous as well.
	in.Names = append(in.Names, compile.Name{OrgID: "orgA", Name: "y.example.com", GroupID: "g1"})
	if s := status(t, compile.Compile(in), "y.example.com").Status; s != compile.StatusAmbiguous {
		t.Fatal(s)
	}
}

func TestCompile_Gates(t *testing.T) {
	in := baseInput()
	in.Routes = []compile.Route{route("a.example.com", "g1", compile.HTTP, false), route("*.w.example.com", "g1", compile.HTTP, false)}
	in.Names = []compile.Name{{OrgID: "orgA", Name: "*.apps.example.com", GroupID: "g1"}, {OrgID: "orgA", Name: "d.example.com", GroupID: "g1"}}
	in.Claims = []compile.Claim{{OrgID: "orgA", FQDN: "q.example.com", Value: "v1"}}

	r := compile.Compile(in) // wildcards off
	for _, n := range []string{"*.w.example.com", "*.apps.example.com"} {
		if status(t, r, n).Status != compile.StatusHeld {
			t.Fatalf("%s must be held", n)
		}
	}
	in.Zone.AllowWildcards = true
	if status(t, compile.Compile(in), "*.w.example.com").Status != compile.StatusOk {
		t.Fatal("wildcard allowed")
	}

	in.Zone.PublishRouteHostnames = false
	r = compile.Compile(in)
	if status(t, r, "a.example.com").Status != compile.StatusNotManaged {
		t.Fatal("route hostnames off")
	}
	if status(t, r, "d.example.com").Status != compile.StatusOk || status(t, r, "_rpmgr-challenge.q.example.com").Status != compile.StatusOk {
		t.Fatal("DNS names and challenge TXTs still publish")
	}
}

func TestCompile_Coverage(t *testing.T) {
	in := baseInput()
	in.Domains = []compile.Domain{
		{OrgID: "orgA", FQDN: "exact.example.com", Verified: true},
		{OrgID: "orgA", FQDN: "pending.example.com", Wildcard: true},               // not verified
		{OrgID: "orgB", FQDN: "other.example.com", Wildcard: true, Verified: true}, // another org
	}
	in.Routes = []compile.Route{
		route("exact.example.com", "g1", compile.HTTP, false),
		route("sub.exact.example.com", "g1", compile.HTTP, false), // no wildcard
		route("a.pending.example.com", "g1", compile.HTTP, false),
		route("a.other.example.com", "g1", compile.HTTP, false),
	}
	r := compile.Compile(in)
	want := map[string]compile.Status{"exact.example.com": compile.StatusOk, "sub.exact.example.com": compile.StatusNotVerified, "a.pending.example.com": compile.StatusNotVerified, "a.other.example.com": compile.StatusNotVerified}
	for n, s := range want {
		if got := status(t, r, n).Status; got != s {
			t.Errorf("%s: %s, want %s", n, got, s)
		}
	}
	if len(r.Desired) != 1 || r.Desired[0].Name != "exact.example.com" {
		t.Fatalf("%+v", r.Desired)
	}
	if compile.StatusNotVerified.Keeps() {
		t.Fatal("records of an uncovered name are removed")
	}
}

func TestCompile_PendingClaimTXT(t *testing.T) {
	in := baseInput()
	in.Domains = nil // a pending claim needs no verified domain
	in.Claims = []compile.Claim{
		{OrgID: "orgA", FQDN: "new.example.com", Value: "val"},
		{OrgID: "orgA", FQDN: "new.example.com", Value: "val"}, // duplicate
		{OrgID: "orgA", FQDN: "elsewhere.org", Value: "v"},     // outside the zone
		{OrgID: "orgA", FQDN: "bad name", Value: "v"},          // invalid
		{OrgID: "orgA", FQDN: "empty.example.com", Value: ""},  // no value
		{OrgID: "orgA", FQDN: "example.com", Value: "apex"},    // the zone apex
	}
	r := compile.Compile(in)
	var got []string
	for _, d := range r.Desired {
		got = append(got, d.Type+" "+d.Name+" "+d.Content)
		if d.Proxied {
			t.Fatal("TXT is never proxied")
		}
	}
	want := []string{"TXT _rpmgr-challenge.example.com apex", "TXT _rpmgr-challenge.new.example.com val"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if !status(t, r, "_rpmgr-challenge.new.example.com").Claim {
		t.Fatal("claim flag")
	}
}

func TestDNS_CrossOrgPublishRefused_SameOrg(t *testing.T) {
	in := baseInput()
	in.Domains = append(in.Domains, compile.Domain{OrgID: "orgB", FQDN: "b.example.com", Wildcard: true, Verified: true})
	in.Routes = []compile.Route{
		{OrgID: "orgB", Hostname: "x.b.example.com", Kind: compile.HTTP, GroupID: "g1"},
		{OrgID: "orgB", Hostname: "mine.example.com", Kind: compile.HTTP, GroupID: "g1"},
		route("ok.example.com", "g1", compile.HTTP, false),
	}
	in.Names = []compile.Name{{OrgID: "orgB", Name: "n.b.example.com", GroupID: "g1"}, {OrgID: "", Name: "e.example.com", GroupID: "g1"}}
	in.Claims = []compile.Claim{{OrgID: "orgB", FQDN: "b.example.com", Value: "v"}}
	r := compile.Compile(in)
	if len(r.Desired) != 1 || r.Desired[0].Name != "ok.example.com" {
		t.Fatalf("another org's sources produced %+v", r.Desired)
	}
	if len(r.Names) != 1 {
		t.Fatalf("another org's names are not even listed: %+v", r.Names)
	}
	// A same-name source of another org does not turn a name ambiguous or change its target.
	in.Routes = append(in.Routes, compile.Route{OrgID: "orgB", Hostname: "ok.example.com", Kind: compile.HTTP, GroupID: "g2"})
	r = compile.Compile(in)
	if s := status(t, r, "ok.example.com").Status; s != compile.StatusOk || r.Desired[0].Type != "CNAME" {
		t.Fatalf("%s %+v", s, r.Desired)
	}
}

func TestDNS_ProxiedOnlyForHttp_Compiler(t *testing.T) {
	in := baseInput()
	in.Zone.AllowProxied = true
	in.Routes = []compile.Route{
		route("web.example.com", "g1", compile.HTTP, true),
		route("pass.example.com", "g2", compile.TLSPassthrough, true), // dns_proxied is ignored
		route("mix.example.com", "g1", compile.HTTP, true),
		route("mix.example.com", "g1", compile.TLSPassthrough, true), // the provider would end the TLS
		route("tcp.example.com", "g1", compile.TCP, true),
		route("udp.example.com", "g1", compile.UDP, true),
		route("off.example.com", "g1", compile.HTTP, false),
	}
	in.Names = []compile.Name{{OrgID: "orgA", Name: "dnsname.example.com", GroupID: "g1"}}
	in.Claims = []compile.Claim{{OrgID: "orgA", FQDN: "web.example.com", Value: "v"}}
	r := compile.Compile(in)
	proxied := map[string]bool{}
	for _, d := range r.Desired {
		if d.Proxied {
			proxied[d.Name] = true
			if d.TTL != compile.AutoTTL || (d.Type != "CNAME" && d.Type != "A" && d.Type != "AAAA") {
				t.Fatalf("%+v", d)
			}
		}
	}
	if len(proxied) != 1 || !proxied["web.example.com"] {
		t.Fatalf("only the http name is proxied: %v", proxied)
	}
	for _, n := range r.Names {
		if n.Name == "tcp.example.com" || n.Name == "udp.example.com" {
			t.Fatalf("tcp and udp hostnames are not published: %+v", n)
		}
	}
	// The zone must allow it.
	in.Zone.AllowProxied = false
	for _, d := range compile.Compile(in).Desired {
		if d.Proxied {
			t.Fatalf("zone does not allow proxying: %+v", d)
		}
	}
}

func TestCompile_ProxyConsensus(t *testing.T) {
	for _, pub := range []bool{false, true} {
		in := baseInput()
		in.Zone.AllowProxied = true
		in.Published = map[string]bool{"mix.example.com": pub}
		in.Routes = []compile.Route{route("mix.example.com", "g1", compile.HTTP, true), route("mix.example.com", "g1", compile.HTTP, false), route("all.example.com", "g1", compile.HTTP, true), route("all.example.com", "g1", compile.HTTP, true)}
		r := compile.Compile(in)
		for _, d := range r.Desired {
			if d.Name == "mix.example.com" && d.Proxied != pub {
				t.Fatalf("published %v: %+v", pub, d)
			}
			if d.Name == "all.example.com" && !d.Proxied {
				t.Fatal("all agree: proxied")
			}
		}
		if w := status(t, r, "mix.example.com").Warnings; !slices.Equal(w, []compile.Warning{compile.ProxyDisagrees}) {
			t.Fatalf("%v", w)
		}
		if len(status(t, r, "all.example.com").Warnings) != 0 {
			t.Fatal("no warning when they agree")
		}
	}
	// A disagreeing name in a zone that forbids the proxy is DNS-only, with no warning.
	in := baseInput()
	in.Published = map[string]bool{"mix.example.com": true}
	in.Routes = []compile.Route{route("mix.example.com", "g1", compile.HTTP, true), route("mix.example.com", "g1", compile.HTTP, false)}
	r := compile.Compile(in)
	if r.Desired[0].Proxied || len(r.Names[0].Warnings) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestCompile_ZoneStates(t *testing.T) {
	in := baseInput()
	in.Routes = []compile.Route{route("a.example.com", "g1", compile.HTTP, false)}
	in.Claims = []compile.Claim{{OrgID: "orgA", FQDN: "q.example.com", Value: "v"}}
	in.Zone.State = compile.StateHeld
	if r := compile.Compile(in); !r.Held || len(r.Desired) != 2 {
		t.Fatalf("a held zone compiles its plan: %+v", r)
	}
	in.Zone.State = compile.StateDisabled
	r := compile.Compile(in)
	if len(r.Desired) != 0 || r.Held || status(t, r, "a.example.com").Status != compile.StatusNotManaged || len(r.Keep()) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestCompile_OutsideZoneAndInvalid(t *testing.T) {
	in := baseInput()
	in.Routes = []compile.Route{
		route("a.notexample.com", "g1", compile.HTTP, false), // a suffix, not a subdomain
		route("a.other.org", "g1", compile.HTTP, false),
		route("not a name", "g1", compile.HTTP, false),
		route("10.0.0.1", "g1", compile.HTTP, false),
		route("", "g1", compile.HTTP, false),
	}
	r := compile.Compile(in)
	if len(r.Desired) != 0 || len(r.Names) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestCompile_Deterministic(t *testing.T) {
	in := baseInput()
	in.Zone.AllowWildcards = true
	in.Routes = []compile.Route{route("b.example.com", "g2", compile.HTTP, false), route("a.example.com", "g1", compile.HTTP, false), route("*.c.example.com", "g1", compile.HTTP, false)}
	in.Claims = []compile.Claim{{OrgID: "orgA", FQDN: "z.example.com", Value: "v"}}
	want := compile.Compile(in)
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // G404: a seeded, reproducible property test
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(in.Routes), func(a, b int) { in.Routes[a], in.Routes[b] = in.Routes[b], in.Routes[a] })
		in.Groups[1].Target.Addresses = []netip.Addr{in.Groups[1].Target.Addresses[1], in.Groups[1].Target.Addresses[0]}
		got := compile.Compile(in)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("order changed the result:\n%v\n%v", got, want)
		}
	}
	if !slices.IsSortedFunc(want.Desired, func(a, b dns.Record) int { return strings.Compare(a.Name+a.Type+a.Content, b.Name+b.Type+b.Content) }) {
		t.Fatal("not sorted")
	}
}

func TestCovers_MatchesDomains(t *testing.T) {
	for _, fqdn := range []string{"example.com", "a.example.com"} {
		for _, wc := range []bool{false, true} {
			for _, h := range []string{"example.com", "a.example.com", "*.example.com", "b.a.example.com", "*.a.example.com", "badexample.com", "com", "x.org"} {
				if compile.Covers(fqdn, wc, h) != domains.Covers(fqdn, wc, h) {
					t.Errorf("Covers(%q, %v, %q) differs from domains.Covers", fqdn, wc, h)
				}
			}
		}
	}
}

// randomInput builds an input from a small pool of names, including the reserved ones, so that
// collisions are frequent.
func randomInput(rng *rand.Rand, reserved []string) compile.Input {
	orgs := []string{"orgA", "orgB", ""}
	hosts := append([]string{"a.example.com", "b.example.com", "*.example.com", "*.apps.example.com", "x.apps.example.com", "_acme-challenge.example.com", "*._acme-challenge.example.com", "_acme-challenge.a.example.com", "example.com", "other.org", "example.com."}, reserved...)
	groups := []string{"g1", "g2", "none", "missing"}
	pick := func(s []string) string { return s[rng.Intn(len(s))] }
	in := baseInput()
	in.Zone.AllowWildcards, in.Zone.AllowProxied, in.Zone.PublishRouteHostnames = rng.Intn(2) == 0, rng.Intn(2) == 0, rng.Intn(4) != 0
	in.Zone.State = []compile.State{compile.StateActive, compile.StateHeld, compile.StateDisabled}[rng.Intn(3)]
	in.Reserved = reserved
	in.Published = map[string]bool{pick(hosts): true}
	in.Domains = []compile.Domain{{OrgID: "orgA", FQDN: "example.com", Wildcard: rng.Intn(2) == 0, Verified: rng.Intn(5) != 0}, {OrgID: "orgB", FQDN: "example.com", Wildcard: true, Verified: true}}
	kinds := []compile.RouteKind{compile.HTTP, compile.TLSPassthrough, compile.TCP, compile.UDP}
	for i := rng.Intn(8); i > 0; i-- {
		in.Routes = append(in.Routes, compile.Route{OrgID: pick(orgs), Hostname: pick(hosts), Kind: kinds[rng.Intn(4)], GroupID: pick(groups), Proxied: rng.Intn(2) == 0})
	}
	for i := rng.Intn(4); i > 0; i-- {
		in.Names = append(in.Names, compile.Name{OrgID: pick(orgs), Name: pick(hosts), GroupID: pick(groups)})
	}
	for i := rng.Intn(4); i > 0; i-- {
		in.Claims = append(in.Claims, compile.Claim{OrgID: pick(orgs), FQDN: pick(hosts), Value: "v"})
	}
	return in
}

func TestDNS_ReservedNamesNeverWritten(t *testing.T) {
	reserved := []string{"ctl.example.com", "alias.example.com", "agents.example.com"}
	rng := rand.New(rand.NewSource(20261104)) //nolint:gosec // G404: a seeded, reproducible property test
	for i := 0; i < 5000; i++ {
		in := randomInput(rng, reserved)
		for _, r := range []string{"ctl.example.com", "alias.example.com", "CTL.Example.com.", "agents.example.com"} {
			in.Routes = append(in.Routes, route(r, "g1", compile.HTTP, false))
			in.Names = append(in.Names, compile.Name{OrgID: "orgA", Name: r, GroupID: "g2"})
		}
		res := compile.Compile(in)
		for _, d := range res.Desired {
			if slices.Contains(reserved, d.Name) || slices.Contains(strings.Split(d.Name, "."), "_acme-challenge") {
				t.Fatalf("iteration %d wrote reserved name %+v\ninput %+v", i, d, in)
			}
		}
		for _, n := range res.Names {
			if slices.Contains(reserved, n.Name) && n.Status != compile.StatusReserved && in.Zone.State != compile.StateDisabled {
				t.Fatalf("iteration %d: %+v", i, n)
			}
		}
	}
	// The listed names are reported as reserved and kept, not deleted.
	in := baseInput()
	in.Reserved = []string{"ctl.example.com"}
	in.Routes = []compile.Route{route("ctl.example.com", "g1", compile.HTTP, false)}
	if r := compile.Compile(in); len(r.Desired) != 0 || r.Keep()[0] != "ctl.example.com" {
		t.Fatalf("%+v", r)
	}
}

// Every record of every random input is for the zone's org, under the zone, and an address
// record is never proxied unless the zone allows it.
func TestCompile_Invariants(t *testing.T) {
	rng := rand.New(rand.NewSource(7)) //nolint:gosec // G404: a seeded, reproducible property test
	for i := 0; i < 3000; i++ {
		in := randomInput(rng, nil)
		res := compile.Compile(in)
		if in.Zone.State == compile.StateDisabled && len(res.Desired) != 0 {
			t.Fatal("disabled zone")
		}
		for _, d := range res.Desired {
			if !strings.HasSuffix("."+d.Name, "."+zoneName) {
				t.Fatalf("outside the zone: %+v", d)
			}
			if d.Proxied && (!in.Zone.AllowProxied || d.Type == "TXT") {
				t.Fatalf("proxied: %+v", d)
			}
			if strings.HasPrefix(d.Name, "*.") && !in.Zone.AllowWildcards {
				t.Fatalf("wildcard: %+v", d)
			}
		}
	}
}
