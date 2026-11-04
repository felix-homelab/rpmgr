// SPDX-License-Identifier: Apache-2.0

// Package compile turns the sources of one managed DNS zone into the records rpmgr wants there
// (docs/15-dns.md, "Publication rules"). It is a pure function of its input: no store, no API, no
// provider, no clock, so two replicas that read the same snapshot compute the same result and the
// same plan hash. The caller reads the sources in one transaction, hands over those that lie in
// the zone, and diffs Result.Desired against the provider with internal/dns/plan.
//
// The compiler is the first line of the same-org, reserved-name and proxy rules: a source of
// another org, a reserved name or a hostname the zone does not cover yields no record, whatever the
// caller passes in.
package compile

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dnsname"
)

// DefaultTTL is the TTL of a record that is not proxied, in seconds (docs/15-dns.md, "Timers and
// limits"). A proxied record has the provider's automatic TTL.
const (
	DefaultTTL = 300
	AutoTTL    = 1
)

// ChallengePrefix is the label of a pending claim's TXT record; see domains.ChallengeName. It is
// repeated here so that this package does not depend on the store.
const ChallengePrefix = "_rpmgr-challenge."

// acmeLabel is the label of certmagic's DNS-01 records, which are never written.
const acmeLabel = "_acme-challenge"

// State is the state of a zone.
type State string

// The states of a zone. A held zone computes the same records, and the job writes none of them
// until a plan is approved; a disabled zone publishes nothing and leaves its records alone.
const (
	StateActive   State = "active"
	StateHeld     State = "held"
	StateDisabled State = "disabled"
)

// Zone is the managed zone to compile for.
type Zone struct {
	Name  string // normalised, without a trailing dot
	OrgID string
	State State

	// The gates (docs/15-dns.md, rule 5). A zero Zone has every gate off, the safe default except
	// for PublishRouteHostnames, which the store defaults to on.
	PublishRouteHostnames bool
	AllowProxied          bool
	AllowWildcards        bool
}

// Target is where a gateway group's names point: one CNAME, or addresses. The zero Target is a
// group without a DNS target.
type Target struct {
	CNAME     string
	Addresses []netip.Addr
}

// Group is a gateway group and its DNS target.
type Group struct {
	ID     string
	Target Target
}

// RouteKind is the protocol of a route.
type RouteKind string

// The kinds of route. Only the first two have a hostname that is published.
const (
	HTTP           RouteKind = "http"
	TLSPassthrough RouteKind = "tls_passthrough"
	TCP            RouteKind = "tcp"
	UDP            RouteKind = "udp"
)

// Route is one hostname of a route.
type Route struct {
	OrgID    string
	Hostname string
	Kind     RouteKind
	GroupID  string
	Proxied  bool // the route's dns_proxied
}

// Name is an explicit DNS name that points at a gateway group.
type Name struct {
	OrgID   string
	Name    string
	GroupID string
}

// Domain is an org's domain claim. Only verified claims cover names.
type Domain struct {
	OrgID    string
	FQDN     string
	Wildcard bool
	Verified bool
}

// Claim is a pending domain claim whose challenge TXT is published.
type Claim struct {
	OrgID string
	FQDN  string
	Value string // the challenge value
}

// Input is everything the compiler reads.
type Input struct {
	Zone    Zone
	Groups  []Group
	Routes  []Route
	Names   []Name
	Domains []Domain
	Claims  []Claim

	// Reserved are names that are never written: the controller's public URL, its aliases, the
	// agent endpoints and gateway tunnel hostnames. Names with a `_acme-challenge` label are
	// reserved without being listed.
	Reserved []string

	// Published is the proxy state of the names that exist now, for a name whose routes disagree.
	Published map[string]bool
}

// Status is the compile-level outcome for one name.
type Status string

// The compile-level statuses. StatusOk, StatusNotManaged, StatusAmbiguous and StatusHeld are the user-facing dns_status of
// the same name; StatusNoTarget, StatusReserved and StatusNotVerified are shown as StatusNotManaged with their reason
// (docs/15-dns.md, "Compile result").
const (
	StatusOk          Status = "ok"
	StatusNotManaged  Status = "not_managed"
	StatusAmbiguous   Status = "ambiguous"
	StatusHeld        Status = "held"
	StatusNoTarget    Status = "no_target"
	StatusReserved    Status = "reserved"
	StatusNotVerified Status = "not_verified"
)

// Keeps reports whether the records already at a name stay as they are, because the compiler
// cannot say what they should be: they are neither created, changed nor deleted. A name with no
// source at all is not in the result, and its owned records are deleted.
func (s Status) Keeps() bool {
	switch s {
	case StatusAmbiguous, StatusHeld, StatusNoTarget, StatusReserved, StatusNotManaged:
		return true
	}
	return false
}

// Warning is a note on a name that is still published.
type Warning string

// ProxyDisagrees: the http routes on the name disagree on dns_proxied, so the name keeps its
// published proxy state.
const ProxyDisagrees Warning = "proxy_disagrees"

// NameResult is the outcome for one name that has a source in the zone.
type NameResult struct {
	Name     string
	Status   Status
	Warnings []Warning
	Claim    bool // the name is the challenge TXT of a pending claim
}

// Result is the compiled zone. Both lists are sorted.
type Result struct {
	// Desired are the records the zone should hold for the names with status StatusOk, without the
	// ownership marker. It is empty for a disabled zone.
	Desired []dns.Record
	Names   []NameResult
	// Held: the zone writes nothing until its plan is approved.
	Held bool
}

// Keep returns the names whose records the plan must leave alone, sorted.
func (r Result) Keep() []string {
	var out []string
	for _, n := range r.Names {
		if n.Status.Keeps() {
			out = append(out, n.Name)
		}
	}
	return out
}

// Compile computes the desired records of in.Zone. Sources of another org, names outside the zone
// and routes without a published hostname (tcp, udp) are skipped without a trace; a name that is
// invalid is skipped too, as the store never holds one.
func Compile(in Input) Result {
	z := in.Zone
	res := Result{Held: z.State == StateHeld}
	c := &compiler{in: in, groups: map[string]Target{}}
	for _, g := range in.Groups {
		c.groups[g.ID] = g.Target
	}
	srcs := c.collect()
	if z.State == StateDisabled {
		for _, name := range slices.Sorted(maps.Keys(srcs)) {
			res.Names = append(res.Names, NameResult{Name: name, Status: StatusNotManaged})
		}
		return res
	}
	for _, name := range slices.Sorted(maps.Keys(srcs)) {
		nr, recs := c.name(name, srcs[name])
		res.Names = append(res.Names, nr)
		res.Desired = append(res.Desired, recs...)
	}
	for _, cl := range c.claims() {
		res.Names = append(res.Names, NameResult{Name: cl.name, Status: StatusOk, Claim: true})
		res.Desired = append(res.Desired, cl.rec)
	}
	slices.SortFunc(res.Names, func(a, b NameResult) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(res.Desired, compareRecords)
	res.Desired = slices.CompactFunc(res.Desired, func(a, b dns.Record) bool { return compareRecords(a, b) == 0 })
	// The last guard: whatever the rules above did, a reserved name is never written.
	res.Desired = slices.DeleteFunc(res.Desired, func(r dns.Record) bool { return c.isReserved(r.Name) })
	return res
}

func compareRecords(a, b dns.Record) int {
	return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Type, b.Type), cmp.Compare(a.Content, b.Content))
}

type compiler struct {
	in     Input
	groups map[string]Target
}

// sources are what asks for one name.
type sources struct {
	dns    []string // group IDs of DNS names
	routes []Route  // http and tls_passthrough routes
}

// inZone reports whether name, which may start with "*.", is the zone or lies below it.
func (c *compiler) inZone(name string) bool {
	return name == c.in.Zone.Name || strings.HasSuffix(name, "."+c.in.Zone.Name)
}

func (c *compiler) collect() map[string]*sources {
	out := map[string]*sources{}
	get := func(org, raw string) *sources {
		if org == "" || org != c.in.Zone.OrgID {
			return nil // rule 1: the same org only
		}
		n, err := dnsname.Normalize(raw, true)
		if err != nil || !c.inZone(strings.TrimPrefix(n, "*.")) {
			return nil
		}
		if out[n] == nil {
			out[n] = &sources{}
		}
		return out[n]
	}
	for _, n := range c.in.Names {
		if s := get(n.OrgID, n.Name); s != nil {
			s.dns = append(s.dns, n.GroupID)
		}
	}
	for _, r := range c.in.Routes {
		if r.Kind != HTTP && r.Kind != TLSPassthrough {
			continue
		}
		if s := get(r.OrgID, r.Hostname); s != nil {
			s.routes = append(s.routes, r)
		}
	}
	return out
}

// isReserved reports whether name is never written (rule 6).
func (c *compiler) isReserved(name string) bool {
	return IsReserved(name, c.in.Reserved)
}

// IsReserved reports whether name is never written (rule 6): it is listed in reserved, or has a
// `_acme-challenge` label. The plan applies it to deletions as well.
func IsReserved(name string, reserved []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, r := range reserved {
		if strings.ToLower(strings.TrimSuffix(r, ".")) == name {
			return true
		}
	}
	return slices.Contains(strings.Split(name, "."), acmeLabel)
}

// covered reports whether a verified domain of the zone's org covers name (rule 2).
func (c *compiler) covered(name string) bool {
	for _, d := range c.in.Domains {
		if d.Verified && d.OrgID == c.in.Zone.OrgID && Covers(d.FQDN, d.Wildcard, name) {
			return true
		}
	}
	return false
}

// Covers reports whether a domain covers a normalised hostname: exactly its name, or with
// wildcard also every name below it. It is domains.Covers, repeated because that package depends
// on the store; a test keeps the two equal.
func Covers(fqdn string, wildcard bool, hostname string) bool {
	name := strings.TrimPrefix(hostname, "*.")
	starred := name != hostname
	if !starred && name == fqdn {
		return true
	}
	return wildcard && (name == fqdn && starred || strings.HasSuffix(name, "."+fqdn))
}

// name decides one name: its status and records.
func (c *compiler) name(name string, s *sources) (NameResult, []dns.Record) {
	z := c.in.Zone
	nr := NameResult{Name: name}
	switch {
	case c.isReserved(name):
		nr.Status = StatusReserved
		return nr, nil
	case strings.HasPrefix(name, "*.") && !z.AllowWildcards:
		nr.Status = StatusHeld
		return nr, nil
	case !c.covered(name):
		nr.Status = StatusNotVerified
		return nr, nil
	}
	groups := distinct(s.dns)
	byDNSName := len(groups) > 0
	if !byDNSName { // rule 3: a DNS name takes precedence over route hostnames
		if !z.PublishRouteHostnames {
			nr.Status = StatusNotManaged
			return nr, nil
		}
		for _, r := range s.routes {
			groups = append(groups, r.GroupID)
		}
		groups = distinct(groups)
	}
	if len(groups) > 1 {
		nr.Status = StatusAmbiguous
		return nr, nil
	}
	t := c.groups[groups[0]]
	if t.CNAME == "" && len(t.Addresses) == 0 {
		nr.Status = StatusNoTarget
		return nr, nil
	}
	nr.Status = StatusOk
	proxied := false
	if !byDNSName {
		var warn bool
		proxied, warn = c.proxy(name, s.routes)
		if warn {
			nr.Warnings = []Warning{ProxyDisagrees}
		}
	}
	return nr, records(name, t, proxied)
}

// proxy applies rule 7: proxied only if every route on the name is http with dns_proxied and the
// zone allows it; if the http routes disagree, the published state stays.
func (c *compiler) proxy(name string, routes []Route) (proxied, disagree bool) {
	if !c.in.Zone.AllowProxied {
		return false, false
	}
	var on, off int
	for _, r := range routes {
		switch {
		case r.Kind != HTTP:
			return false, false // tls_passthrough cannot be proxied: the provider ends TLS
		case r.Proxied:
			on++
		default:
			off++
		}
	}
	switch {
	case on > 0 && off > 0:
		return c.in.Published[name], true
	}
	return on > 0, false
}

func distinct(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}

// records returns the address records of a target: one CNAME, or an A or AAAA per address.
func records(name string, t Target, proxied bool) []dns.Record {
	ttl := DefaultTTL
	if proxied {
		ttl = AutoTTL
	}
	if t.CNAME != "" {
		return []dns.Record{{Type: "CNAME", Name: name, Content: strings.ToLower(strings.TrimSuffix(t.CNAME, ".")), TTL: ttl, Proxied: proxied}}
	}
	var out []dns.Record
	for _, a := range t.Addresses {
		a = a.Unmap()
		typ := "A"
		if a.Is6() {
			typ = "AAAA"
		}
		out = append(out, dns.Record{Type: typ, Name: name, Content: a.String(), TTL: ttl, Proxied: proxied})
	}
	return out
}

type claimRec struct {
	name string
	rec  dns.Record
}

// claims returns the challenge TXT of each pending claim of the zone's org (rule 2, exception).
func (c *compiler) claims() []claimRec {
	var out []claimRec
	for _, cl := range c.in.Claims {
		fqdn, err := dnsname.Normalize(cl.FQDN, false)
		if cl.OrgID == "" || cl.OrgID != c.in.Zone.OrgID || err != nil || cl.Value == "" {
			continue
		}
		name := ChallengePrefix + fqdn
		if !c.inZone(name) || c.isReserved(name) {
			continue
		}
		out = append(out, claimRec{name, dns.Record{Type: "TXT", Name: name, Content: cl.Value, TTL: DefaultTTL}})
	}
	slices.SortFunc(out, func(a, b claimRec) int { return compareRecords(a.rec, b.rec) })
	return slices.CompactFunc(out, func(a, b claimRec) bool { return a.name == b.name })
}
