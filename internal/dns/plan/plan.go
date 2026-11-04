// SPDX-License-Identifier: Apache-2.0

// Package plan diffs the desired records of a zone (internal/dns/compile) against the records the
// provider holds, by the conflict table of docs/15-dns.md. It is a pure function: it reads no
// provider and no ledger, writes nothing and has no clock. The caller lists the zone's records,
// reads the ownership ledger, and applies the plan through the ledger (slice 6.10).
//
// The one rule that matters: a plan changes or deletes only a record that is in the ledger. A
// foreign record is read, reported as a conflict where it is in the way, and never written.
package plan

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/compile"
)

// Owned is one row of the ownership ledger: a record rpmgr may change or delete.
type Owned struct {
	LedgerID string // the ID in the record's marker comment
	RecordID string // the provider's record ID; empty while the row is being created
}

// Input is everything the planner reads.
type Input struct {
	Zone     string       // the zone's name, normalised
	Desired  []dns.Record // compile.Result.Desired
	Keep     []string     // compile.Result.Keep(): names whose records stay as they are
	Reserved []string     // names that are never written, not even deleted
	Live     []dns.Record // every record of the zone at the provider
	Owned    []Owned      // the zone's ledger rows
	// TrustDomain is this instance's trust domain, for the marker of an orphan.
	TrustDomain string
}

// ConflictKind says why a name cannot be written.
type ConflictKind string

// The conflicts of docs/15-dns.md, "Conflicts".
const (
	// ForeignAddress: a foreign A, AAAA or CNAME record occupies a name that wants address records.
	ForeignAddress ConflictKind = "foreign_address"
	// CNAMEBesideData: the name wants a CNAME and other data (TXT, MX, ...) is there, which a CNAME
	// cannot share a name with.
	CNAMEBesideData ConflictKind = "cname_beside_data"
	// Delegated: an NS delegation at or above the name, inside the zone, means the records would not
	// be served. Shown to the user as `conflict` with the reason delegated.
	Delegated ConflictKind = "delegated"
)

// Conflict is a name the plan does not write, and the records that are in the way.
type Conflict struct {
	Name    string
	Kind    ConflictKind
	Records []dns.Record // the foreign records, or the NS records of the delegation
}

// Plan is what a pass would do. Every list is sorted. Hash identifies the plan (see Encode).
type Plan struct {
	Creates []dns.Record // no ID
	Updates []dns.Record // ID of an owned record; every field is the new one, Comment kept
	Deletes []dns.Record // owned records, as they are now
	// Conflicts are names the plan leaves alone.
	Conflicts []Conflict
	// Orphans are live records with this instance's marker and no ledger row. They are reported,
	// never deleted.
	Orphans []dns.Record
	// Shadows are created names that a foreign wildcard record covers today; the name stops
	// following the wildcard.
	Shadows []string
	// Lost are ledger rows whose record is gone at the provider; a desired record is created again.
	Lost []Owned
	Hash string
}

// Empty reports whether the plan writes nothing.
func (p Plan) Empty() bool { return len(p.Creates)+len(p.Updates)+len(p.Deletes) == 0 }

func isAddr(t string) bool { return t == "A" || t == "AAAA" || t == "CNAME" }

func canonName(n string) string { return strings.ToLower(strings.TrimSuffix(n, ".")) }

// canon returns the content of r in the form records are compared in.
func canon(r dns.Record) string {
	c := r.Content
	switch r.Type {
	case "A", "AAAA":
		if a, err := netip.ParseAddr(strings.TrimSpace(c)); err == nil {
			return a.Unmap().String()
		}
	case "CNAME", "NS":
		return canonName(c)
	case "TXT": // a provider may return the value inside quotes
		if len(c) >= 2 && c[0] == '"' && c[len(c)-1] == '"' {
			return c[1 : len(c)-1]
		}
	}
	return c
}

func compare(a, b dns.Record) int {
	return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Type, b.Type), cmp.Compare(canon(a), canon(b)), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Content, b.Content), cmp.Compare(a.TTL, b.TTL), cmp.Compare(a.Comment, b.Comment), boolCmp(a.Proxied, b.Proxied))
}

func boolCmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
}

// Diff computes the plan.
func Diff(in Input) Plan {
	var p Plan
	owned := map[string]bool{}
	ledger := map[string]bool{}
	for _, o := range in.Owned {
		if o.RecordID != "" {
			owned[o.RecordID] = true
		}
		ledger[o.LedgerID] = true
	}
	keep := map[string]bool{}
	for _, k := range in.Keep {
		keep[canonName(k)] = true
	}

	live := map[string][]dns.Record{} // by name
	seen := map[string]bool{}
	for _, r := range in.Live {
		r.Name = canonName(r.Name)
		live[r.Name] = append(live[r.Name], r)
		if r.ID != "" {
			seen[r.ID] = true
		}
		if id, ok := marker(r.Comment, in.TrustDomain); ok && !owned[r.ID] && !ledger[id] {
			p.Orphans = append(p.Orphans, r)
		}
	}
	for _, o := range in.Owned {
		if o.RecordID != "" && !seen[o.RecordID] {
			p.Lost = append(p.Lost, o)
		}
	}
	want := map[string][]dns.Record{}
	for _, r := range in.Desired {
		r.Name = canonName(r.Name)
		want[r.Name] = append(want[r.Name], r)
	}

	// The names to look at: the desired ones, and those that hold an owned record.
	names := map[string]bool{}
	for n := range want {
		names[n] = true
	}
	for n, rs := range live {
		if slices.ContainsFunc(rs, func(r dns.Record) bool { return owned[r.ID] }) {
			names[n] = true
		}
	}
	delegations := delegationsOf(in.Zone, live)
	for _, name := range slices.Sorted(keysOf(names)) {
		if keep[name] || compile.IsReserved(name, in.Reserved) {
			continue
		}
		if d := delegation(name, delegations); len(d) > 0 {
			p.Conflicts = append(p.Conflicts, Conflict{Name: name, Kind: Delegated, Records: d})
			continue
		}
		planName(&p, in.Zone, name, want[name], live[name], owned, live)
	}

	for _, l := range []*[]dns.Record{&p.Creates, &p.Updates, &p.Deletes, &p.Orphans} {
		slices.SortFunc(*l, compare)
	}
	for i := range p.Conflicts {
		slices.SortFunc(p.Conflicts[i].Records, compare)
	}
	slices.SortFunc(p.Conflicts, func(a, b Conflict) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Kind, b.Kind)) })
	slices.Sort(p.Shadows)
	slices.SortFunc(p.Lost, func(a, b Owned) int {
		return cmp.Or(cmp.Compare(a.LedgerID, b.LedgerID), cmp.Compare(a.RecordID, b.RecordID))
	})
	p.Hash = p.hash()
	return p
}

func keysOf[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// marker returns the ledger ID of a record's marker comment, `rpmgr <trust-domain> <ledger ID>`.
// The marker of the ACME solver (`rpmgr <trust-domain> acme`) is not a ledger ID.
func marker(comment, td string) (string, bool) {
	f := strings.Fields(comment)
	if len(f) != 3 || f[0] != "rpmgr" || f[1] != td || td == "" || f[2] == "acme" {
		return "", false
	}
	return f[2], true
}

// delegationsOf returns the NS records below the zone apex by name: each starts a delegation.
func delegationsOf(zone string, live map[string][]dns.Record) map[string][]dns.Record {
	out := map[string][]dns.Record{}
	for n, rs := range live {
		if n == zone {
			continue
		}
		for _, r := range rs {
			if r.Type == "NS" {
				out[n] = append(out[n], r)
			}
		}
	}
	return out
}

// delegation returns the NS records of the closest delegation at or above name.
func delegation(name string, d map[string][]dns.Record) []dns.Record {
	n := strings.TrimPrefix(name, "*.")
	for {
		if rs := d[n]; len(rs) > 0 {
			return rs
		}
		_, rest, ok := strings.Cut(n, ".")
		if !ok {
			return nil
		}
		n = rest
	}
}

// planName diffs one name. The address records (A, AAAA, CNAME) are one unit; every other type is
// diffed on its own and coexists with foreign records of other types.
func planName(p *Plan, zone, name string, want, have []dns.Record, owned map[string]bool, all map[string][]dns.Record) {
	var foreignAddr, otherData []dns.Record
	var wantCNAME, wantAddr bool
	for _, r := range want {
		wantCNAME = wantCNAME || r.Type == "CNAME"
		wantAddr = wantAddr || isAddr(r.Type)
	}
	for _, r := range have {
		if isAddr(r.Type) && !owned[r.ID] {
			foreignAddr = append(foreignAddr, r)
		}
		if !isAddr(r.Type) {
			otherData = append(otherData, r)
		}
	}
	switch {
	case wantAddr && len(foreignAddr) > 0:
		p.Conflicts = append(p.Conflicts, Conflict{Name: name, Kind: ForeignAddress, Records: foreignAddr})
		return
	case wantCNAME && len(otherData) > 0:
		p.Conflicts = append(p.Conflicts, Conflict{Name: name, Kind: CNAMEBesideData, Records: otherData})
		return
	}
	classes := map[string]bool{"": true} // "" is the address set
	for _, r := range want {
		if !isAddr(r.Type) {
			classes[r.Type] = true
		}
	}
	for _, r := range have {
		if !isAddr(r.Type) && owned[r.ID] {
			classes[r.Type] = true
		}
	}
	for _, class := range slices.Sorted(keysOf(classes)) {
		in := func(r dns.Record) bool { return (class == "" && isAddr(r.Type)) || r.Type == class }
		var w, h []dns.Record
		for _, r := range want {
			if in(r) {
				w = append(w, r)
			}
		}
		for _, r := range have {
			if in(r) && owned[r.ID] {
				h = append(h, r)
			}
		}
		diffSet(p, w, h)
	}
	if len(have) == 0 && len(want) > 0 && shadows(zone, name, all, owned) {
		p.Shadows = append(p.Shadows, name)
	}
}

// diffSet diffs the desired records of a set against the owned ones: equal records stay, a changed
// TTL or proxy flag is an update, records of the same type are paired into updates, and the rest
// are created or deleted. A change of type is a delete and a create.
func diffSet(p *Plan, want, have []dns.Record) {
	slices.SortFunc(want, compare)
	slices.SortFunc(have, compare)
	used := make([]bool, len(have))
	matched := make([]bool, len(want))
	for wi, w := range want {
		for hi, h := range have {
			if !used[hi] && h.Type == w.Type && canon(h) == canon(w) {
				used[hi], matched[wi] = true, true
				if h.TTL != w.TTL || h.Proxied != w.Proxied {
					p.Updates = append(p.Updates, change(h, w))
				}
				break
			}
		}
	}
	for wi, w := range want {
		if matched[wi] {
			continue
		}
		hi := slices.IndexFunc(have, func(h dns.Record) bool { return h.Type == w.Type })
		for hi >= 0 && used[hi] {
			next := slices.IndexFunc(have[hi+1:], func(h dns.Record) bool { return h.Type == w.Type })
			if next < 0 {
				hi = -1
				break
			}
			hi += 1 + next
		}
		if hi < 0 {
			w.ID = ""
			p.Creates = append(p.Creates, w)
			continue
		}
		used[hi] = true
		p.Updates = append(p.Updates, change(have[hi], w))
	}
	for hi, h := range have {
		if !used[hi] {
			p.Deletes = append(p.Deletes, h)
		}
	}
}

// change is the update of owned record h to w: w's fields, h's ID and marker comment.
func change(h, w dns.Record) dns.Record {
	w.ID, w.Comment = h.ID, h.Comment
	return w
}

// shadows reports whether a foreign wildcard record covers name today. The search goes up from the
// name and stops at the closest name that exists, as a wildcard applies only below it (RFC 4592).
func shadows(zone, name string, all map[string][]dns.Record, owned map[string]bool) bool {
	n := name
	for {
		_, rest, ok := strings.Cut(n, ".")
		if !ok {
			return false
		}
		if w := all["*."+rest]; len(w) > 0 {
			return slices.ContainsFunc(w, func(r dns.Record) bool { return !owned[r.ID] })
		}
		if rest == zone || exists(rest, all) {
			return false
		}
		n = rest
	}
}

// exists reports whether a name holds a record or has one below it.
func exists(name string, all map[string][]dns.Record) bool {
	for n, rs := range all {
		if len(rs) > 0 && (n == name || strings.HasSuffix(n, "."+name)) {
			return true
		}
	}
	return false
}
