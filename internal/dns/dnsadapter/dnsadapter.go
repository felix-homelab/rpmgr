// SPDX-License-Identifier: Apache-2.0

// Package dnsadapter implements libdns RecordAppender and RecordDeleter over a DNS provider, which
// is what certmagic's DNS-01 solver needs (docs/15-dns.md, "ACME DNS-01"; D166, D167). It writes
// only ACME challenge TXT records, in a managed zone of one org, marks each with the comment
// `rpmgr <trust domain> acme`, and deletes only a record whose type, name, content and comment all
// equal what it wrote. Every request it sends is taken from the provider's rate budget as DNS-01,
// which may use at most half of the window. The adapter is the spike S6's internal/dnsadapter,
// moved onto the Provider interface and the managed zones of the database.
package dnsadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// The reasons a challenge is refused. Test for them with errors.Is.
var (
	// ErrZoneNotManaged: no managed zone of the org holds the name, or the zone was removed.
	ErrZoneNotManaged = errors.New("dnsadapter: no managed zone of the org holds the name")
	// ErrZoneDisabled: the zone is disabled; another installation of the trust domain may use it
	// (D166).
	ErrZoneDisabled = errors.New("dnsadapter: the zone is disabled")
)

// challengeLabel starts the name of every record the adapter writes.
const challengeLabel = "_acme-challenge."

// minTTL is the shortest TTL the adapter asks for; Cloudflare's lowest is 60 s.
const minTTL = 60 * time.Second

// ZoneFor returns the managed zone of org with the longest name that holds hostname; a wildcard
// counts by its base name. A zone of another org is never returned (D166). It fails with
// ErrZoneNotManaged if the org has none. The zone's state is the caller's to judge.
func ZoneFor(ctx context.Context, c *ent.Client, org, hostname string) (*ent.DNSZone, error) {
	name := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(hostname, ".")), "*.")
	zones, err := c.DNSZone.Query().Where(dnszone.OrgID(org)).All(ctx)
	if err != nil {
		return nil, err
	}
	var best *ent.DNSZone
	for _, z := range zones {
		if (name == z.Name || strings.HasSuffix(name, "."+z.Name)) && (best == nil || len(z.Name) > len(best.Name)) {
			best = z
		}
	}
	if best == nil {
		return nil, fmt.Errorf("%w: %s", ErrZoneNotManaged, name)
	}
	return best, nil
}

// Adapter is the libdns provider of the challenges of one org's hostnames.
type Adapter struct {
	DB *store.DB
	// Sys is the system scope the zones and providers are read in.
	Sys    context.Context
	Sealer *secret.Sealer
	// Dial makes the client of a provider account; nil is providers.Dial.
	Dial providers.Dialer
	// Budget is the request budget of the providers; nil: none, for tests of other things.
	Budget *budget.Budget
	// TrustDomain is this instance's, in the marker.
	TrustDomain string
	// Org is the org whose managed zones the adapter uses.
	Org string
}

// Marker is the comment of every record the adapter writes.
func (a *Adapter) Marker() string { return apply.Marker(a.TrustDomain, "acme") }

// scoped returns a context that carries the system scope, which the budget's transactions need,
// and ends when ctx does. certmagic cleans up under a context of its own, with no scope.
func (a *Adapter) scoped(ctx context.Context) (context.Context, context.CancelFunc) {
	c, cancel := context.WithCancel(context.WithoutCancel(a.Sys))
	stop := context.AfterFunc(ctx, cancel)
	return c, func() { stop(); cancel() }
}

// target finds the managed zone named zone of the adapter's org, which must not be disabled, and
// the client of its provider with the DNS-01 budget.
func (a *Adapter) target(ctx context.Context, zone string) (*ent.DNSZone, dns.Provider, error) {
	name := strings.ToLower(strings.TrimSuffix(zone, "."))
	c := a.DB.ReadClient()
	z, err := c.DNSZone.Query().Where(dnszone.OrgID(a.Org), dnszone.Name(name)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil, fmt.Errorf("%w: %s", ErrZoneNotManaged, name)
	}
	if err != nil {
		return nil, nil, err
	}
	if z.SyncState == dnszone.SyncStateDisabled {
		return nil, nil, fmt.Errorf("%w: %s", ErrZoneDisabled, name)
	}
	p, err := c.DNSProvider.Get(ctx, z.DNSProviderID)
	if err != nil {
		return nil, nil, err
	}
	tok, err := a.Sealer.Open(providers.SecretContext(p.ID), p.CredentialEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("dnsadapter: the provider's token cannot be opened: %w", err)
	}
	dial := a.Dial
	if dial == nil {
		dial = providers.Dial
	}
	prov, err := dial(string(p.Kind), p.AccountID, tok)
	if err != nil {
		return nil, nil, err
	}
	if a.Budget != nil {
		prov = a.Budget.Wrap(prov, p.ID, budget.DNS01)
	}
	return z, prov, nil
}

// challengeTXT checks that rec is a TXT record at an ACME challenge name and returns it with its
// name in full.
func challengeTXT(rec libdns.Record, zone string) (libdns.RR, string, error) {
	rr := rec.RR()
	if rr.Type != "TXT" {
		return rr, "", fmt.Errorf("dnsadapter: only TXT records are written, got %s", rr.Type)
	}
	fqdn := strings.ToLower(strings.TrimSuffix(libdns.AbsoluteName(rr.Name, zone), "."))
	if !strings.HasPrefix(fqdn, challengeLabel) {
		return rr, "", fmt.Errorf("dnsadapter: %s is not an ACME challenge name", fqdn)
	}
	return rr, fqdn, nil
}

// AppendRecords implements libdns.RecordAppender. It also removes the leftovers of earlier
// orders at the same names, those that carry the marker; an order that runs at the same time at
// one of the names loses its record then, fails, and is retried.
func (a *Adapter) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	ctx, done := a.scoped(ctx)
	defer done()
	z, prov, err := a.target(ctx, zone)
	if err != nil {
		return nil, err
	}
	var posts []dns.Record
	var out []libdns.Record
	names := map[string]bool{}
	for _, rec := range recs {
		rr, fqdn, err := challengeTXT(rec, z.Name)
		if err != nil {
			return nil, err
		}
		ttl := max(rr.TTL, minTTL)
		posts = append(posts, dns.Record{Type: "TXT", Name: fqdn, Content: rr.Data, TTL: int(ttl / time.Second), Comment: a.Marker()})
		out = append(out, libdns.TXT{Name: rr.Name, TTL: ttl, Text: rr.Data})
		names[fqdn] = true
	}
	// A TXT that an earlier order left at the name, as after a crash, carries this marker and is
	// removed with the new one written (D167); a record without it is not touched.
	live, err := prov.ListRecords(ctx, z.ProviderZoneID)
	if err != nil {
		return nil, err
	}
	var b dns.Batch
	for _, r := range live {
		if r.Type == "TXT" && r.Comment == a.Marker() && names[strings.ToLower(r.Name)] {
			b.Deletes = append(b.Deletes, r.ID)
		}
	}
	b.Posts = posts
	if err := prov.Apply(ctx, z.ProviderZoneID, b); err != nil {
		return nil, err
	}
	return out, nil
}

// unquote drops the quotes a provider may put around the text of a TXT record.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// DeleteRecords implements libdns.RecordDeleter. It deletes a record only if its type, name,
// content and comment equal what the adapter wrote, so a challenge of another party at the same
// name stays; a record that is gone already is success.
func (a *Adapter) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	ctx, done := a.scoped(ctx)
	defer done()
	z, prov, err := a.target(ctx, zone)
	if err != nil {
		return nil, err
	}
	type key struct{ name, content string }
	want := map[key]libdns.Record{}
	for _, rec := range recs {
		rr, fqdn, err := challengeTXT(rec, z.Name)
		if err != nil {
			return nil, err
		}
		want[key{fqdn, rr.Data}] = rec
	}
	live, err := prov.ListRecords(ctx, z.ProviderZoneID)
	if err != nil {
		return nil, err
	}
	var b dns.Batch
	var out []libdns.Record
	for _, r := range live {
		rec, ok := want[key{strings.ToLower(r.Name), unquote(r.Content)}]
		if !ok || r.Type != "TXT" || r.Comment != a.Marker() {
			continue // a foreign record, or another order's
		}
		b.Deletes = append(b.Deletes, r.ID)
		out = append(out, rec)
	}
	if err := prov.Apply(ctx, z.ProviderZoneID, b); err != nil {
		return nil, err
	}
	return out, nil
}

// Interface guards.
var (
	_ libdns.RecordAppender = (*Adapter)(nil)
	_ libdns.RecordDeleter  = (*Adapter)(nil)
)
