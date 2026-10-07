// SPDX-License-Identifier: Apache-2.0

// Package dnsadapter implements libdns RecordAppender and RecordDeleter over the Cloudflare
// client, which is what certmagic's DNS-01 solver needs (docs/15-dns.md, "ACME DNS-01"). It only
// writes ACME challenge TXT records, marks every record it creates with a comment, deletes only
// records that carry its marker, and refuses zones that are not active, full zones of the account.
package dnsadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/felix-homelab/rpmgr/spikes/s6/internal/cfclient"
)

// ErrZoneNotManaged is returned for a zone the account does not hold as an active, full zone.
var ErrZoneNotManaged = errors.New("dnsadapter: zone is not a managed zone")

// Provider is the libdns adapter.
type Provider struct {
	Client *cfclient.Client
	// Marker is the record comment, "rpmgr <trust domain> <ledger ID>" in the product
	// (docs/15-dns.md, "Ownership ledger"); at most 100 characters.
	Marker string
}

func (p *Provider) zoneID(ctx context.Context, zone string) (string, string, error) {
	name := strings.ToLower(strings.TrimSuffix(zone, "."))
	zs, err := p.Client.ListZones(ctx)
	if err != nil {
		return "", "", err
	}
	for _, z := range zs {
		if z.Name == name {
			if z.Status != "active" || z.Type != "full" {
				return "", "", fmt.Errorf("%w: %s is %s/%s", ErrZoneNotManaged, name, z.Status, z.Type)
			}
			return z.ID, name, nil
		}
	}
	return "", "", fmt.Errorf("%w: %s", ErrZoneNotManaged, name)
}

func challengeTXT(rec libdns.Record, zone string) (libdns.RR, string, error) {
	rr := rec.RR()
	if rr.Type != "TXT" {
		return rr, "", fmt.Errorf("dnsadapter: only TXT records are written, got %s", rr.Type)
	}
	fqdn := strings.ToLower(libdns.AbsoluteName(rr.Name, zone))
	if !strings.HasPrefix(fqdn, "_acme-challenge.") {
		return rr, "", fmt.Errorf("dnsadapter: %s is not an ACME challenge name", fqdn)
	}
	return rr, fqdn, nil
}

// AppendRecords implements libdns.RecordAppender.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if len(p.Marker) > 100 {
		return nil, errors.New("dnsadapter: marker longer than 100 characters")
	}
	id, zname, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, rec := range recs {
		rr, fqdn, err := challengeTXT(rec, zname)
		if err != nil {
			return out, err
		}
		ttl := max(int(rr.TTL/time.Second), 60)
		created, err := p.Client.CreateRecord(ctx, id, cfclient.Record{Type: "TXT", Name: fqdn,
			Content: rr.Data, TTL: ttl, Comment: p.Marker})
		if err != nil {
			return out, err
		}
		out = append(out, libdns.TXT{Name: rr.Name, TTL: time.Duration(ttl) * time.Second,
			Text: rr.Data, ProviderData: created.ID})
	}
	return out, nil
}

// DeleteRecords implements libdns.RecordDeleter. It deletes only records with the same name,
// content and this adapter's marker, and treats an already deleted record as success.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	id, zname, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, rec := range recs {
		rr, fqdn, err := challengeTXT(rec, zname)
		if err != nil {
			return out, err
		}
		existing, err := p.Client.ListTXT(ctx, id, fqdn)
		if err != nil {
			return out, err
		}
		for _, e := range existing {
			if e.Content != rr.Data || e.Comment != p.Marker {
				continue // a foreign record, or another challenge's
			}
			if err := p.Client.DeleteRecord(ctx, id, e.ID); err != nil {
				var ae *cfclient.APIError
				if errors.As(err, &ae) && ae.Status == 404 {
					continue
				}
				return out, err
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

// Interface guards.
var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
