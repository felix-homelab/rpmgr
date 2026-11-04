// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"context"
	"encoding/json"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
)

// StalenessLimit is how old an adopted original may be before putting it back warns that its
// address may now belong to someone else (docs/15-dns.md, "Timers and limits").
const StalenessLimit = 30 * 24 * time.Hour

// Original is a record as it was when it was adopted, as the ledger keeps it in adopted_from.
type Original struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

// OriginalOf returns the original of an adopted row; ok is false for a row that was not adopted.
func OriginalOf(r *ent.DNSRecord) (o Original, ok bool) {
	if r.AdoptedFrom == "" || json.Unmarshal([]byte(r.AdoptedFrom), &o) != nil {
		return Original{}, false
	}
	return o, true
}

// Adopt writes the ledger row of a foreign record, in tx: the record becomes owned. The row is as
// the record is, with its original content in adopted_from, and has not been written by the job
// yet, so the next pass rewrites it to what the sources want and puts the marker on it.
func Adopt(ctx context.Context, tx *ent.Tx, z Zone, rec dns.Record, now time.Time) (*ent.DNSRecord, error) {
	orig, err := json.Marshal(Original{Type: rec.Type, Content: rec.Content, TTL: rec.TTL, Proxied: rec.Proxied, Comment: rec.Comment})
	if err != nil {
		return nil, err
	}
	return tx.DNSRecord.Create().SetOrgID(z.OrgID).SetDNSZoneID(z.ID).SetName(rec.Name).SetType(dnsrecord.Type(rec.Type)).
		SetContent(rec.Content).SetTTL(rec.TTL).SetProxied(rec.Proxied).SetProviderRecordID(rec.ID).
		SetState(dnsrecord.StateSynced).SetAdoptedFrom(string(orig)).SetAdoptedAt(now).Save(ctx)
}
