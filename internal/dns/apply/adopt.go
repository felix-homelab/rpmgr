// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
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

// Release carries out the releases that ReleaseRecord asked for, under the lease: each owned record
// is written at the provider, without rpmgr's marker or, for restore, as it was adopted, and only
// then its row is dropped, in a transaction that checks the fencing token. A lost lease or one that
// will not outlast the write (Guard) stops it before the write; a crash between the write and the
// commit leaves the row, and the next holder writes the same again. A restore of a record whose
// type changed since, or that was not adopted, is not carried out: the request is cleared and the
// row says why. It returns how many rows it dropped.
func (e *Engine) Release(ctx context.Context, l lease.Lease, p dns.Provider, z Zone) (int, error) {
	rows, err := e.DB.ReadClient().DNSRecord.Query().Where(dnsrecord.DNSZoneID(z.ID), dnsrecord.ReleaseRequestedNEQ("")).All(ctx)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	live, err := p.ListRecords(ctx, z.ProviderID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, row := range rows {
		restore := row.ReleaseRequested == "restore"
		var patch *dns.Record
		refuse := ""
		if row.ProviderRecordID != nil {
			if i := slices.IndexFunc(live, func(r dns.Record) bool { return r.ID == *row.ProviderRecordID }); i >= 0 {
				rec := live[i]
				orig, adopted := OriginalOf(row)
				switch {
				case restore && !adopted:
					refuse = "the record was not adopted, so it has no original to put back"
				case restore && rec.Type != orig.Type:
					refuse = "the type of the record changed since it was adopted, so its original cannot be put back"
				case restore:
					rec.Content, rec.TTL, rec.Proxied, rec.Comment = orig.Content, orig.TTL, orig.Proxied, orig.Comment
					patch = &rec
				case strings.HasPrefix(rec.Comment, "rpmgr ") && strings.HasSuffix(rec.Comment, " "+row.ID):
					rec.Comment = ""
					patch = &rec
				}
			}
		}
		if patch != nil {
			if e.Guard != nil {
				if err := e.Guard(ctx); err != nil {
					return n, err
				}
			}
			if err := p.Apply(ctx, z.ProviderID, dns.Batch{Patches: []dns.Record{*patch}}); err != nil {
				return n, err
			}
		}
		err := store.WriteTx(context.WithoutCancel(ctx), e.DB, func(tx *ent.Tx) error {
			if err := e.Leases.Fence(ctx, tx, l); err != nil {
				return err
			}
			if refuse != "" {
				return tx.DNSRecord.UpdateOneID(row.ID).SetReleaseRequested("").SetReason(refuse).Exec(ctx)
			}
			if err := tx.DNSRecord.DeleteOneID(row.ID).Exec(ctx); err != nil {
				return err
			}
			return e.auditRow(ctx, tx, z, "dns_record.release", "released at the request of an Owner or Admin, dns zone "+z.ID, snap(row), nil)
		})
		if err != nil {
			return n, err
		}
		if refuse == "" {
			n++
		}
	}
	return n, nil
}
