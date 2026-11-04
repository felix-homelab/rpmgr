// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// The reasons of the refusals to adopt and release records (docs/07-api.md, "Errors").
const (
	ReasonRecordNotFound        = "RECORD_NOT_FOUND"
	ReasonRecordAlreadyOwned    = "RECORD_ALREADY_OWNED"
	ReasonRecordTypeUnsupported = "RECORD_TYPE_UNSUPPORTED"
	ReasonRecordNotWanted       = "RECORD_NOT_WANTED"
	ReasonRecordNotAdopted      = "RECORD_NOT_ADOPTED"
	ReasonRecordBusy            = "RECORD_BUSY"
	ReasonRecordNotRestorable   = "RECORD_NOT_RESTORABLE"
	ReasonZoneDisabled          = "ZONE_DISABLED"
)

// manageable are the types of record rpmgr owns.
var manageable = []string{"A", "AAAA", "CNAME", "TXT"}

func failed(code connect.Code, msg, reason string) error {
	return withReason(connect.NewError(code, errors.New("apisvc: "+msg)), reason)
}

// recordOf is the API's view of a ledger row.
func recordOf(r *ent.DNSRecord) *rpmgrv1.DnsRecord {
	out := &rpmgrv1.DnsRecord{Id: r.ID, Name: r.Name, Type: string(r.Type), Content: r.Content, Ttl: int32(r.TTL), Proxied: r.Proxied, Reason: r.Reason} //nolint:gosec // G115: a TTL is at most a day
	if r.ProviderRecordID != nil {
		out.ProviderRecordId = *r.ProviderRecordID
	}
	switch r.State {
	case dnsrecord.StateCreating:
		out.State = rpmgrv1.DnsRecordState_DNS_RECORD_STATE_CREATING
	case dnsrecord.StateSynced:
		out.State = rpmgrv1.DnsRecordState_DNS_RECORD_STATE_SYNCED
	case dnsrecord.StateDrifted:
		out.State = rpmgrv1.DnsRecordState_DNS_RECORD_STATE_DRIFTED
	case dnsrecord.StateOrphaned:
		out.State = rpmgrv1.DnsRecordState_DNS_RECORD_STATE_ORPHANED
	case dnsrecord.StateError:
		out.State = rpmgrv1.DnsRecordState_DNS_RECORD_STATE_ERROR
	case dnsrecord.StateDeleting:
		out.State = rpmgrv1.DnsRecordState_DNS_RECORD_STATE_DELETING
	}
	if r.AdoptedAt != nil {
		out.AdoptedTime = timestamppb.New(*r.AdoptedAt)
	}
	return out
}

// liveOf is the API's view of a record read from the provider that rpmgr does not own.
func liveOf(r dns.Record, state rpmgrv1.DnsRecordState) *rpmgrv1.DnsRecord {
	return &rpmgrv1.DnsRecord{ProviderRecordId: r.ID, Name: r.Name, Type: r.Type, Content: r.Content, Ttl: int32(r.TTL), Proxied: r.Proxied, State: state} //nolint:gosec // G115: a TTL is at most a day
}

func (z *DnsZones) now() time.Time {
	if z.Now != nil {
		return z.Now()
	}
	return time.Now()
}

// ListZoneRecords implements DnsZoneService: the owned records come from the ledger, for every
// member of the org; the others are read live and shown to an Owner or Admin only. The caller who
// may not see them is refused when they ask, and is never sent one: an Operator learns nothing of
// what else is in the zone.
func (z *DnsZones) ListZoneRecords(ctx context.Context, req *connect.Request[rpmgrv1.ListZoneRecordsRequest]) (
	*connect.Response[rpmgrv1.ListZoneRecordsResponse], error) {
	zone, err := z.DB.ReadClient().DNSZone.Get(ctx, req.Msg.GetDnsZoneId())
	if err != nil {
		return nil, storeError(err)
	}
	foreign := req.Msg.GetIncludeForeign()
	if foreign && !api.Permits(ctx, zone.OrgID, authz.PermInfrastructureWrite) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("apisvc: the records of a zone that rpmgr does not own are shown to Owners and Admins only"))
	}
	rows, err := z.DB.ReadClient().DNSRecord.Query().Where(dnsrecord.DNSZoneID(zone.ID)).
		Order(ent.Asc(dnsrecord.FieldName), ent.Asc(dnsrecord.FieldType), ent.Asc(dnsrecord.FieldID)).All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListZoneRecordsResponse{}
	owned := map[string]bool{}
	for _, r := range rows {
		out.Records = append(out.Records, recordOf(r))
		if r.ProviderRecordID != nil {
			owned[*r.ProviderRecordID] = true
		}
	}
	if !foreign {
		return connect.NewResponse(out), nil
	}
	_, in, err := z.inspectZone(ctx, zone.ID)
	if err != nil {
		return nil, err
	}
	orphan := map[string]bool{}
	for _, o := range in.Plan.Orphans {
		orphan[o.ID] = true
	}
	var others []*rpmgrv1.DnsRecord
	for _, r := range in.Live {
		switch {
		case owned[r.ID]:
		case orphan[r.ID]:
			others = append(others, liveOf(r, rpmgrv1.DnsRecordState_DNS_RECORD_STATE_ORPHANED))
		default:
			others = append(others, liveOf(r, rpmgrv1.DnsRecordState_DNS_RECORD_STATE_FOREIGN))
		}
	}
	slices.SortFunc(others, func(a, b *rpmgrv1.DnsRecord) int {
		return strings.Compare(a.GetName()+"/"+a.GetType()+"/"+a.GetContent()+"/"+a.GetProviderRecordId(),
			b.GetName()+"/"+b.GetType()+"/"+b.GetContent()+"/"+b.GetProviderRecordId())
	})
	out.Records = append(out.Records, others...)
	return connect.NewResponse(out), nil
}

// AdoptRecords implements DnsZoneService: the records are read live, all are checked, and then all
// are adopted or none. A record is adopted only if it is a record of this zone, at a name that the
// zone's org publishes: the names come from the sources of the zone's own org, so a record at a
// name another org wants is never adopted from here. The rows and the request for a full pass are
// written in one configuration transaction, so that the next pass rewrites them.
func (z *DnsZones) AdoptRecords(ctx context.Context, req *connect.Request[rpmgrv1.AdoptRecordsRequest]) (
	*connect.Response[rpmgrv1.AdoptRecordsResponse], error) {
	ids := req.Msg.GetProviderRecordIds()
	if len(slices.Compact(slices.Sorted(slices.Values(ids)))) != len(ids) {
		return nil, invalid(errors.New("apisvc: a record is named twice"))
	}
	zone, in, err := z.inspectZone(ctx, req.Msg.GetDnsZoneId())
	if err != nil {
		return nil, err
	}
	live := map[string]dns.Record{}
	for _, r := range in.Live {
		live[r.ID] = r
	}
	wanted := map[string]bool{}
	for _, n := range in.Wanted {
		wanted[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
	var recs []dns.Record
	for _, id := range ids {
		r, ok := live[id]
		switch {
		case !ok:
			return nil, failed(connect.CodeNotFound, "the provider holds no such record in the zone", ReasonRecordNotFound)
		case !slices.Contains(manageable, r.Type):
			return nil, failed(connect.CodeFailedPrecondition, "rpmgr owns records of type A, AAAA, CNAME and TXT only", ReasonRecordTypeUnsupported)
		case !wanted[strings.ToLower(strings.TrimSuffix(r.Name, "."))]:
			return nil, failed(connect.CodeFailedPrecondition, "no source of the org publishes a record at the name of the record", ReasonRecordNotWanted)
		}
		recs = append(recs, r)
	}
	az := apply.Zone{ID: zone.ID, OrgID: zone.OrgID, Name: zone.Name, ProviderID: zone.ProviderZoneID}
	api.AuditReason(ctx, "adopt "+strings.Join(ids, ", ")+" in dns zone "+zone.ID) // before the transaction, which appends the entry
	var rows []*ent.DNSRecord
	now := z.now().UTC()
	_, err = store.ConfigTx(ctx, z.DB, func(tx *ent.Tx) ([]string, error) {
		rows = rows[:0]
		n, err := tx.DNSRecord.Query().Where(dnsrecord.DNSZoneID(zone.ID), dnsrecord.ProviderRecordIDIn(ids...)).Count(ctx)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, failed(connect.CodeAlreadyExists, "a record is owned already", ReasonRecordAlreadyOwned)
		}
		for _, r := range recs {
			row, err := apply.Adopt(ctx, tx, az, r, now)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		// The pass that rewrites them is a full one: a revision alone would find that the sources
		// compile as before and read nothing.
		if err := tx.DNSZone.UpdateOneID(zone.ID).SetSyncRequestedAt(now).Exec(ctx); err != nil {
			return nil, err
		}
		return []string{zone.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.AdoptRecordsResponse{}
	for _, r := range rows {
		out.Records = append(out.Records, recordOf(r))
	}
	return connect.NewResponse(out), nil
}

// ReleaseRecord implements DnsZoneService: an owned record leaves the ledger and stays at the
// provider. It loses rpmgr's marker, so that it is not reported as an orphan, or with restore it
// is put back to the content it was adopted with. Both are written to the provider before the row
// is dropped; a call that fails in between is made again.
func (z *DnsZones) ReleaseRecord(ctx context.Context, req *connect.Request[rpmgrv1.ReleaseRecordRequest]) (
	*connect.Response[rpmgrv1.ReleaseRecordResponse], error) {
	m := req.Msg
	zone, err := z.DB.ReadClient().DNSZone.Get(ctx, m.GetDnsZoneId())
	if err != nil {
		return nil, storeError(err)
	}
	row, err := z.DB.ReadClient().DNSRecord.Get(ctx, m.GetRecordId())
	if ent.IsNotFound(err) || err == nil && row.DNSZoneID != zone.ID {
		return nil, failed(connect.CodeNotFound, "the zone owns no such record", ReasonRecordNotFound)
	}
	if err != nil {
		return nil, storeError(err)
	}
	if row.State == dnsrecord.StateCreating || row.State == dnsrecord.StateDeleting {
		return nil, failed(connect.CodeFailedPrecondition, "the DNS job is writing the record; try again in a moment", ReasonRecordBusy)
	}
	orig, adopted := apply.OriginalOf(row)
	if m.GetRestore() && !adopted {
		return nil, failed(connect.CodeFailedPrecondition, "the record was not adopted, so it has no original to put back", ReasonRecordNotAdopted)
	}
	warning := ""
	if m.GetRestore() && row.AdoptedAt != nil && z.now().Sub(*row.AdoptedAt) > apply.StalenessLimit {
		warning = fmt.Sprintf("the original is older than %d days: its address may belong to someone else now", int(apply.StalenessLimit.Hours()/24))
	}
	diff, _ := json.Marshal(map[string]any{"name": row.Name, "type": row.Type, "restore": m.GetRestore()})
	api.AuditDiff(ctx, string(diff)) // before the transaction, which appends the entry
	api.AuditReason(ctx, "release "+row.ID+" of dns zone "+zone.ID)
	if row.ProviderRecordID != nil {
		if err := z.unmark(ctx, zone, row, orig, m.GetRestore()); err != nil {
			return nil, err
		}
	}
	_, err = store.ConfigTx(ctx, z.DB, func(tx *ent.Tx) ([]string, error) {
		if err := tx.DNSRecord.DeleteOneID(row.ID).Exec(ctx); err != nil {
			return nil, err
		}
		// What the record now is to the zone, a conflict where a source wants its name, is for the
		// next pass to find: a full one.
		return []string{zone.ID}, tx.DNSZone.UpdateOneID(zone.ID).SetSyncRequestedAt(z.now().UTC()).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.ReleaseRecordResponse{Warning: warning}), nil
}

// unmark writes the record at the provider as a release leaves it: without rpmgr's marker, or with
// restore as it was adopted. A record that is gone, or that someone else changed to carry no marker
// of ours, needs nothing.
func (z *DnsZones) unmark(ctx context.Context, zone *ent.DNSZone, row *ent.DNSRecord, orig apply.Original, restore bool) error {
	p, err := z.providerOf(ctx, zone)
	if err != nil {
		return err
	}
	live, err := p.ListRecords(ctx, zone.ProviderZoneID)
	if err != nil {
		return providerError(err)
	}
	i := slices.IndexFunc(live, func(r dns.Record) bool { return r.ID == *row.ProviderRecordID })
	if i < 0 {
		return nil
	}
	rec := live[i]
	switch {
	case restore && rec.Type != orig.Type:
		return failed(connect.CodeFailedPrecondition, "the type of the record changed since it was adopted, so its original cannot be put back", ReasonRecordNotRestorable)
	case restore:
		rec.Content, rec.TTL, rec.Proxied, rec.Comment = orig.Content, orig.TTL, orig.Proxied, orig.Comment
	case strings.HasPrefix(rec.Comment, "rpmgr ") && strings.HasSuffix(rec.Comment, " "+row.ID):
		rec.Comment = ""
	default:
		return nil
	}
	if err := p.Apply(ctx, zone.ProviderZoneID, dns.Batch{Patches: []dns.Record{rec}}); err != nil {
		return providerError(err)
	}
	return nil
}

// SyncZone implements DnsZoneService: the request is written to the zone's row, where the DNS job,
// on whichever replica holds its lease, finds it at its next tick.
func (z *DnsZones) SyncZone(ctx context.Context, req *connect.Request[rpmgrv1.SyncZoneRequest]) (
	*connect.Response[rpmgrv1.SyncZoneResponse], error) {
	var row *ent.DNSZone
	err := store.WriteTx(ctx, z.DB, func(tx *ent.Tx) error {
		cur, err := tx.DNSZone.Get(ctx, req.Msg.GetDnsZoneId())
		if err != nil {
			return err
		}
		if cur.SyncState == dnszone.SyncStateDisabled {
			return failed(connect.CodeFailedPrecondition, "the zone is disabled: the DNS job does nothing in it", ReasonZoneDisabled)
		}
		row, err = tx.DNSZone.UpdateOneID(cur.ID).SetSyncRequestedAt(z.now().UTC()).Save(ctx)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.SyncZoneResponse{DnsZone: zoneOf(row)}), nil
}
