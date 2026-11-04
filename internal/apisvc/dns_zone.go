// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsnamestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// The reasons of the refusals of an import (docs/07-api.md, "Errors"). A zone the provider does
// not call active is ZONE_NOT_ACTIVE, one that is not a full zone ZONE_NOT_FULL.
const (
	ReasonZoneNotActive        = "ZONE_NOT_ACTIVE"
	ReasonZoneNotFull          = "ZONE_NOT_FULL"
	ReasonZoneClaimNotWildcard = "ZONE_CLAIM_NOT_WILDCARD"
)

// The reasons of the refusals of a plan's approval (docs/07-api.md, "Errors"): the plan has
// another hash now, or the zone is not held.
const (
	ReasonPlanChanged = "PLAN_CHANGED"
	ReasonZoneNotHeld = "ZONE_NOT_HELD"
)

// HeldImported is the held_reason of a zone that was imported and has no approved plan yet.
const HeldImported = apply.HeldImported

// The bounds of the numbers a caller sets on a zone (docs/15-dns.md, "Timers and limits").
const (
	minZoneTTL         = 60
	maxZoneTTL         = 86400
	maxDeleteThreshold = 1000
)

// zoneFields are the fields UpdateZone may change.
var zoneFields = []string{"publish_route_hostnames", "allow_proxied", "allow_wildcards", "delete_threshold", "default_ttl"}

// DnsZones is DnsZoneService (docs/07-api.md; docs/15-dns.md, "Connecting, importing and
// disconnecting"). Its methods run in the org scope the interceptor gives them.
type DnsZones struct {
	rpmgrv1connect.UnimplementedDnsZoneServiceHandler
	DB  *store.DB
	API *api.Server
	// Providers makes the client of a zone's provider account.
	Providers *DnsProviders
	// Planner computes the plan of a zone now: the DNS job's Preview. The API and the job must
	// share it, so that a plan is approved as the job computes it.
	Planner Planner
	Now     func() time.Time
}

// Planner computes the plan of a zone as the DNS job would now, with p as the zone's provider.
type Planner interface {
	Preview(ctx context.Context, zoneID string, p dns.Provider) (plan.Plan, error)
}

// zoneOf is the API's view of a row.
func zoneOf(r *ent.DNSZone) *rpmgrv1.DnsZone {
	z := &rpmgrv1.DnsZone{Id: r.ID, Name: r.Name, DnsProviderId: r.DNSProviderID, ProviderZoneId: r.ProviderZoneID,
		HeldReason: r.HeldReason, PublishRouteHostnames: r.PublishRouteHostnames, AllowProxied: r.AllowProxied,
		AllowWildcards: r.AllowWildcards, DeleteThreshold: int32(r.DeleteThreshold), DefaultTtl: int32(r.DefaultTTL), //nolint:gosec // G115: bounded on write
		Etag: etagOf(r.Version), PendingPlanHash: r.PendingPlanHash}
	switch r.SyncState {
	case dnszone.SyncStateActive:
		z.SyncState = rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_ACTIVE
	case dnszone.SyncStateHeld:
		z.SyncState = rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_HELD
	case dnszone.SyncStateDisabled:
		z.SyncState = rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_DISABLED
	}
	switch r.ProviderStatus {
	case dnszone.ProviderStatusOk:
		z.ProviderStatus = rpmgrv1.ZoneProviderStatus_ZONE_PROVIDER_STATUS_OK
	case dnszone.ProviderStatusPermissionDenied:
		z.ProviderStatus = rpmgrv1.ZoneProviderStatus_ZONE_PROVIDER_STATUS_PERMISSION_DENIED
	case dnszone.ProviderStatusUnreachable:
		z.ProviderStatus = rpmgrv1.ZoneProviderStatus_ZONE_PROVIDER_STATUS_UNREACHABLE
	case dnszone.ProviderStatusRateLimited:
		z.ProviderStatus = rpmgrv1.ZoneProviderStatus_ZONE_PROVIDER_STATUS_RATE_LIMITED
	}
	if r.LastSyncedAt != nil {
		z.LastSyncedTime = timestamppb.New(*r.LastSyncedAt)
	}
	return z
}

// importable says why a zone the provider lists cannot be imported, in fixed words that name the
// state and not the provider's text. Only a zone that is active and full can: a pending zone is
// not served by the provider yet, and adding one needs no proof of ownership, and in a partial or
// secondary setup the provider is not authoritative (docs/15-dns.md, "Connecting, importing and
// disconnecting").
func importable(z dns.Zone) error {
	if !strings.EqualFold(z.Status, "active") {
		what := "the zone is not active at the provider"
		switch strings.ToLower(z.Status) {
		case "pending", "initializing":
			what = "the zone is pending: its nameservers do not point at the provider yet"
		case "moved":
			what = "the zone has moved away from the provider"
		}
		return withReason(connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: "+what)), ReasonZoneNotActive)
	}
	if !strings.EqualFold(z.Type, "full") {
		what := "the zone is not a full zone: the provider is not authoritative for it"
		switch strings.ToLower(z.Type) {
		case "partial":
			what = "the zone is a partial (CNAME) setup: the provider is not authoritative for it"
		case "secondary":
			what = "the zone is a secondary zone: the provider is not authoritative for it"
		}
		return withReason(connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: "+what)), ReasonZoneNotFull)
	}
	return nil
}

// apexClaim returns the claim that covers the apex of a zone and every name below it, for org:
// a verified domain that does, or else the org's claim on the apex, which it makes if there is
// none. The claim is pending until it is verified like any other; a zone at a provider is no
// proof (docs/04-security.md, "Route and hostname ownership").
func apexClaim(ctx context.Context, tx *ent.Tx, org, apex string) (*ent.Domain, error) {
	switch d, err := domains.Covering(ctx, tx, org, "*."+apex); {
	case err == nil:
		return d, nil
	case !errors.Is(err, domains.ErrNotOwned):
		return nil, err
	}
	switch d, err := tx.Domain.Query().Where(domain.Fqdn(apex)).Only(ctx); {
	case err == nil && d.Wildcard:
		return d, nil
	case err == nil:
		return nil, withReason(connect.NewError(connect.CodeFailedPrecondition,
			errors.New("apisvc: the org's claim on the zone's name does not cover the names below it; delete it and import the zone again")),
			ReasonZoneClaimNotWildcard)
	case !ent.IsNotFound(err):
		return nil, err
	}
	d, err := domains.Claim(ctx, tx, org, apex, true)
	if errors.Is(err, domains.ErrTaken) {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("apisvc: the zone's name is claimed by another org"))
	}
	return d, err
}

// ImportZone implements DnsZoneService. The zone is read live from the provider outside any
// transaction; the zone and its claim are then written in one.
func (z *DnsZones) ImportZone(ctx context.Context, req *connect.Request[rpmgrv1.ImportZoneRequest]) (
	*connect.Response[rpmgrv1.ImportZoneResponse], error) {
	m := req.Msg
	prov, err := z.DB.ReadClient().DNSProvider.Get(ctx, m.GetDnsProviderId())
	if err != nil {
		return nil, storeError(err)
	}
	p, err := z.Providers.client(ctx, prov)
	if err != nil {
		return nil, err
	}
	zones, err := p.ListZones(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	var found *dns.Zone
	for i := range zones {
		if zones[i].ID == m.GetProviderZoneId() {
			found = &zones[i]
		}
	}
	if found == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("apisvc: the provider lists no such zone"))
	}
	if err := importable(*found); err != nil {
		return nil, err
	}
	name, err := domains.Normalize(found.Name, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the zone's name is not a domain name rpmgr accepts"))
	}

	var row *ent.DNSZone
	var claim *ent.Domain
	_, err = store.ConfigTx(ctx, z.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.DNSProvider.Get(ctx, prov.ID)
		if err != nil {
			return nil, err
		}
		if n, err := tx.DNSZone.Query().Where(dnszone.Name(name)).Count(ctx); err != nil || n > 0 {
			return nil, errors.Join(err, errIf(n > 0, connect.NewError(connect.CodeAlreadyExists, errors.New("apisvc: the zone is already imported"))))
		}
		if claim, err = apexClaim(ctx, tx, cur.OrgID, name); err != nil {
			return nil, err
		}
		row, err = tx.DNSZone.Create().SetOrgID(cur.OrgID).SetDNSProviderID(cur.ID).SetProviderZoneID(found.ID).SetName(name).
			SetHeldReason(HeldImported).Save(ctx)
		if err != nil {
			return nil, err
		}
		return []string{row.ID, claim.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.ImportZoneResponse{DnsZone: zoneOf(row), Domain: domainOf(claim)}), nil
}

// GetZone implements DnsZoneService.
func (z *DnsZones) GetZone(ctx context.Context, req *connect.Request[rpmgrv1.GetZoneRequest]) (
	*connect.Response[rpmgrv1.GetZoneResponse], error) {
	row, err := z.DB.ReadClient().DNSZone.Get(ctx, req.Msg.GetDnsZoneId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetZoneResponse{DnsZone: zoneOf(row)}), nil
}

// ListZones implements DnsZoneService.
func (z *DnsZones) ListZones(ctx context.Context, req *connect.Request[rpmgrv1.ListZonesRequest]) (
	*connect.Response[rpmgrv1.ListZonesResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := z.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := z.DB.ReadClient().DNSZone.Query().Where(dnszone.OrgID(m.GetOrgId())).Order(ent.Asc(dnszone.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(dnszone.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListZonesResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = z.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.DnsZones = append(out.DnsZones, zoneOf(r))
	}
	return connect.NewResponse(out), nil
}

// UpdateZone implements DnsZoneService: the gates and the default TTL. Name, provider and state
// are not changed here.
func (z *DnsZones) UpdateZone(ctx context.Context, req *connect.Request[rpmgrv1.UpdateZoneRequest]) (
	*connect.Response[rpmgrv1.UpdateZoneResponse], error) {
	m := req.Msg
	cur, err := z.DB.ReadClient().DNSZone.Get(ctx, m.GetDnsZone().GetId())
	if err != nil {
		return nil, storeError(err)
	}
	if err := api.CheckEtag(m.GetEtag(), cur.Version, zoneOf(cur)); err != nil {
		return nil, err
	}
	next := proto.Clone(zoneOf(cur)).(*rpmgrv1.DnsZone)
	if err := api.ApplyMask(next, m.GetDnsZone(), m.GetUpdateMask(), zoneFields...); err != nil {
		return nil, err
	}
	if t := next.GetDeleteThreshold(); t < 0 || t > maxDeleteThreshold {
		return nil, invalid(errors.New("apisvc: delete_threshold is out of range"))
	}
	if ttl := next.GetDefaultTtl(); ttl < minZoneTTL || ttl > maxZoneTTL {
		return nil, invalid(errors.New("apisvc: default_ttl is out of range"))
	}
	var row *ent.DNSZone
	_, err = store.ConfigTx(ctx, z.DB, func(tx *ent.Tx) ([]string, error) {
		var err error
		row, err = tx.DNSZone.UpdateOneID(cur.ID).Where(dnszone.Version(cur.Version)).
			SetPublishRouteHostnames(next.GetPublishRouteHostnames()).SetAllowProxied(next.GetAllowProxied()).
			SetAllowWildcards(next.GetAllowWildcards()).SetDeleteThreshold(int(next.GetDeleteThreshold())).
			SetDefaultTTL(int(next.GetDefaultTtl())).Save(ctx)
		return []string{cur.ID}, err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateZoneResponse{DnsZone: zoneOf(row)}), nil
}

// RemoveZone implements DnsZoneService: the zone is no longer managed. Its records stay at the
// provider, and so does the claim on its apex.
func (z *DnsZones) RemoveZone(ctx context.Context, req *connect.Request[rpmgrv1.RemoveZoneRequest]) (
	*connect.Response[rpmgrv1.RemoveZoneResponse], error) {
	_, err := store.ConfigTx(ctx, z.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.DNSZone.Get(ctx, req.Msg.GetDnsZoneId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, zoneOf(cur)); err != nil {
			return nil, err
		}
		// The records stay at the provider, and the ledger rows and name statuses go with the zone
		// (docs/15-dns.md, "Connecting, importing and disconnecting").
		if _, err := tx.DNSRecord.Delete().Where(dnsrecord.DNSZoneID(cur.ID)).Exec(ctx); err != nil {
			return nil, err
		}
		if _, err := tx.DNSNameStatus.Delete().Where(dnsnamestatus.DNSZoneID(cur.ID)).Exec(ctx); err != nil {
			return nil, err
		}
		return []string{cur.ID}, tx.DNSZone.DeleteOneID(cur.ID).Where(dnszone.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.RemoveZoneResponse{}), nil
}

// previewZone is the live plan of a zone: the provider's records are read through its client, and
// the plan is what the DNS job would compute now.
func (z *DnsZones) previewZone(ctx context.Context, zoneID string) (*ent.DNSZone, plan.Plan, error) {
	row, err := z.DB.ReadClient().DNSZone.Get(ctx, zoneID)
	if err != nil {
		return nil, plan.Plan{}, storeError(err)
	}
	if z.Planner == nil {
		return nil, plan.Plan{}, connect.NewError(connect.CodeInternal, errors.New("apisvc: no planner"))
	}
	prov, err := z.DB.ReadClient().DNSProvider.Get(ctx, row.DNSProviderID)
	if err != nil {
		return nil, plan.Plan{}, storeError(err)
	}
	p, err := z.Providers.client(ctx, prov)
	if err != nil {
		return nil, plan.Plan{}, err
	}
	pl, err := z.Planner.Preview(ctx, row.ID, p)
	if err != nil {
		return nil, plan.Plan{}, providerError(err)
	}
	return row, pl, nil
}

func planRecord(r dns.Record) *rpmgrv1.PlanRecord {
	return &rpmgrv1.PlanRecord{Id: r.ID, Name: r.Name, Type: r.Type, Content: r.Content, Ttl: int32(r.TTL), Proxied: r.Proxied} //nolint:gosec // G115: a TTL is at most a day
}

func planRecords(rs []dns.Record) []*rpmgrv1.PlanRecord {
	var out []*rpmgrv1.PlanRecord
	for _, r := range rs {
		out = append(out, planRecord(r))
	}
	return out
}

// planOf is the API's view of a plan.
func planOf(p plan.Plan) *rpmgrv1.ZonePlan {
	out := &rpmgrv1.ZonePlan{Creates: planRecords(p.Creates), Updates: planRecords(p.Updates), Deletes: planRecords(p.Deletes),
		Orphans: planRecords(p.Orphans), Shadows: p.Shadows, Hash: p.Hash}
	for _, c := range p.Conflicts {
		out.Conflicts = append(out.Conflicts, &rpmgrv1.PlanConflict{Name: c.Name, Kind: string(c.Kind), Records: planRecords(c.Records)})
	}
	for _, l := range p.Lost {
		out.Lost = append(out.Lost, l.RecordID)
	}
	return out
}

// PlanZoneSync implements DnsZoneService: the plan a pass would carry out now, read live.
func (z *DnsZones) PlanZoneSync(ctx context.Context, req *connect.Request[rpmgrv1.PlanZoneSyncRequest]) (
	*connect.Response[rpmgrv1.PlanZoneSyncResponse], error) {
	row, pl, err := z.previewZone(ctx, req.Msg.GetDnsZoneId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.PlanZoneSyncResponse{DnsZone: zoneOf(row), Plan: planOf(pl)}), nil
}

// ApproveZonePlan implements DnsZoneService: the Owner or Admin approves the plan they read, by
// its hash. The plan is computed again now; if it has another hash, nothing changes and the answer
// is PLAN_CHANGED, so that no one approves what they have not seen. The zone becomes active, and
// the next pass applies this plan and no other (docs/15-dns.md, "Held zones and plan approval").
func (z *DnsZones) ApproveZonePlan(ctx context.Context, req *connect.Request[rpmgrv1.ApproveZonePlanRequest]) (
	*connect.Response[rpmgrv1.ApproveZonePlanResponse], error) {
	notHeld := func() error {
		return withReason(connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the zone is not held")), ReasonZoneNotHeld)
	}
	cur, err := z.DB.ReadClient().DNSZone.Get(ctx, req.Msg.GetDnsZoneId())
	if err != nil {
		return nil, storeError(err)
	}
	if cur.SyncState != dnszone.SyncStateHeld {
		return nil, notHeld()
	}
	_, pl, err := z.previewZone(ctx, cur.ID)
	if err != nil {
		return nil, err
	}
	if pl.Hash != req.Msg.GetPlanHash() {
		return nil, withReason(connect.NewError(connect.CodeFailedPrecondition,
			errors.New("apisvc: the plan changed since it was shown; read it again")), ReasonPlanChanged)
	}
	stored, err := json.Marshal(pl)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	var row *ent.DNSZone
	_, err = store.ConfigTx(ctx, z.DB, func(tx *ent.Tx) ([]string, error) {
		var err error
		row, err = tx.DNSZone.UpdateOneID(cur.ID).Where(dnszone.SyncStateEQ(dnszone.SyncStateHeld)).
			SetSyncState(dnszone.SyncStateActive).SetHeldReason("").SetPendingPlan(stored).SetPendingPlanHash(pl.Hash).Save(ctx)
		return []string{cur.ID}, err
	})
	if ent.IsNotFound(err) {
		return nil, notHeld() // changed since it was read
	}
	if err != nil {
		return nil, storeError(err)
	}
	api.AuditReason(ctx, "approved plan "+pl.Hash)
	return connect.NewResponse(&rpmgrv1.ApproveZonePlanResponse{DnsZone: zoneOf(row)}), nil
}
