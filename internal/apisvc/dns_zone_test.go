// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// zoneEnv is dnsEnv with a connected provider.
func zoneEnv(t *testing.T) (*env, *browser, string, *rpmgrv1.DnsProvider) {
	t.Helper()
	e, ada, org := dnsEnv(t)
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	return e, ada, org, p
}

func importZone(b *browser, provider, zone string) (*rpmgrv1.ImportZoneResponse, error) {
	r, err := b.dnsz.ImportZone(context.Background(), connect.NewRequest(&rpmgrv1.ImportZoneRequest{DnsProviderId: provider, ProviderZoneId: zone}))
	if err != nil {
		return nil, err
	}
	return r.Msg, nil
}

func updateZone(b *browser, z *rpmgrv1.DnsZone, etag string, paths ...string) (*rpmgrv1.DnsZone, error) {
	r, err := b.dnsz.UpdateZone(context.Background(), connect.NewRequest(&rpmgrv1.UpdateZoneRequest{DnsZone: z, Etag: etag,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetDnsZone(), nil
}

func removeZone(b *browser, id, etag string) error {
	_, err := b.dnsz.RemoveZone(context.Background(), connect.NewRequest(&rpmgrv1.RemoveZoneRequest{DnsZoneId: id, Etag: etag}))
	return err
}

func planZone(b *browser, id string) (*rpmgrv1.PlanZoneSyncResponse, error) {
	r, err := b.dnsz.PlanZoneSync(context.Background(), connect.NewRequest(&rpmgrv1.PlanZoneSyncRequest{DnsZoneId: id}))
	if err != nil {
		return nil, err
	}
	return r.Msg, nil
}

func approveZone(b *browser, id, hash string) error {
	_, err := b.dnsz.ApproveZonePlan(context.Background(), connect.NewRequest(&rpmgrv1.ApproveZonePlanRequest{DnsZoneId: id, PlanHash: hash}))
	return err
}

func zoneCount(e *env) int { return e.db.Client().DNSZone.Query().CountX(e.sys) }

// TestDNS_PendingZoneIsNotProof (docs/12-testing-and-quality.md, "Security testing"): a zone that
// the provider calls pending, partial or secondary, or is anything but active and full, is not
// imported, and no claim is made for it; a zone that is imported proves nothing: its claim stays
// pending, and a TXT record that the provider's API shows but the authoritative nameservers do
// not give verifies nothing.
func TestDNS_PendingZoneIsNotProof(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	ctx := context.Background()
	refused := map[string]struct {
		status, typ, reason, words string
	}{
		"pending":             {"pending", "full", apisvc.ReasonZoneNotActive, "pending"},
		"initializing":        {"initializing", "full", apisvc.ReasonZoneNotActive, "pending"},
		"moved":               {"moved", "full", apisvc.ReasonZoneNotActive, "moved"},
		"unknown":             {"deleted", "full", apisvc.ReasonZoneNotActive, "not active"},
		"partial":             {"active", "partial", apisvc.ReasonZoneNotFull, "partial"},
		"secondary":           {"active", "secondary", apisvc.ReasonZoneNotFull, "secondary"},
		"internal":            {"active", "internal", apisvc.ReasonZoneNotFull, "not a full zone"},
		"pending and partial": {"pending", "partial", apisvc.ReasonZoneNotActive, "pending"},
	}
	seen := map[string]string{}
	i := 0
	for name, c := range refused {
		i++
		id := fmt.Sprintf("z-%d", i)
		e.dns.zones = []dns.Zone{{ID: id, Name: fmt.Sprintf("refused%d.example", i), Status: c.status, Type: c.typ}}
		_, err := importZone(ada, p.GetId(), id)
		if code(err) != connect.CodeFailedPrecondition || reason(err) != c.reason || !strings.Contains(fmt.Sprint(err), c.words) {
			t.Errorf("%s: %v (reason %q)", name, err, reason(err))
		}
		if err != nil {
			seen[name] = err.Error()
		}
	}
	// The refusals tell the states apart.
	if seen["pending"] == seen["moved"] || seen["partial"] == seen["secondary"] || seen["pending"] == seen["partial"] {
		t.Errorf("the refusals are not distinct: %v", seen)
	}
	if n := zoneCount(e); n != 0 {
		t.Errorf("%d zones were imported", n)
	}
	if n := e.db.Client().Domain.Query().CountX(e.sys); n != 0 {
		t.Errorf("a refused import made %d claims", n)
	}

	// An active, full zone is imported, held, and proves nothing.
	e.dns.zones = []dns.Zone{{ID: "z-ok", Name: "example.com", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z-ok")
	if err != nil {
		t.Fatal(err)
	}
	claim := r.GetDomain()
	if claim.GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING || claim.GetFqdn() != "example.com" || !claim.GetWildcard() {
		t.Fatalf("the claim of an imported zone: %v", claim)
	}
	if r.GetDnsZone().GetSyncState() != rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_HELD {
		t.Errorf("the zone starts %v", r.GetDnsZone().GetSyncState())
	}
	// The provider's API shows the challenge in the zone; the authoritative nameservers (the
	// verifier) do not give it. The claim stays pending, and the check asks the provider nothing.
	e.dns.records = []dns.Record{{ID: "r1", Type: "TXT", Name: claim.GetChallenge().GetTxtName(), Content: claim.GetChallenge().GetValue()}}
	dials := e.dns.dials()
	v, err := ada.dom.VerifyDomain(ctx, connect.NewRequest(&rpmgrv1.VerifyDomainRequest{DomainId: claim.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	if v.Msg.GetDomain().GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING || v.Msg.GetDomain().GetLastError() == "" {
		t.Errorf("a record only the provider shows verified the claim: %v", v.Msg.GetDomain())
	}
	if e.dns.dials() != dials {
		t.Error("the check of a claim asked the provider")
	}
	// A route under the zone is still refused: nothing is covered until the claim is verified.
	g, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org, GatewayGroup: &rpmgrv1.GatewayGroup{Name: "g2"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createRoute(ada, org, httpRoute("web", g.Msg.GetGatewayGroup().GetId(), "www.example.com"), ""); reason(err) != apisvc.ReasonDomainNotVerified {
		t.Errorf("a route under an unverified zone: %v", err)
	}
	// With the proof at the nameservers, the claim verifies.
	e.txt.prove("example.com")
	if v, err := ada.dom.VerifyDomain(ctx, connect.NewRequest(&rpmgrv1.VerifyDomainRequest{DomainId: claim.GetId()})); err != nil ||
		v.Msg.GetDomain().GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED {
		t.Errorf("the proof at the nameservers: %v %v", v, err)
	}
}

// TestDnsZones_Import: an import makes a held zone with the gates of docs/15-dns.md and a pending
// claim on the apex, wildcard included; a verified domain that covers the zone is used instead, an
// own claim that is already there is reused, and what cannot cover the zone's names is refused.
func TestDnsZones_Import(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	ctx := context.Background()
	e.dns.zones = []dns.Zone{
		{ID: "z1", Name: "example.com", Status: "active", Type: "full"},
		{ID: "z2", Name: "sub.parent.test", Status: "active", Type: "full"},
		{ID: "z3", Name: "own.test", Status: "active", Type: "full"},
		{ID: "z4", Name: "flat.test", Status: "active", Type: "full"},
		{ID: "z5", Name: "com", Status: "active", Type: "full"},
	}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	z := r.GetDnsZone()
	if !strings.HasPrefix(z.GetId(), "dnz_") || z.GetName() != "example.com" || z.GetDnsProviderId() != p.GetId() || z.GetProviderZoneId() != "z1" ||
		z.GetSyncState() != rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_HELD || z.GetHeldReason() != apisvc.HeldImported ||
		z.GetProviderStatus() != rpmgrv1.ZoneProviderStatus_ZONE_PROVIDER_STATUS_OK || !z.GetPublishRouteHostnames() ||
		z.GetAllowProxied() || z.GetAllowWildcards() || z.GetDeleteThreshold() != 10 || z.GetDefaultTtl() != 300 || z.GetEtag() != "1" ||
		z.GetLastSyncedTime() != nil {
		t.Fatalf("imported: %v", z)
	}
	if d := r.GetDomain(); d.GetFqdn() != "example.com" || !d.GetWildcard() || d.GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING {
		t.Fatalf("claim: %v", d)
	}
	if g, err := ada.dnsz.GetZone(ctx, connect.NewRequest(&rpmgrv1.GetZoneRequest{DnsZoneId: z.GetId()})); err != nil || g.Msg.GetDnsZone().GetName() != "example.com" {
		t.Errorf("get: %v %v", g, err)
	}
	if l, err := ada.dnsz.ListZones(ctx, connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org})); err != nil || len(l.Msg.GetDnsZones()) != 1 {
		t.Errorf("list: %v %v", l, err)
	}

	// A duplicate import is refused, and changes nothing.
	if _, err := importZone(ada, p.GetId(), "z1"); code(err) != connect.CodeAlreadyExists || !strings.Contains(err.Error(), "already imported") {
		t.Errorf("a second import: %v", err)
	}
	if zoneCount(e) != 1 || e.db.Client().Domain.Query().CountX(e.sys) != 1 {
		t.Error("a second import changed something")
	}

	// A verified wildcard domain above the zone covers it: no claim is made.
	parent, err := claim(ada, org, "parent.test", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	e.txt.prove("parent.test")
	if _, err := ada.dom.VerifyDomain(ctx, connect.NewRequest(&rpmgrv1.VerifyDomainRequest{DomainId: parent.GetId()})); err != nil {
		t.Fatal(err)
	}
	if r, err := importZone(ada, p.GetId(), "z2"); err != nil || r.GetDomain().GetId() != parent.GetId() ||
		r.GetDomain().GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED || e.db.Client().Domain.Query().CountX(e.sys) != 2 {
		t.Errorf("under a verified wildcard domain: %v %v", r, err)
	}

	// The org's own pending wildcard claim of the apex is reused.
	own, err := claim(ada, org, "own.test", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := importZone(ada, p.GetId(), "z3"); err != nil || r.GetDomain().GetId() != own.GetId() || e.db.Client().Domain.Query().CountX(e.sys) != 3 {
		t.Errorf("with an own claim: %v %v", r, err)
	}

	// An own claim that is not a wildcard does not cover the names below the apex.
	if _, err := claim(ada, org, "flat.test", false, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := importZone(ada, p.GetId(), "z4"); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonZoneClaimNotWildcard {
		t.Errorf("with a claim without the wildcard: %v", err)
	}
	// A name rpmgr does not accept as a domain is refused.
	if _, err := importZone(ada, p.GetId(), "z5"); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a zone named com: %v", err)
	}
	if n := zoneCount(e); n != 3 {
		t.Errorf("%d zones, want 3", n)
	}

	// A zone the provider does not list.
	if _, err := importZone(ada, p.GetId(), "z-none"); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown zone: %v", err)
	}
	if _, err := importZone(ada, "dnp_missing", "z1"); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown provider: %v", err)
	}
	// What the provider answers maps to a code, in fixed words, and imports nothing.
	for name, c := range map[string]struct {
		err  error
		want connect.Code
	}{
		"revoked":      {&dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized}, connect.CodeFailedPrecondition},
		"rate limited": {dns.RateLimited{Until: e.clock.Add(time.Minute)}, connect.CodeResourceExhausted},
		"unreachable":  {errors.New("dial tcp 198.51.100.1:443: i/o timeout"), connect.CodeUnavailable},
	} {
		e.dns.know(dnsToken1, fakeDNSToken{err: c.err})
		if _, err := importZone(ada, p.GetId(), "z4"); code(err) != c.want || strings.Contains(fmt.Sprint(err), "198.51.100.1") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := zoneCount(e); n != 3 {
		t.Errorf("%d zones, want 3", n)
	}
}

// TestDnsZones_ClaimedByAnotherOrg: a zone whose name another org claims is not imported, whatever
// the claim's status, and neither a zone nor a claim is made; nor can an org import a zone that
// another org has imported.
func TestDnsZones_ClaimedByAnotherOrg(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "taken.example", Status: "active", Type: "full"}, {ID: "z2", Name: "shared.example", Status: "active", Type: "full"}}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := claim(bob, orgB, "taken.example", false, 0); err != nil { // not even a wildcard
		t.Fatal(err)
	}
	if _, err := importZone(ada, p.GetId(), "z1"); code(err) != connect.CodeAlreadyExists || !strings.Contains(err.Error(), "another org") {
		t.Errorf("a name another org claims: %v", err)
	}
	if zoneCount(e) != 0 || e.db.Client().Domain.Query().Where().CountX(e.sys) != 1 {
		t.Error("the refused import left something behind")
	}

	// Bob imports shared.example from his own provider; Ada then cannot claim it, nor import it.
	pb, err := connectProvider(bob, orgB, "bobs", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importZone(bob, pb.GetId(), "z2"); err != nil {
		t.Fatal(err)
	}
	if _, err := importZone(ada, p.GetId(), "z2"); code(err) != connect.CodeAlreadyExists {
		t.Errorf("a zone another org imported: %v", err)
	}
	if n := e.db.Client().DNSZone.Query().Where().CountX(e.sys); n != 1 {
		t.Errorf("%d zones, want Bob's", n)
	}
	// Ada's org holds no row of either.
	if l, err := ada.dnsz.ListZones(context.Background(), connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org})); err != nil || len(l.Msg.GetDnsZones()) != 0 {
		t.Errorf("ada lists %v %v", l, err)
	}
}

// TestDnsZones_OtherOrg: another org's zone and provider, and an org the caller is not in, are
// NOT_FOUND to every method, and nothing changes.
func TestDnsZones_OtherOrg(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	ctx := context.Background()
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetDnsZone().GetId()
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"get": func() error {
			_, err := bob.dnsz.GetZone(ctx, connect.NewRequest(&rpmgrv1.GetZoneRequest{DnsZoneId: id}))
			return err
		},
		"update": func() error {
			_, err := updateZone(bob, &rpmgrv1.DnsZone{Id: id, AllowProxied: true}, "", "allow_proxied")
			return err
		},
		"remove":                 func() error { return removeZone(bob, id, "") },
		"plan":                   func() error { _, err := planZone(bob, id); return err },
		"approve":                func() error { return approveZone(bob, id, strings.Repeat("a", 64)) },
		"import with a provider": func() error { _, err := importZone(bob, p.GetId(), "z1"); return err },
		"list org a": func() error {
			_, err := bob.dnsz.ListZones(ctx, connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org}))
			return err
		},
	} {
		if got := code(call()); got != connect.CodeNotFound {
			t.Errorf("%s: %v", name, got)
		}
	}
	row := e.db.Client().DNSZone.GetX(e.sys, id)
	if row.AllowProxied || row.Version != 1 || row.OrgID != org {
		t.Error("another org's call changed the zone")
	}
}

// TestDnsZones_Roles: Owners and Admins manage zones; an Operator and a Viewer cannot even read
// them.
func TestDnsZones_Roles(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	ctx := context.Background()
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}, {ID: "z2", Name: "admin.example", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetDnsZone().GetId()
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if _, err := importZone(adm, p.GetId(), "z2"); err != nil {
		t.Errorf("an Admin imports: %v", err)
	}
	for _, role := range []string{"operator", "viewer"} {
		u, _ := e.join(t, ada, org, role+"@example.com", role)
		calls := map[string]func() error{
			"import": func() error { _, err := importZone(u, p.GetId(), "z1"); return err },
			"get": func() error {
				_, err := u.dnsz.GetZone(ctx, connect.NewRequest(&rpmgrv1.GetZoneRequest{DnsZoneId: id}))
				return err
			},
			"list": func() error {
				_, err := u.dnsz.ListZones(ctx, connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org}))
				return err
			},
			"update": func() error {
				_, err := updateZone(u, &rpmgrv1.DnsZone{Id: id, AllowProxied: true}, "", "allow_proxied")
				return err
			},
			"remove":  func() error { return removeZone(u, id, "") },
			"plan":    func() error { _, err := planZone(u, id); return err },
			"approve": func() error { return approveZone(u, id, strings.Repeat("a", 64)) },
		}
		for name, call := range calls {
			if c := code(call()); c != connect.CodePermissionDenied {
				t.Errorf("a %s calls %s: %v", role, name, c)
			}
		}
	}
	if n := zoneCount(e); n != 2 {
		t.Errorf("%d zones, want the 2 of the Owner and the Admin", n)
	}
}

// TestDnsZones_Update: the gates and the default TTL change as the mask says and nothing else;
// values out of range, a path that is not allowed, and a stale etag are refused.
func TestDnsZones_Update(t *testing.T) {
	e, ada, _, p := zoneEnv(t)
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	z := r.GetDnsZone()
	got, err := updateZone(ada, &rpmgrv1.DnsZone{Id: z.GetId(), AllowProxied: true, AllowWildcards: true, PublishRouteHostnames: false, DeleteThreshold: 0, DefaultTtl: 120},
		"1", "allow_proxied", "allow_wildcards", "publish_route_hostnames", "delete_threshold", "default_ttl")
	if err != nil || !got.GetAllowProxied() || !got.GetAllowWildcards() || got.GetPublishRouteHostnames() || got.GetDeleteThreshold() != 0 ||
		got.GetDefaultTtl() != 120 || got.GetEtag() != "2" || got.GetSyncState() != z.GetSyncState() || got.GetName() != "example.com" {
		t.Fatalf("updated: %v %v", got, err)
	}
	// Fields the mask does not name stay.
	if got, err := updateZone(ada, &rpmgrv1.DnsZone{Id: z.GetId(), DefaultTtl: 600}, "", "default_ttl"); err != nil || got.GetDefaultTtl() != 600 || !got.GetAllowProxied() {
		t.Errorf("one field: %v %v", got, err)
	}
	for name, c := range map[string]struct {
		z     *rpmgrv1.DnsZone
		etag  string
		paths []string
		want  connect.Code
	}{
		"ttl too low":       {&rpmgrv1.DnsZone{Id: z.GetId(), DefaultTtl: 59}, "", []string{"default_ttl"}, connect.CodeInvalidArgument},
		"ttl too high":      {&rpmgrv1.DnsZone{Id: z.GetId(), DefaultTtl: 86401}, "", []string{"default_ttl"}, connect.CodeInvalidArgument},
		"ttl unset":         {&rpmgrv1.DnsZone{Id: z.GetId()}, "", []string{"default_ttl"}, connect.CodeInvalidArgument},
		"threshold too big": {&rpmgrv1.DnsZone{Id: z.GetId(), DeleteThreshold: 1001}, "", []string{"delete_threshold"}, connect.CodeInvalidArgument},
		"negative":          {&rpmgrv1.DnsZone{Id: z.GetId(), DeleteThreshold: -1}, "", []string{"delete_threshold"}, connect.CodeInvalidArgument},
		"the name":          {&rpmgrv1.DnsZone{Id: z.GetId(), Name: "other.example"}, "", []string{"name"}, connect.CodeInvalidArgument},
		"the state":         {&rpmgrv1.DnsZone{Id: z.GetId(), SyncState: rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_ACTIVE}, "", []string{"sync_state"}, connect.CodeInvalidArgument},
		"the provider":      {&rpmgrv1.DnsZone{Id: z.GetId(), DnsProviderId: "dnp_x"}, "", []string{"dns_provider_id"}, connect.CodeInvalidArgument},
		"no mask":           {&rpmgrv1.DnsZone{Id: z.GetId(), AllowProxied: false}, "", nil, connect.CodeInvalidArgument},
		"unknown path":      {&rpmgrv1.DnsZone{Id: z.GetId()}, "", []string{"nope"}, connect.CodeInvalidArgument},
		"stale etag":        {&rpmgrv1.DnsZone{Id: z.GetId(), AllowProxied: false}, "1", []string{"allow_proxied"}, connect.CodeFailedPrecondition},
		"missing zone":      {&rpmgrv1.DnsZone{Id: "dnz_missing", AllowProxied: false}, "", []string{"allow_proxied"}, connect.CodeNotFound},
	} {
		if _, err := updateZone(ada, c.z, c.etag, c.paths...); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	row := e.db.Client().DNSZone.GetX(e.sys, z.GetId())
	if row.Name != "example.com" || row.SyncState != "held" || !row.AllowProxied || row.DefaultTTL != 600 {
		t.Errorf("a refused update changed the zone: %+v", row)
	}
}

// TestDnsZones_Remove: a zone is removed with the etag checked; the claim on its apex stays; the
// zone can be imported again; a provider is deleted only after its zones are gone.
func TestDnsZones_Remove(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	ctx := context.Background()
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetDnsZone().GetId()
	delProvider := func() error {
		_, err := ada.dnsp.DeleteDnsProvider(ctx, connect.NewRequest(&rpmgrv1.DeleteDnsProviderRequest{DnsProviderId: p.GetId()}))
		return err
	}
	if err := delProvider(); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("a provider with a zone: %v", err)
	}
	if err := removeZone(ada, id, "9"); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stale etag: %v", err)
	}
	if zoneCount(e) != 1 {
		t.Fatal("a refused removal removed the zone")
	}
	// The ledger rows and name statuses of the zone go with it.
	c := e.db.Client()
	c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(id).SetName("a.example.com").SetType("A").SetContent("192.0.2.1").SetTTL(300).ExecX(e.sys)
	c.DNSNameStatus.Create().SetOrgID(org).SetDNSZoneID(id).SetName("a.example.com").SetStatus("published").ExecX(e.sys)
	c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(id).SetName("b.example.com").SetType("A").SetContent("192.0.2.2").SetTTL(300).SetState("deleting").ExecX(e.sys)
	if err := removeZone(ada, id, "1"); err != nil {
		t.Fatal(err)
	}
	if n := c.DNSRecord.Query().CountX(e.sys); n != 0 {
		t.Errorf("%d ledger rows left after the removal", n)
	}
	if n := c.DNSNameStatus.Query().CountX(e.sys); n != 0 {
		t.Errorf("%d name statuses left after the removal", n)
	}
	if zoneCount(e) != 0 || e.db.Client().Domain.Query().CountX(e.sys) != 1 {
		t.Error("a removal must keep the claim and drop the zone")
	}
	if err := removeZone(ada, id, ""); code(err) != connect.CodeNotFound {
		t.Errorf("a second removal: %v", err)
	}
	again, err := importZone(ada, p.GetId(), "z1")
	if err != nil || again.GetDnsZone().GetId() == id || again.GetDomain().GetId() != r.GetDomain().GetId() {
		t.Errorf("an import after a removal: %v %v", again, err)
	}
	if err := removeZone(ada, again.GetDnsZone().GetId(), ""); err != nil {
		t.Fatal(err)
	}
	if err := delProvider(); err != nil {
		t.Errorf("a provider without zones: %v", err)
	}
	_ = org
}

// TestDnsZones_ListPages: zones come by ID, page by page, with a token that only fits the same
// request.
func TestDnsZones_ListPages(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	ctx := context.Background()
	for i, n := range []string{"a", "b", "c"} {
		id := fmt.Sprintf("z%d", i)
		e.dns.zones = append(e.dns.zones, dns.Zone{ID: id, Name: n + ".example", Status: "active", Type: "full"})
		if _, err := importZone(ada, p.GetId(), id); err != nil {
			t.Fatal(err)
		}
	}
	p1, err := ada.dnsz.ListZones(ctx, connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org, PageSize: 2}))
	if err != nil || len(p1.Msg.GetDnsZones()) != 2 || p1.Msg.GetNextPageToken() == "" {
		t.Fatalf("page 1: %v %v", p1, err)
	}
	p2, err := ada.dnsz.ListZones(ctx, connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org, PageSize: 2, PageToken: p1.Msg.GetNextPageToken()}))
	if err != nil || len(p2.Msg.GetDnsZones()) != 1 || p2.Msg.GetNextPageToken() != "" {
		t.Fatalf("page 2: %v %v", p2, err)
	}
	if _, err := ada.dnsz.ListZones(ctx, connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org, PageToken: "forged"})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a forged page token: %v", err)
	}
	if _, err := ada.dnsz.ListZones(ctx, connect.NewRequest(&rpmgrv1.ListZonesRequest{OrgId: org, PageSize: -1})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a negative page size: %v", err)
	}
}

// TestDnsZones_PlanAndApprove: the plan is read live with its hash; an approval is bound to that
// hash, needs a step-up and an Owner or Admin, and fails with PLAN_CHANGED, changing nothing, when
// the provider's records or the zone changed since the plan was shown; a zone that is not held
// cannot be approved.
func TestDnsZones_PlanAndApprove(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}, {ID: "z2", Name: "other.example", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetDnsZone().GetId()
	row := func() *ent.DNSZone { return e.db.Client().DNSZone.GetX(e.sys, id) }

	// A record of this instance's marker that no ledger row owns is an orphan in the plan.
	e.dns.records = []dns.Record{{ID: "0000000000000000000000000000000a", Type: "A", Name: "old.example.com", Content: "192.0.2.1", TTL: 300, Comment: "rpmgr apitest dnr_gone"}}
	pl, err := planZone(ada, id)
	if err != nil {
		t.Fatal(err)
	}
	hash := pl.GetPlan().GetHash()
	if len(hash) != 64 || len(pl.GetPlan().GetOrphans()) != 1 || pl.GetPlan().GetOrphans()[0].GetName() != "old.example.com" ||
		pl.GetDnsZone().GetSyncState() != rpmgrv1.ZoneSyncState_ZONE_SYNC_STATE_HELD {
		t.Fatalf("plan %v", pl)
	}
	if again, err := planZone(ada, id); err != nil || again.GetPlan().GetHash() != hash {
		t.Fatalf("the same input gave another hash: %v %v", again, err)
	}
	if row().SyncState != "held" || row().Version != 1 {
		t.Fatal("reading a plan changed the zone")
	}

	// Refused, and nothing changes: a hash of the wrong shape or content, a user without a step-up.
	for name, c := range map[string]struct {
		hash string
		code connect.Code
		why  string
	}{
		"short":       {"abc", connect.CodeInvalidArgument, ""},
		"empty":       {"", connect.CodeInvalidArgument, ""},
		"stale":       {strings.Repeat("a", 64), connect.CodeFailedPrecondition, apisvc.ReasonPlanChanged},
		"upper case":  {strings.ToUpper(hash), connect.CodeFailedPrecondition, apisvc.ReasonPlanChanged},
		"with space":  {hash[:63] + " ", connect.CodeFailedPrecondition, apisvc.ReasonPlanChanged},
		"hash of nil": {strings.Repeat("0", 64), connect.CodeFailedPrecondition, apisvc.ReasonPlanChanged},
	} {
		err := approveZone(ada, id, c.hash)
		if code(err) != c.code || reason(err) != c.why {
			t.Errorf("%s: %v (reason %q)", name, err, reason(err))
		}
	}
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if err := approveZone(adm, id, hash); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("without a step-up: %v", err)
	}
	if row().SyncState != "held" || row().PendingPlanHash != "" {
		t.Fatalf("a refused approval changed the zone: %+v", row())
	}

	// The provider's records change after the plan was shown: the approval of the old plan fails.
	e.dns.records = append(e.dns.records, dns.Record{ID: "0000000000000000000000000000000b", Type: "A", Name: "new.example.com", Content: "192.0.2.2", TTL: 300, Comment: "rpmgr apitest dnr_new"})
	if err := approveZone(ada, id, hash); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonPlanChanged {
		t.Fatalf("a plan that changed: %v", err)
	}
	if row().SyncState != "held" {
		t.Fatal("a stale approval activated the zone")
	}
	pl, err = planZone(ada, id)
	if err != nil || pl.GetPlan().GetHash() == hash || len(pl.GetPlan().GetOrphans()) != 2 {
		t.Fatalf("the new plan: %v %v", pl, err)
	}
	hash = pl.GetPlan().GetHash()

	// An Admin, stepped up, approves the plan they read.
	if err := adm.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	revBefore := e.db.Client().ConfigRevision.Query().CountX(e.sys)
	if err := approveZone(adm, id, hash); err != nil {
		t.Fatal(err)
	}
	got := row()
	if got.SyncState != "active" || got.HeldReason != "" || got.PendingPlanHash != hash || len(got.PendingPlan) == 0 {
		t.Fatalf("approved zone %+v", got)
	}
	if e.db.Client().ConfigRevision.Query().CountX(e.sys) != revBefore+1 {
		t.Error("an approval is a configuration change with a revision: the job looks for it")
	}
	// Not held any more, so there is nothing to approve; the plan can still be read.
	if err := approveZone(ada, id, hash); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonZoneNotHeld {
		t.Errorf("a second approval: %v", err)
	}
	if _, err := planZone(ada, id); err != nil {
		t.Errorf("the plan of an active zone: %v", err)
	}
	// A disabled zone, as after restore --dns-disabled, cannot be approved either.
	e.db.Client().DNSZone.UpdateOneID(id).SetSyncState("disabled").ExecX(e.sys)
	if err := approveZone(ada, id, hash); reason(err) != apisvc.ReasonZoneNotHeld {
		t.Errorf("a disabled zone: %v", err)
	}
	if row().SyncState != "disabled" {
		t.Error("an approval enabled a disabled zone")
	}
	if err := approveZone(ada, "dnz_missing", hash); code(err) != connect.CodeNotFound {
		t.Errorf("a missing zone: %v", err)
	}
}

// A provider that fails fails the plan and the approval with the status of the failure, and
// leaves the zone held.
func TestDnsZones_PlanProviderFailures(t *testing.T) {
	e, ada, _, p := zoneEnv(t)
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetDnsZone().GetId()
	for name, c := range map[string]struct {
		err  error
		want connect.Code
	}{
		"revoked":      {&dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized}, connect.CodeFailedPrecondition},
		"rate limited": {dns.RateLimited{Until: e.clock.Add(time.Minute)}, connect.CodeResourceExhausted},
		"unreachable":  {errors.New("dial tcp 198.51.100.1:443: i/o timeout"), connect.CodeUnavailable},
	} {
		e.dns.know(dnsToken1, fakeDNSToken{err: c.err})
		if _, err := planZone(ada, id); code(err) != c.want || strings.Contains(fmt.Sprint(err), "198.51.100.1") {
			t.Errorf("plan, %s: %v", name, err)
		}
		if err := approveZone(ada, id, strings.Repeat("a", 64)); code(err) != c.want {
			t.Errorf("approve, %s: %v", name, err)
		}
	}
	if z := e.db.Client().DNSZone.GetX(e.sys, id); z.SyncState != "held" {
		t.Errorf("zone %+v", z)
	}
}

// recordEnv is a zone example.com whose claim is verified, with a gateway group that has a DNS
// target and the name app.example.com, and a provider that holds a foreign record at that name, one
// at a name nothing publishes, one of a type rpmgr does not own and an orphan.
func recordEnv(t *testing.T) (e *env, ada *browser, org, zone string) {
	t.Helper()
	e, ada, org, group := gatewayEnv(t)
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	e.logs.Secret(dnsToken1)
	e.dns.know(dnsToken1, fakeDNSToken{})
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	e.db.Client().Domain.Update().SetStatus("verified").ExecX(e.sys)
	e.db.Client().GatewayGroup.UpdateOneID(group).SetDNSAddresses([]string{"192.0.2.99"}).ExecX(e.sys)
	if _, err := createName(ada, org, "app.example.com", group, 0); err != nil {
		t.Fatal(err)
	}
	e.dns.records = []dns.Record{
		{ID: "000000000000000000000000000000a1", Type: "A", Name: "app.example.com", Content: "192.0.2.10", TTL: 300, Comment: "hand made"},
		{ID: "000000000000000000000000000000a2", Type: "A", Name: "other.example.com", Content: "192.0.2.11", TTL: 300},
		{ID: "000000000000000000000000000000a3", Type: "MX", Name: "app.example.com", Content: "mail.example.net", TTL: 300},
		{ID: "000000000000000000000000000000a4", Type: "TXT", Name: "old.example.com", Content: "x", TTL: 300, Comment: "rpmgr apitest dnr_gone"},
	}
	return e, ada, org, r.GetDnsZone().GetId()
}

func listRecords(b *browser, zone string, foreign bool) ([]*rpmgrv1.DnsRecord, error) {
	r, err := b.dnsz.ListZoneRecords(context.Background(), connect.NewRequest(&rpmgrv1.ListZoneRecordsRequest{DnsZoneId: zone, IncludeForeign: foreign}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetRecords(), nil
}

func adoptRecords(b *browser, zone string, ids ...string) ([]*rpmgrv1.DnsRecord, error) {
	r, err := b.dnsz.AdoptRecords(context.Background(), connect.NewRequest(&rpmgrv1.AdoptRecordsRequest{DnsZoneId: zone, ProviderRecordIds: ids}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetRecords(), nil
}

func releaseRecord(b *browser, zone, id string, restore bool) (string, error) {
	r, err := b.dnsz.ReleaseRecord(context.Background(), connect.NewRequest(&rpmgrv1.ReleaseRecordRequest{DnsZoneId: zone, RecordId: id, Restore: restore}))
	if err != nil {
		return "", err
	}
	return r.Msg.GetWarning(), nil
}

func states(rs []*rpmgrv1.DnsRecord) map[string]rpmgrv1.DnsRecordState {
	out := map[string]rpmgrv1.DnsRecordState{}
	for _, r := range rs {
		out[r.GetName()+"/"+r.GetType()] = r.GetState()
	}
	return out
}

// TestDnsZones_ListRecords: the owned records are listed for every member from the ledger, without
// asking the provider; the other records, read live, and the orphans only for an Owner or Admin: an
// Operator or Viewer who asks for them is refused and is never sent one.
func TestDnsZones_ListRecords(t *testing.T) {
	e, ada, org, zone := recordEnv(t)
	own := e.db.Client().DNSRecord.Create().SetOrgID(org).SetDNSZoneID(zone).SetName("mine.example.com").SetType("A").SetContent("192.0.2.1").SetTTL(300).
		SetProviderRecordID("000000000000000000000000000000b1").SetState("synced").SaveX(e.sys)
	e.dns.records = append(e.dns.records, dns.Record{ID: "000000000000000000000000000000b1", Type: "A", Name: "mine.example.com", Content: "192.0.2.1", TTL: 300})

	all, err := listRecords(ada, zone, true)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]rpmgrv1.DnsRecordState{
		"mine.example.com/A": rpmgrv1.DnsRecordState_DNS_RECORD_STATE_SYNCED, "app.example.com/A": rpmgrv1.DnsRecordState_DNS_RECORD_STATE_FOREIGN,
		"other.example.com/A": rpmgrv1.DnsRecordState_DNS_RECORD_STATE_FOREIGN, "app.example.com/MX": rpmgrv1.DnsRecordState_DNS_RECORD_STATE_FOREIGN,
		"old.example.com/TXT": rpmgrv1.DnsRecordState_DNS_RECORD_STATE_ORPHANED,
	}
	if got := states(all); len(all) != 5 || fmt.Sprint(got) != fmt.Sprint(want) || all[0].GetId() != own.ID || all[0].GetProviderRecordId() == "" {
		t.Fatalf("records %v\nwant %v", all, want)
	}
	for _, r := range all[1:] {
		if r.GetId() != "" {
			t.Errorf("a record that is not owned has a ledger ID: %v", r)
		}
	}

	dials := e.dns.dials()
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if r, err := listRecords(adm, zone, true); err != nil || len(r) != 5 {
		t.Errorf("an Admin lists everything: %v %v", r, err)
	}
	dials = e.dns.dials() - dials
	for _, role := range []string{"operator", "viewer"} {
		u, _ := e.join(t, ada, org, role+"@example.com", role)
		before := e.dns.dials()
		r, err := listRecords(u, zone, false)
		if err != nil || len(r) != 1 || r[0].GetId() != own.ID {
			t.Errorf("a %s lists the owned records: %v %v", role, r, err)
		}
		if e.dns.dials() != before {
			t.Errorf("a %s's list asked the provider", role)
		}
		r, err = listRecords(u, zone, true)
		if code(err) != connect.CodePermissionDenied || len(r) != 0 {
			t.Errorf("a %s asks for the foreign records: %v %v", role, r, err)
		}
		if e.dns.dials() != before {
			t.Errorf("a refused %s read the provider", role)
		}
	}
	_ = dials

	// Another org sees nothing of the zone, and a missing zone is NOT_FOUND.
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	for _, f := range []bool{false, true} {
		if _, err := listRecords(bob, zone, f); code(err) != connect.CodeNotFound {
			t.Errorf("another org lists (foreign %v): %v", f, err)
		}
	}
	if _, err := listRecords(ada, "dnz_missing", false); code(err) != connect.CodeNotFound {
		t.Errorf("a missing zone: %v", err)
	}
	// A provider that fails fails the live part only.
	e.dns.know(dnsToken1, fakeDNSToken{err: errors.New("dial tcp 198.51.100.1:443: i/o timeout")})
	if _, err := listRecords(ada, zone, true); code(err) != connect.CodeUnavailable {
		t.Errorf("an unreachable provider: %v", err)
	}
	if r, err := listRecords(ada, zone, false); err != nil || len(r) != 1 {
		t.Errorf("the owned records of a zone whose provider is down: %v %v", r, err)
	}
}

// TestDnsZones_AdoptRecords: a foreign record at a name the org publishes is adopted with its
// original kept; a record that is not there, is owned, is of another type or lies at a name nothing
// publishes fails the whole call and adopts none; an Operator and another org are refused.
func TestDnsZones_AdoptRecords(t *testing.T) {
	e, ada, org, zone := recordEnv(t)
	const app, other, mx, orphan = "000000000000000000000000000000a1", "000000000000000000000000000000a2", "000000000000000000000000000000a3", "000000000000000000000000000000a4"
	ledger := func() int { return e.db.Client().DNSRecord.Query().CountX(e.sys) }

	for name, c := range map[string]struct {
		ids  []string
		code connect.Code
		why  string
	}{
		"a name nothing publishes":    {[]string{other}, connect.CodeFailedPrecondition, apisvc.ReasonRecordNotWanted},
		"a type rpmgr does not own":   {[]string{mx}, connect.CodeFailedPrecondition, apisvc.ReasonRecordTypeUnsupported},
		"a record the provider lacks": {[]string{"00000000000000000000000000000fff"}, connect.CodeNotFound, apisvc.ReasonRecordNotFound},
		"one good, one bad":           {[]string{app, other}, connect.CodeFailedPrecondition, apisvc.ReasonRecordNotWanted},
		"an orphan's name":            {[]string{orphan}, connect.CodeFailedPrecondition, apisvc.ReasonRecordNotWanted},
		"a record twice":              {[]string{app, app}, connect.CodeInvalidArgument, ""},
		"none":                        {nil, connect.CodeInvalidArgument, ""},
	} {
		if _, err := adoptRecords(ada, zone, c.ids...); code(err) != c.code || reason(err) != c.why {
			t.Errorf("%s: %v (reason %q)", name, err, reason(err))
		}
	}
	if n := ledger(); n != 0 {
		t.Fatalf("a refused adoption left %d ledger rows", n)
	}
	if _, err := adoptRecords(ada, zone, make([]string, 201)...); code(err) != connect.CodeInvalidArgument {
		t.Errorf("201 records: %v", err)
	}

	// An Operator cannot adopt, and neither can another org's Owner, who does not even see the zone.
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	if _, err := adoptRecords(op, zone, app); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator adopts: %v", err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := adoptRecords(bob, zone, app); code(err) != connect.CodeNotFound {
		t.Errorf("another org adopts: %v", err)
	}
	if n := ledger(); n != 0 {
		t.Fatalf("a refused adoption left %d ledger rows", n)
	}

	rev := e.db.Client().ConfigRevision.Query().CountX(e.sys)
	rs, err := adoptRecords(ada, zone, app)
	if err != nil || len(rs) != 1 || rs[0].GetName() != "app.example.com" || rs[0].GetState() != rpmgrv1.DnsRecordState_DNS_RECORD_STATE_SYNCED ||
		!strings.HasPrefix(rs[0].GetId(), "dnr_") || rs[0].GetProviderRecordId() != app || rs[0].GetAdoptedTime() == nil {
		t.Fatalf("adopted %v, %v", rs, err)
	}
	row := e.db.Client().DNSRecord.GetX(e.sys, rs[0].GetId())
	if row.Content != "192.0.2.10" || row.LastSyncedAt != nil || row.AdoptedAt == nil || !strings.Contains(row.AdoptedFrom, "192.0.2.10") || !strings.Contains(row.AdoptedFrom, "hand made") {
		t.Fatalf("row %+v", row)
	}
	if z := e.db.Client().DNSZone.GetX(e.sys, zone); z.SyncRequestedAt == nil || e.db.Client().ConfigRevision.Query().CountX(e.sys) != rev+1 {
		t.Errorf("the adoption asks for a pass: %+v", z)
	}
	if a := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.DnsZoneService.AdoptRecords"), auditentry.ResultEQ("success")).AllX(e.sys); len(a) != 1 ||
		a[0].ActorType != "user" || !strings.Contains(a[0].Reason, app) || !strings.Contains(a[0].Reason, zone) {
		t.Errorf("audit entries for the adoption: %+v", a)
	}
	if _, err := adoptRecords(ada, zone, app); code(err) != connect.CodeAlreadyExists || reason(err) != apisvc.ReasonRecordAlreadyOwned {
		t.Errorf("a second adoption: %v", err)
	}
	all, err := listRecords(ada, zone, true)
	if err != nil || states(all)["app.example.com/A"] != rpmgrv1.DnsRecordState_DNS_RECORD_STATE_SYNCED || len(all) != 4 {
		t.Errorf("after the adoption: %v %v", all, err)
	}
	// Names are compared the way they are stored: case and a trailing dot do not matter.
	e.dns.records[1].Name = "APP.example.com."
	if _, err := adoptRecords(ada, zone, other); err != nil {
		t.Errorf("a name in another spelling: %v", err)
	}
}

// TestDnsZones_ReleaseRecord: an owned record leaves the ledger and stays at the provider, without
// rpmgr's marker, or with restore as it was adopted; a record that is not owned, one of another
// zone, one the job is writing and a restore without an original are refused; an old original warns.
func TestDnsZones_ReleaseRecord(t *testing.T) {
	e, ada, org, zone := recordEnv(t)
	const app = "000000000000000000000000000000a1"
	c := e.db.Client()
	rs, err := adoptRecords(ada, zone, app)
	if err != nil {
		t.Fatal(err)
	}
	id := rs[0].GetId()
	live := func(rid string) dns.Record {
		for _, r := range e.dns.records {
			if r.ID == rid {
				return r
			}
		}
		return dns.Record{}
	}
	// What the job's first pass does: rewrites the record to what the sources want, with the marker.
	job := func() {
		for i := range e.dns.records {
			if e.dns.records[i].ID == app {
				e.dns.records[i].Content, e.dns.records[i].Comment = "192.0.2.99", "rpmgr apitest "+id
			}
		}
		c.DNSRecord.UpdateOneID(id).SetContent("192.0.2.99").SetLastSyncedAt(time.Now()).ExecX(e.sys)
	}

	// Refused: a record that is not owned, another zone's, and a role that may not.
	other := c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(zone).SetName("busy.example.com").SetType("A").SetContent("192.0.2.9").SetTTL(300).SaveX(e.sys) // creating
	if _, err := releaseRecord(ada, zone, "dnr_missing", false); code(err) != connect.CodeNotFound || reason(err) != apisvc.ReasonRecordNotFound {
		t.Errorf("a record that is not owned: %v", err)
	}
	if _, err := releaseRecord(ada, zone, app, false); code(err) != connect.CodeNotFound {
		t.Errorf("a provider ID is no ledger row: %v", err)
	}
	if _, err := releaseRecord(ada, zone, other.ID, false); reason(err) != apisvc.ReasonRecordBusy {
		t.Errorf("a record the job is creating: %v", err)
	}
	c.DNSRecord.DeleteOneID(other.ID).ExecX(e.sys)
	z2 := c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(c.DNSZone.GetX(e.sys, zone).DNSProviderID).SetProviderZoneID("z2").SetName("two.example").SaveX(e.sys)
	foreignRow := c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(z2.ID).SetName("a.two.example").SetType("A").SetContent("192.0.2.2").SetTTL(300).SetState("synced").SaveX(e.sys)
	if _, err := releaseRecord(ada, zone, foreignRow.ID, false); code(err) != connect.CodeNotFound {
		t.Errorf("a row of another zone: %v", err)
	}
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	if _, err := releaseRecord(op, zone, id, false); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator releases: %v", err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := releaseRecord(bob, zone, id, false); code(err) != connect.CodeNotFound {
		t.Errorf("another org releases: %v", err)
	}
	if _, err := releaseRecord(ada, zone, foreignRow.ID, true); reason(err) != apisvc.ReasonRecordNotAdopted && code(err) != connect.CodeNotFound {
		t.Errorf("restore of a record that was not adopted: %v", err)
	}
	plain := c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(zone).SetName("plain.example.com").SetType("A").SetContent("192.0.2.3").SetTTL(300).SetState("synced").SaveX(e.sys)
	if _, err := releaseRecord(ada, zone, plain.ID, true); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonRecordNotAdopted {
		t.Errorf("restore of a record that was not adopted: %v", err)
	}
	if n := c.DNSRecord.Query().CountX(e.sys); n != 3 || len(e.dns.batches) != 0 {
		t.Fatalf("a refused release changed something: %d rows, %d batches", n, len(e.dns.batches))
	}

	// A provider that is down fails the release, and the row stays.
	e.dns.know(dnsToken1, fakeDNSToken{err: errors.New("dial tcp 198.51.100.1:443: i/o timeout")})
	job()
	if _, err := releaseRecord(ada, zone, id, true); code(err) != connect.CodeUnavailable {
		t.Errorf("an unreachable provider: %v", err)
	}
	e.dns.know(dnsToken1, fakeDNSToken{})
	if c.DNSRecord.Query().Where(dnsrecord.ID(id)).CountX(e.sys) != 1 || live(app).Content != "192.0.2.99" {
		t.Fatal("a failed release changed something")
	}

	// Restore: the record is what it was when it was adopted, comment included, and the row is gone.
	c.DNSRecord.UpdateOneID(id).SetAdoptedAt(time.Now().Add(-31 * 24 * time.Hour)).ExecX(e.sys)
	warn, err := releaseRecord(ada, zone, id, true)
	if err != nil || !strings.Contains(warn, "30 days") {
		t.Fatalf("restore: %q, %v", warn, err)
	}
	if r := live(app); r.Type != "A" || r.Content != "192.0.2.10" || r.Comment != "hand made" {
		t.Fatalf("the record after a restore: %+v", r)
	}
	if c.DNSRecord.Query().Where(dnsrecord.ID(id)).CountX(e.sys) != 0 {
		t.Error("the row is still there")
	}
	if a := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.DnsZoneService.ReleaseRecord"), auditentry.ResultEQ("success")).AllX(e.sys); len(a) != 1 ||
		!strings.Contains(a[0].Reason, id) || !strings.Contains(a[0].Diff, `"restore":true`) {
		t.Errorf("audit entries for the release: %+v", a)
	}
	if _, err := releaseRecord(ada, zone, id, false); code(err) != connect.CodeNotFound {
		t.Errorf("a second release: %v", err)
	}

	// Keep: the marker goes, nothing else changes, and nothing warns; a record that is gone needs
	// no write.
	rs, err = adoptRecords(ada, zone, app)
	if err != nil {
		t.Fatal(err)
	}
	id = rs[0].GetId()
	job()
	writes := len(e.dns.batches)
	if warn, err := releaseRecord(ada, zone, id, false); err != nil || warn != "" {
		t.Fatalf("keep: %q, %v", warn, err)
	}
	if r := live(app); r.Content != "192.0.2.99" || r.Comment != "" || len(e.dns.batches) != writes+1 {
		t.Fatalf("the record after a release: %+v", r)
	}
	gone := c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(zone).SetName("gone.example.com").SetType("A").SetContent("192.0.2.4").SetTTL(300).
		SetProviderRecordID("0000000000000000000000000000dead").SetState("synced").SaveX(e.sys)
	if _, err := releaseRecord(ada, zone, gone.ID, false); err != nil || len(e.dns.batches) != writes+1 {
		t.Errorf("a record that is gone at the provider: %v, %d writes", err, len(e.dns.batches)-writes)
	}
	// An adopted record the job has not written yet carries no marker: nothing to take off. One
	// whose type the job changed has no original that fits: the restore is refused.
	e.dns.records[0].Comment = "hand made"
	rs, err = adoptRecords(ada, zone, app)
	if err != nil {
		t.Fatal(err)
	}
	writes = len(e.dns.batches)
	if _, err := releaseRecord(ada, zone, rs[0].GetId(), false); err != nil || len(e.dns.batches) != writes || live(app).Comment != "hand made" {
		t.Errorf("a record the job has not written: %v, %d writes, %+v", err, len(e.dns.batches)-writes, live(app))
	}
	rs, err = adoptRecords(ada, zone, app)
	if err != nil {
		t.Fatal(err)
	}
	e.dns.records[0].Type = "AAAA"
	if _, err := releaseRecord(ada, zone, rs[0].GetId(), true); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonRecordNotRestorable {
		t.Errorf("a record whose type changed: %v", err)
	}
	if c.DNSRecord.Query().Where(dnsrecord.ID(rs[0].GetId())).CountX(e.sys) != 1 {
		t.Error("a refused restore dropped the row")
	}
}

// TestDnsZones_SyncZone: the request is written to the row; a disabled zone, another org and a role
// that may not are refused.
func TestDnsZones_SyncZone(t *testing.T) {
	e, ada, org, zone := recordEnv(t)
	sync := func(b *browser, id string) error {
		_, err := b.dnsz.SyncZone(context.Background(), connect.NewRequest(&rpmgrv1.SyncZoneRequest{DnsZoneId: id}))
		return err
	}
	if err := sync(ada, zone); err != nil {
		t.Fatal(err)
	}
	first := e.db.Client().DNSZone.GetX(e.sys, zone).SyncRequestedAt
	if first == nil {
		t.Fatal("no request written")
	}
	e.clock = e.clock.Add(time.Minute)
	if err := sync(ada, zone); err != nil {
		t.Fatal(err)
	}
	if second := e.db.Client().DNSZone.GetX(e.sys, zone).SyncRequestedAt; !second.After(*first) {
		t.Errorf("a second request did not move the time: %v then %v", first, second)
	}
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	if err := sync(op, zone); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator: %v", err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if err := sync(bob, zone); code(err) != connect.CodeNotFound {
		t.Errorf("another org: %v", err)
	}
	if err := sync(ada, "dnz_missing"); code(err) != connect.CodeNotFound {
		t.Errorf("a missing zone: %v", err)
	}
	e.db.Client().DNSZone.UpdateOneID(zone).SetSyncState("disabled").ClearSyncRequestedAt().ExecX(e.sys)
	if err := sync(ada, zone); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonZoneDisabled {
		t.Errorf("a disabled zone: %v", err)
	}
	if e.db.Client().DNSZone.GetX(e.sys, zone).SyncRequestedAt != nil {
		t.Error("a disabled zone was asked to sync")
	}
}

// TestDnsZones_EnableZone: a disabled zone becomes held and nothing else; it needs a step-up and an
// Owner or Admin; a zone that is not disabled and another org's are refused; the enabled zone still
// needs an approved plan.
func TestDnsZones_EnableZone(t *testing.T) {
	e, ada, org, p := zoneEnv(t)
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}}
	r, err := importZone(ada, p.GetId(), "z1")
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetDnsZone().GetId()
	enable := func(b *browser, zone string) error {
		_, err := b.dnsz.EnableZone(context.Background(), connect.NewRequest(&rpmgrv1.EnableZoneRequest{DnsZoneId: zone}))
		return err
	}
	if err := enable(ada, id); reason(err) != apisvc.ReasonZoneNotDisabled {
		t.Errorf("a held zone: %v", err)
	}
	e.db.Client().DNSZone.UpdateOneID(id).SetSyncState("disabled").SetPendingPlanHash("x").ExecX(e.sys)
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	if err := op.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if err := enable(adm, id); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("without a step-up: %v", err)
	}
	if err := enable(op, id); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator: %v", err)
	}
	if err := enable(bob, id); code(err) != connect.CodeNotFound {
		t.Errorf("another org: %v", err)
	}
	if err := enable(ada, "dnz_missing"); code(err) != connect.CodeNotFound {
		t.Errorf("a missing zone: %v", err)
	}
	if e.db.Client().DNSZone.GetX(e.sys, id).SyncState != "disabled" {
		t.Fatal("a refused call enabled the zone")
	}
	if err := enable(ada, id); err != nil {
		t.Fatal(err)
	}
	if z := e.db.Client().DNSZone.GetX(e.sys, id); z.SyncState != "held" || z.HeldReason != "enabled" || z.PendingPlanHash != "" {
		t.Fatalf("zone %+v", z)
	}
	// A hash that was never approved activates nothing: approval is still needed.
	if err := approveZone(ada, id, strings.Repeat("a", 64)); reason(err) != apisvc.ReasonPlanChanged {
		t.Errorf("approval after enabling: %v", err)
	}
	pl, err := planZone(ada, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := approveZone(ada, id, pl.GetPlan().GetHash()); err != nil {
		t.Errorf("approving the plan read: %v", err)
	}
}
