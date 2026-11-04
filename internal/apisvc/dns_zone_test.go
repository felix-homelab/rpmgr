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
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/dns"
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
			"remove": func() error { return removeZone(u, id, "") },
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
	if err := removeZone(ada, id, "1"); err != nil {
		t.Fatal(err)
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
