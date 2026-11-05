// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsprovider"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// zoneLister is a provider whose token is good and which lists zones.
type zoneLister struct {
	zones []dns.Zone
	err   error
}

func (zoneLister) Verify(context.Context) (dns.TokenInfo, error) {
	return dns.TokenInfo{Status: "active"}, nil
}
func (z zoneLister) ListZones(context.Context) ([]dns.Zone, error)           { return z.zones, z.err }
func (zoneLister) ListRecords(context.Context, string) ([]dns.Record, error) { return nil, nil }
func (zoneLister) Apply(context.Context, string, dns.Batch) error            { return nil }
func (zoneLister) Caps() dns.Capabilities                                    { return dns.Capabilities{} }

// publicNS answers the public nameservers of a domain by name; a name it does not know fails.
type publicNS map[string][]string

func (p publicNS) Delegation(_ context.Context, apex string) ([]string, error) {
	if ns, ok := p[apex]; ok {
		return ns, nil
	}
	return nil, errors.New("lookup failed")
}

// TestDNSTokenJob_Delegation (issue #1144): the hourly check reads the nameservers the provider
// assigned to each imported zone and whether the public DNS delegates the domain to them: a match
// is ok, a domain at a parking provider is a mismatch that names the public nameservers, and a
// failed lookup, a zone the provider no longer lists, a provider that cannot list and a token that
// is refused leave the verdict as it was; nothing is checked without a lookup.
func TestDNSTokenJob_Delegation(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	kek, _ := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	sealer, _ := secret.NewSealer(kek)
	leases := lease.New(db, "ctn_test", nil)
	held, ok, err := leases.TryAcquire(sys, "dns-tokens")
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	assigned := []string{"ada.ns.example.net", "bob.ns.example.net"}
	lister := &zoneLister{zones: []dns.Zone{
		{ID: "pz-ok", Name: "ok.example", NameServers: assigned},
		{ID: "pz-parked", Name: "parked.example", NameServers: assigned},
		{ID: "pz-lookup", Name: "lookup.example", NameServers: assigned},
		{ID: "pz-bare", Name: "bare.example"},
	}}
	dial := func(_, _ string, _ secret.Value) (dns.Provider, error) { return lister, nil }
	org := storetest.Org(t, db, "org-a")
	c := db.Client()
	pid := ids.New("dnp")
	sealed, err := sealer.Seal(providers.SecretContext(pid), secret.New("token-good-0001"))
	if err != nil {
		t.Fatal(err)
	}
	c.DNSProvider.Create().SetID(pid).SetOrgID(org).SetKind(dnsprovider.KindCloudflare).SetName("cf").SetCredentialEnc(sealed).ExecX(sys)
	zone := func(pz, name string) string {
		return c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(pid).SetProviderZoneID(pz).SetName(name).SaveX(sys).ID
	}
	ok1, parked, lookup, bare, gone := zone("pz-ok", "ok.example"), zone("pz-parked", "parked.example"),
		zone("pz-lookup", "lookup.example"), zone("pz-bare", "bare.example"), zone("pz-gone", "gone.example")
	public := publicNS{"ok.example": {"ada.ns.example.net", "bob.ns.example.net"}, "parked.example": {"ns1.lander.example.net"},
		"bare.example": {"ns1.lander.example.net"}, "gone.example": {"ns1.lander.example.net"}}

	run := func(delegation publicNS) {
		t.Helper()
		o := controller.DNSTokenOptions{DB: db, Leases: leases, Sealer: sealer, Dial: dial, Now: func() time.Time { return now }}
		if delegation != nil {
			o.Delegation = delegation
		}
		if err := controller.DNSTokenJob(o).Run(context.WithoutCancel(sys), held); err != nil {
			t.Fatal(err)
		}
	}
	row := func(id string) *ent.DNSZone { return c.DNSZone.GetX(sys, id) }

	run(nil) // no lookup: the nameservers are not read either
	if r := row(ok1); r.DelegationState != dnszone.DelegationStateUnknown || r.DelegationCheckedAt != nil || len(r.AssignedNameservers) != 0 {
		t.Fatalf("a check without a lookup: %+v", r)
	}

	run(public)
	if r := row(ok1); r.DelegationState != dnszone.DelegationStateOk || !slices.Equal(r.AssignedNameservers, assigned) || r.DelegationCheckedAt == nil {
		t.Errorf("matching: %+v", r)
	}
	if r := row(parked); r.DelegationState != dnszone.DelegationStateMismatch || !slices.Equal(r.DelegationNameservers, []string{"ns1.lander.example.net"}) ||
		!slices.Equal(r.AssignedNameservers, assigned) {
		t.Errorf("parked: %+v", r)
	}
	if r := row(lookup); r.DelegationState != dnszone.DelegationStateUnknown || !slices.Equal(r.AssignedNameservers, assigned) {
		t.Errorf("a failed lookup is no verdict: %+v", r)
	}
	if r := row(bare); r.DelegationState != dnszone.DelegationStateUnknown {
		t.Errorf("a provider that assigns none has nothing to compare: %+v", r)
	}
	if r := row(gone); r.DelegationState != dnszone.DelegationStateUnknown || r.DelegationCheckedAt != nil {
		t.Errorf("a zone the provider does not list: %+v", r)
	}

	// The domain is moved to the provider: the mismatch clears at the next check. A lookup that
	// fails after a verdict makes it unknown again, and a provider that cannot list keeps it.
	public["parked.example"] = assigned
	now = now.Add(providers.CheckEvery)
	run(public)
	if r := row(parked); r.DelegationState != dnszone.DelegationStateOk || !r.DelegationCheckedAt.Equal(now) {
		t.Errorf("after the move: %+v", r)
	}
	lister.err = errors.New("provider unreachable")
	public["ok.example"] = []string{"ns1.lander.example.net"}
	run(public)
	if r := row(ok1); r.DelegationState != dnszone.DelegationStateOk {
		t.Errorf("a provider that cannot list changed a verdict: %+v", r)
	}
}
