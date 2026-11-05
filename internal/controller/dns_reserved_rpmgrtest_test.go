// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package controller_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	dnsjob "github.com/felix-homelab/rpmgr/internal/dns/job"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestDNS_ReservedNamesNeverWritten (docs/12-testing-and-quality.md): with the reserved names the
// controller hands the DNS job (DNSReserved), a DNS name asking for the controller's public URL, an
// alias, an advertised endpoint, a gateway's tunnel endpoint or WSS hostname, or an
// `_acme-challenge` name produces no record at the provider, and shows `not_managed`; an ordinary
// name in the same zone is published.
func TestDNS_ReservedNamesNeverWritten(t *testing.T) {
	const apiToken = "a-token-of-the-test-0123456789"
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	c := db.Client()
	fake := cftest.New(t, apiToken)
	cz := fake.AddZone("example.com")
	kek, _ := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	sealer, _ := secret.NewSealer(kek)
	pid := ids.New("dnp")
	sealed, err := sealer.Seal(providers.SecretContext(pid), secret.New(apiToken))
	if err != nil {
		t.Fatal(err)
	}
	c.DNSProvider.Create().SetID(pid).SetOrgID(org).SetKind("cloudflare").SetName("cf").SetCredentialEnc(sealed).ExecX(sys)
	zone := c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(pid).SetProviderZoneID(cz.ID).SetName("example.com").SetSyncState("active").SaveX(sys)
	group := c.GatewayGroup.Create().SetOrgID(org).SetName("edge").SetDNSCname("gw.example.net").SaveX(sys)
	dom := c.Domain.Create().SetOrgID(org).SetFqdn("example.com").SetWildcard(true).SetStatus("verified").SetChallengeValue("v").SaveX(sys)
	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{PublicUrlAliases: []string{"https://alias.example.com"},
		ControllerEndpoints: []string{"https://ctl.example.com:9443"}}, &fieldmaskpb.FieldMask{Paths: []string{"public_url_aliases", "controller_endpoints"}}, 0); err != nil {
		t.Fatal(err)
	}
	c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group.ID).SetName("gw1").SetTunnelEndpoints([]string{"tunnel.example.com:443"}).
		SetWssHostname("wss.example.com").SaveX(sys)
	names := []string{"panel.example.com", "alias.example.com", "ctl.example.com", "tunnel.example.com", "wss.example.com",
		"_acme-challenge.example.com", "app.example.com"}
	for _, n := range names {
		c.DNSName.Create().SetOrgID(org).SetFqdn(n).SetGatewayGroupID(group.ID).SetDomainID(dom.ID).SaveX(sys)
	}

	now := time.Now().UTC()
	leases := lease.New(db, "ctn_test", nil)
	j := dnsjob.New(dnsjob.Options{DB: db, Leases: leases, Sealer: sealer, TrustDomain: "test.rpmgr", Now: func() time.Time { return now },
		Budget: &budget.Budget{DB: db}, Reserved: controller.DNSReserved(db, "https://panel.example.com"),
		Dial: func(_, account string, tok secret.Value) (dns.Provider, error) {
			return cloudflare.NewForTest(cloudflare.Config{Token: tok, AccountID: account}, fake.URL(), fake.RootCAs())
		}})
	ls, ok, err := leases.TryAcquireFor(sys, dnsjob.LeaseName, dnsjob.LeaseTTL)
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	j.Sync(zone.ID)
	if err := j.Run(context.WithoutCancel(sys), ls); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range fake.Records(cz.ID) {
		got = append(got, r.Name)
	}
	if !slices.Equal(got, []string{"app.example.com"}) {
		t.Fatalf("records at the provider: %v, want app.example.com alone", got)
	}
	for _, n := range c.DNSNameStatus.Query().AllX(sys) {
		want := "not_managed"
		if n.Name == "app.example.com" {
			want = "published"
		}
		if string(n.Status) != want {
			t.Errorf("%s is %s, want %s", n.Name, n.Status, want)
		}
	}
}
