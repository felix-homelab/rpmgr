// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package controller_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestRun_DNSPublishesRouteRecords is the DNS automation end to end through the running controller
// (docs/15-dns.md): an Owner connects a Cloudflare provider (the fake of cftest), imports a zone,
// which starts held, so that a route in it shows `held` and nothing is written; the Owner approves
// the plan they read, and the DNS job, started by Run under its lease, writes the group's CNAME for
// the route's hostname, which the route then shows as `published` with its record. A name
// that lies outside every managed zone shows no DNS line, and the provider token is in no answer.
func TestRun_DNSPublishesRouteRecords(t *testing.T) {
	const apiToken = "a-token-of-the-test-0123456789"
	fake := cftest.New(t, apiToken)
	cz := fake.AddZone("example.com")
	r := startRunWith(t, runSetup{dnsDial: func(_, account string, tok secret.Value) (dns.Provider, error) {
		return cloudflare.NewForTest(cloudflare.Config{Token: tok, AccountID: account}, fake.URL(), fake.RootCAs())
	}})
	ctx := context.Background()
	const pw = "correct horse battery staple"
	_, tok, _ := strings.Cut(r.firstUserLink, "#")
	if _, err := rpmgrv1connect.NewAuthServiceClient(r.client, r.url).CompletePasswordReset(ctx, connect.NewRequest(
		&rpmgrv1.CompletePasswordResetRequest{Token: tok, NewPassword: pw, Email: "ada@example.com", DisplayName: "Ada"})); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: r.client.Transport, Timeout: 10 * time.Second}
	auth := rpmgrv1connect.NewAuthServiceClient(c, r.url)
	if _, err := auth.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com", Password: pw})); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.StepUp(ctx, connect.NewRequest(&rpmgrv1.StepUpRequest{Password: pw})); err != nil {
		t.Fatal(err)
	}
	sess, err := auth.GetSession(ctx, connect.NewRequest(&rpmgrv1.GetSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	org := sess.Msg.GetMemberships()[0].GetOrgId()
	providersAPI := rpmgrv1connect.NewDnsProviderServiceClient(c, r.url)
	zonesAPI := rpmgrv1connect.NewDnsZoneServiceClient(c, r.url)
	routesAPI := rpmgrv1connect.NewRouteServiceClient(c, r.url)

	cp, err := providersAPI.ConnectDnsProvider(ctx, connect.NewRequest(&rpmgrv1.ConnectDnsProviderRequest{OrgId: org,
		DnsProvider: &rpmgrv1.DnsProvider{Name: "cf", Kind: &rpmgrv1.DnsProvider_Cloudflare{Cloudflare: &rpmgrv1.CloudflareProvider{ApiToken: apiToken}}}}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cp.Msg.String(), apiToken) {
		t.Fatal("the answer holds the token")
	}
	imp, err := zonesAPI.ImportZone(ctx, connect.NewRequest(&rpmgrv1.ImportZoneRequest{DnsProviderId: cp.Msg.GetDnsProvider().GetId(), ProviderZoneId: cz.ID}))
	if err != nil {
		t.Fatal(err)
	}
	zone := imp.Msg.GetDnsZone().GetId()

	// The claim of the zone's apex is verified out of band, a gateway group has a DNS target and
	// the org a route in the zone and another outside it.
	db, err := store.OpenSQLite(ctx, r.h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sys := storetest.SystemCtx(t)
	db.Client().Domain.UpdateOneID(imp.Msg.GetDomain().GetId()).SetStatus("verified").ExecX(sys)
	db.Client().Domain.Create().SetOrgID(org).SetFqdn("elsewhere.test").SetWildcard(true).SetStatus("verified").SetChallengeValue("v").ExecX(sys)
	group := db.Client().GatewayGroup.Create().SetOrgID(org).SetName("edge").SetDNSCname("gw.example.net").SaveX(sys)
	route := func(name, host string) string {
		t.Helper()
		got, err := routesAPI.CreateRoute(ctx, connect.NewRequest(&rpmgrv1.CreateRouteRequest{OrgId: org, Route: &rpmgrv1.Route{Name: name, GatewayGroupId: group.ID,
			Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: []string{host}}}}}))
		if err != nil {
			t.Fatal(err)
		}
		return got.Msg.GetRoute().GetId()
	}
	inZone, outside := route("app", "app.example.com"), route("other", "www.elsewhere.test")
	dnsLine := func(id string) *rpmgrv1.HostnameDnsStatus {
		t.Helper()
		got, err := routesAPI.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: id}))
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Msg.GetRoute().GetDnsStatus()) == 0 {
			return nil
		}
		return got.Msg.GetRoute().GetDnsStatus()[0]
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(45 * time.Second); !ok(); time.Sleep(100 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out: %s", what)
			}
		}
	}

	// The zone is held: the job plans, and writes nothing.
	waitFor("the route shows held", func() bool { l := dnsLine(inZone); return l != nil && l.GetStatus() == "held" })
	if n := len(fake.Records(cz.ID)); n != 0 {
		t.Fatalf("%d records were written into a held zone", n)
	}
	if l := dnsLine(outside); l != nil && l.GetStatus() != "not_managed" {
		t.Fatalf("a route outside every zone: %v", l)
	}

	plan, err := zonesAPI.PlanZoneSync(ctx, connect.NewRequest(&rpmgrv1.PlanZoneSyncRequest{DnsZoneId: zone}))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Msg.GetPlan().GetCreates()) != 1 || plan.Msg.GetPlan().GetCreates()[0].GetName() != "app.example.com" {
		t.Fatalf("plan: %v", plan.Msg.GetPlan())
	}
	if _, err := zonesAPI.ApproveZonePlan(ctx, connect.NewRequest(&rpmgrv1.ApproveZonePlanRequest{DnsZoneId: zone, PlanHash: plan.Msg.GetPlan().GetHash()})); err != nil {
		t.Fatal(err)
	}
	waitFor("the route shows published", func() bool { l := dnsLine(inZone); return l != nil && l.GetStatus() == "published" })
	recs := fake.Records(cz.ID)
	if len(recs) != 1 || recs[0].Type != "CNAME" || recs[0].Name != "app.example.com" || recs[0].Content != "gw.example.net" {
		t.Fatalf("records at the provider: %+v", recs)
	}
	if l := dnsLine(inZone); len(l.GetRecords()) != 1 || l.GetRecords()[0] != "CNAME gw.example.net" {
		t.Fatalf("the route's DNS line: %v", l)
	}
}
