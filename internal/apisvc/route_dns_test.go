// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestRoute_DNSStatus (docs/15-dns.md, "Publication rules"): GetRoute and ListRoutes show, for each
// hostname the DNS job recorded a status for, that status with its reason and the records
// published at it; a hostname with none shows none, another org's status of the same name is never
// shown, a rate-limited provider turns a pending name into rate_limited, and the route's own
// status is untouched.
func TestRoute_DNSStatus(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	e.verified(t, org, "example.com", true)
	rt, err := createRoute(ada, org, httpRoute("web", group, "app.example.com", "other.example.com", "plain.example.com"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.GetDnsStatus()) != 0 {
		t.Fatalf("a route nobody published: %v", rt.GetDnsStatus())
	}

	p := c.DNSProvider.Create().SetID(ids.New("dnp")).SetOrgID(org).SetKind("cloudflare").SetName("cf").SetCredentialEnc([]byte("x")).SaveX(e.sys)
	z := c.DNSZone.Create().SetOrgID(org).SetDNSProviderID(p.ID).SetProviderZoneID("pz").SetName("example.com").SetSyncState("active").SaveX(e.sys)
	c.DNSNameStatus.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("app.example.com").SetStatus("published").ExecX(e.sys)
	c.DNSNameStatus.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("other.example.com").SetStatus("conflict").SetReason("foreign").ExecX(e.sys)
	c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("app.example.com").SetType("A").SetContent("192.0.2.10").SetTTL(300).SetState("synced").ExecX(e.sys)
	c.DNSRecord.Create().SetOrgID(org).SetDNSZoneID(z.ID).SetName("app.example.com").SetType("A").SetContent("192.0.2.99").SetTTL(300).SetState("deleting").ExecX(e.sys)
	// Another org's zone has a status for a name of the same spelling: it is never shown.
	stranger := storetest.Org(t, e.db, "dns-stranger")
	sp := c.DNSProvider.Create().SetID(ids.New("dnp")).SetOrgID(stranger).SetKind("cloudflare").SetName("cf2").SetCredentialEnc([]byte("x")).SaveX(e.sys)
	sz := c.DNSZone.Create().SetOrgID(stranger).SetDNSProviderID(sp.ID).SetProviderZoneID("pz2").SetName("stranger.test").SaveX(e.sys)
	c.DNSNameStatus.Create().SetOrgID(stranger).SetDNSZoneID(sz.ID).SetName("plain.example.com").SetStatus("error").SetReason("secret").ExecX(e.sys)

	got, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: rt.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	st := map[string]*rpmgrv1.HostnameDnsStatus{}
	for _, s := range got.Msg.GetRoute().GetDnsStatus() {
		st[s.GetHostname()] = s
	}
	if len(st) != 2 || st["app.example.com"].GetStatus() != "published" || len(st["app.example.com"].GetRecords()) != 1 ||
		st["app.example.com"].GetRecords()[0] != "A 192.0.2.10" ||
		st["other.example.com"].GetStatus() != "conflict" || st["other.example.com"].GetReason() != "foreign" {
		t.Fatalf("dns_status: %v", got.Msg.GetRoute().GetDnsStatus())
	}
	if _, ok := st["plain.example.com"]; ok {
		t.Fatal("another org's status is shown")
	}
	if got.Msg.GetRoute().GetStatus() == nil {
		t.Fatal("the route's own status is gone")
	}

	// A pending name of a zone whose provider rate-limits says so, in a list as well.
	c.DNSNameStatus.Update().Where().SetStatus("pending").ExecX(e.sys)
	z.Update().SetProviderStatus("rate_limited").ExecX(e.sys)
	list, err := ada.rt.ListRoutes(ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org}))
	if err != nil || len(list.Msg.GetRoutes()) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	for _, s := range list.Msg.GetRoutes()[0].GetDnsStatus() {
		if s.GetStatus() != "rate_limited" {
			t.Fatalf("%s is %s, want rate_limited", s.GetHostname(), s.GetStatus())
		}
	}
	if len(list.Msg.GetRoutes()[0].GetDnsStatus()) != 2 {
		t.Fatalf("list: %v", list.Msg.GetRoutes()[0].GetDnsStatus())
	}
}
