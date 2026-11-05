// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"time"
)

// TestDNSReserved (docs/15-dns.md, "Publication rules", rule 6): the names the DNS job never writes
// are the public URL's host, the aliases and endpoints of the instance settings, and each
// gateway's tunnel endpoints and WSS hostname, in lower case and without a port; a gateway that is
// decommissioned reserves nothing.
func TestDNSReserved(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	c := db.Client()
	reserved := controller.DNSReserved(db, "https://rpmgr.example.com:8443")

	if got := reserved(sys); !slices.Equal(got, []string{"rpmgr.example.com"}) {
		t.Fatalf("at the start: %v", got)
	}
	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{
		PublicUrlAliases:    []string{"https://Alias.example.com"},
		ControllerEndpoints: []string{"https://ctl.example.com:9443"},
	}, &fieldmaskpb.FieldMask{Paths: []string{"public_url_aliases", "controller_endpoints"}}, 0); err != nil {
		t.Fatal(err)
	}
	group := c.GatewayGroup.Create().SetOrgID(org).SetName("eu").SaveX(sys)
	c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group.ID).SetName("gw1").SetTunnelEndpoints([]string{"gw1.example.net:443", "203.0.113.5:443"}).
		SetWssHostname("wss.example.net").SaveX(sys)
	c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group.ID).SetName("gone").SetTunnelEndpoints([]string{"gone.example.net:443"}).
		SetDecommissionedAt(time.Now()).SaveX(sys)

	got := reserved(sys)
	slices.Sort(got)
	want := []string{"203.0.113.5", "alias.example.com", "ctl.example.com", "gw1.example.net", "rpmgr.example.com", "wss.example.net"}
	if !slices.Equal(got, want) {
		t.Fatalf("reserved %v, want %v", got, want)
	}
}
