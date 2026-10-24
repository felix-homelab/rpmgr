// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestSetWSSHostname (docs/04-security.md, "Route edge rules"): a gateway's WSS hostname lies under
// a verified domain of its org, is no wildcard, no route hostname of its group and no other
// gateway's; a route cannot take a gateway's WSS hostname either; an empty name removes it.
func TestSetWSSHostname(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		f.verifiedExample(t)
		c := db.Client()
		set := func(gw, name string) error {
			return f.tx(t, func(tx *ent.Tx) error { _, err := routes.SetWSSHostname(f.sys, tx, gw, name); return err })
		}
		f.httpRoute(t, "web", true, true, nil, "app.example.com")
		for name, want := range map[string]error{
			"tunnel.other.example":    domains.ErrNotOwned,
			"*.example.com":           nil, // refused by Normalize, checked below
			"app.example.com":         routes.ErrWSSHostnameTaken,
			"tunnel.example.com":      nil,
			"TUNNEL.example.com.":     nil, // the same name, normalised
			"gw-1.tunnel.example.com": nil,
		} {
			err := set(f.gateway, name)
			switch {
			case name == "*.example.com":
				if err == nil {
					t.Errorf("a wildcard was accepted")
				}
			case want == nil && err != nil:
				t.Errorf("%s: %v", name, err)
			case want != nil && !errors.Is(err, want):
				t.Errorf("%s: %v, want %v", name, err, want)
			}
		}
		if err := set(f.gateway, "tunnel.example.com"); err != nil {
			t.Fatal(err)
		}
		if gw := c.Gateway.GetX(f.sys, f.gateway); gw.WssHostname == nil || *gw.WssHostname != "tunnel.example.com" {
			t.Fatalf("stored %v", gw.WssHostname)
		}
		other := c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetName("gw2").SetSlot(2).
			SetTunnelEndpoints([]string{"gw2.example:443"}).SaveX(f.sys).ID
		if err := set(other, "tunnel.example.com"); !errors.Is(err, routes.ErrWSSHostnameTaken) {
			t.Errorf("another gateway's name: %v", err)
		}
		web2 := c.Route.Create().SetOrgID(f.orgA).SetName("web2").SetType("http").SetGatewayGroupID(f.groupA).SaveX(f.sys).ID
		if err := f.tx(t, func(tx *ent.Tx) error {
			_, err := routes.AddHostname(f.sys, tx, web2, "tunnel.example.com", "")
			return err
		}); !errors.Is(err, routes.ErrHostnameTaken) {
			t.Errorf("a route took a gateway's WSS hostname: %v", err)
		}
		if err := set(f.gateway, ""); err != nil || c.Gateway.GetX(f.sys, f.gateway).WssHostname != nil {
			t.Fatalf("removed: %v", err)
		}
	})
}

// TestCompile_WSSCertificate: a gateway's snapshot carries the certificate of its WSS hostname:
// an uploaded certificate of its org that covers it, else its active ACME certificate; another
// gateway of the group does not get it, and one without a certificate gets none yet.
func TestCompile_WSSCertificate(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		f.verifiedExample(t)
		c := db.Client()
		if err := f.tx(t, func(tx *ent.Tx) error {
			_, err := routes.SetWSSHostname(f.sys, tx, f.gateway, "tunnel.example.com")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		certsOf := func(gw string) map[string][]string {
			out := map[string][]string{}
			for _, r := range f.compile(t, pki.KindGateway, gw) {
				if g := r.GetGatewayCertificate(); g != nil {
					out[r.GetId()] = g.GetHostnames()
				}
			}
			return out
		}
		if got := certsOf(f.gateway); len(got) != 0 {
			t.Fatalf("a certificate before there was one: %v", got)
		}
		notAfter := time.Unix(1893456000, 0)
		row := func(src certificate.Source, sans ...string) string {
			return c.Certificate.Create().SetOrgID(f.orgA).SetSource(src).SetSans(sans).SetNotBefore(time.Now()).SetNotAfter(notAfter).
				SetChain([]byte{1}).SetKeyEnc([]byte{2}).SetContentSha256([]byte{3}).SaveX(f.sys).ID
		}
		acmeID := row(certificate.SourceAcme, "tunnel.example.com")
		if got := certsOf(f.gateway); !slices.Equal(got[acmeID], []string{"tunnel.example.com"}) || len(got) != 1 {
			t.Fatalf("the ACME certificate: %v", got)
		}
		uploaded := row(certificate.SourceUploaded, "*.example.com")
		if got := certsOf(f.gateway); !slices.Equal(got[uploaded], []string{"tunnel.example.com"}) || len(got) != 1 {
			t.Fatalf("an uploaded certificate covering the name: %v", got)
		}
		other := c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetName("gw2").SetSlot(2).
			SetTunnelEndpoints([]string{"gw2.example:443"}).SaveX(f.sys).ID
		if got := certsOf(other); len(got) != 0 {
			t.Fatalf("another gateway got the WSS certificate: %v", got)
		}
	})
}

// TestCompile_GatewayWSS: a gateway that announces tunnel.wss gets its WSS hostname; one without
// the capability, a disabled one and one without a name get none.
func TestCompile_GatewayWSS(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		f.verifiedExample(t)
		wss := func(caps ...string) string {
			for _, r := range f.compileAs(t, pki.KindGateway, f.gateway, caps...) {
				if g := r.GetGatewayWss(); g != nil {
					return g.GetHostname()
				}
			}
			return ""
		}
		if got := wss(agentproto.CapTunnelWSS); got != "" {
			t.Fatalf("without a name: %q", got)
		}
		if err := f.tx(t, func(tx *ent.Tx) error {
			_, err := routes.SetWSSHostname(f.sys, tx, f.gateway, "tunnel.example.com")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if got := wss(agentproto.CapTunnelWSS); got != "tunnel.example.com" {
			t.Fatalf("with the capability: %q", got)
		}
		if got := wss(); got != "" {
			t.Fatalf("a gateway without tunnel.wss got %q", got)
		}
		db.Client().Gateway.UpdateOneID(f.gateway).SetEnabled(false).ExecX(f.sys)
		if got := wss(agentproto.CapTunnelWSS); got != "" {
			t.Fatalf("a disabled gateway got %q", got)
		}
	})
}
