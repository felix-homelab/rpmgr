// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectlistener"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestCompile_ConnectListenerCertificate (#934): a TLS CONNECT listener that names no certificate
// presents an uploaded certificate of its org that covers its hostname, else its ACME one, and
// none before there is one; one that names a certificate presents that one; only the gateways of
// the listener's group get it, and only while an enabled route is on the listener.
func TestCompile_ConnectListenerCertificate(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		f.verifiedExample(t)
		c := db.Client()
		var route string
		listener := func(cert string) string {
			var id string
			if err := f.tx(t, func(tx *ent.Tx) error {
				if _, err := routes.AddPool(f.sys, tx, f.orgA, f.groupA, routes.TCP, 21000, 21009); err != nil {
					return err
				}
				r, err := tx.Route.Create().SetOrgID(f.orgA).SetName("proxy").SetType("tcp").SetGatewayGroupID(f.groupA).Save(f.sys)
				if err != nil {
					return err
				}
				if err := tx.RouteTCP.Create().SetOrgID(f.orgA).SetRouteID(r.ID).SetListenerMode(routetcp.ListenerModeHTTPConnect).Exec(f.sys); err != nil {
					return err
				}
				l, err := routes.JoinListener(f.sys, tx, r, routes.Listener{Mode: connectlistener.AuthModeTLSBasic, Hostname: "proxy.example.com",
					CertificateID: cert}, 0, []string{"db.internal"})
				if err != nil {
					return err
				}
				route, id = r.ID, l.ID
				return tx.RouteTCP.Update().Where(routetcp.RouteID(r.ID)).SetConnectListenerID(l.ID).Exec(f.sys)
			}); err != nil {
				t.Fatal(err)
			}
			return id
		}
		certsOf := func(gw string) map[string][]string {
			out := map[string][]string{}
			for _, r := range f.compileAs(t, pki.KindGateway, gw, gateway.Capabilities...) {
				if g := r.GetGatewayCertificate(); g != nil {
					out[r.GetId()] = g.GetHostnames()
				}
			}
			return out
		}
		notAfter := time.Unix(1893456000, 0)
		row := func(src certificate.Source, sans ...string) string {
			return c.Certificate.Create().SetOrgID(f.orgA).SetSource(src).SetSans(sans).SetNotBefore(time.Now()).SetNotAfter(notAfter).
				SetChain([]byte{1}).SetKeyEnc([]byte{2}).SetContentSha256([]byte{3}).SaveX(f.sys).ID
		}

		l := listener("")
		if got := certsOf(f.gateway); len(got) != 0 {
			t.Fatalf("a certificate before there was one: %v", got)
		}
		acmeID := row(certificate.SourceAcme, "proxy.example.com")
		if got := certsOf(f.gateway); !slices.Equal(got[acmeID], []string{"proxy.example.com"}) || len(got) != 1 {
			t.Fatalf("the ACME certificate: %v", got)
		}
		uploaded := row(certificate.SourceUploaded, "*.example.com")
		if got := certsOf(f.gateway); !slices.Equal(got[uploaded], []string{"proxy.example.com"}) || len(got) != 1 {
			t.Fatalf("an uploaded certificate covering the name is preferred: %v", got)
		}
		// Only the gateways of the listener's group.
		group := c.GatewayGroup.Create().SetOrgID(f.orgA).SetName("other").SaveX(f.sys).ID
		other := c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(group).SetName("gw-other").SetSlot(1).
			SetTunnelEndpoints([]string{"gw-other.example:443"}).SaveX(f.sys).ID
		if got := certsOf(other); len(got) != 0 {
			t.Fatalf("a gateway of another group got the listener's certificate: %v", got)
		}
		// Not while no enabled route is on the listener.
		c.Route.UpdateOneID(route).SetEnabled(false).ExecX(f.sys)
		if got := certsOf(f.gateway); len(got) != 0 {
			t.Fatalf("a listener without an enabled route: %v", got)
		}
		c.Route.UpdateOneID(route).SetEnabled(true).ExecX(f.sys)

		// A listener that names a certificate presents that one, not the upload preferred above.
		named := row(certificate.SourceUploaded, "proxy.example.com", "vpn.example.com")
		c.ConnectListener.UpdateOneID(l).SetCertificateID(named).ExecX(f.sys)
		if got := certsOf(f.gateway); !slices.Equal(got[named], []string{"proxy.example.com"}) || len(got) != 1 {
			t.Fatalf("the named certificate: %v", got)
		}
	})
}
