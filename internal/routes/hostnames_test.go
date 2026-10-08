// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"errors"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestHostnames: a hostname needs a verified domain of the route's org; within a gateway group it
// is one tls_passthrough route or any number of http routes with distinct path prefixes.
func TestHostnames(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		c := db.Client()
		verified := func(org, fqdn string, wildcard bool) {
			if err := e.tx(t, func(tx *ent.Tx) error {
				d, err := domains.Claim(e.sys, tx, org, fqdn, wildcard)
				if err != nil {
					return err
				}
				return tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(e.sys)
			}); err != nil {
				t.Fatal(err)
			}
		}
		verified(e.orgA, "example.com", true)
		verified(e.orgB, "other.example", false)
		mk := func(org, group, name string, typ route.Type) string {
			return c.Route.Create().SetOrgID(org).SetName(name).SetType(typ).SetGatewayGroupID(group).SaveX(e.sys).ID
		}
		pass := mk(e.orgA, e.groupA, "db", route.TypeTLSPassthrough)
		pass2 := mk(e.orgA, e.groupA, "db2", route.TypeTLSPassthrough)
		web := mk(e.orgA, e.groupA, "web", route.TypeHTTP)
		web2 := mk(e.orgA, e.groupA, "web2", route.TypeHTTP)
		tcp := mk(e.orgA, e.groupA, "tcp", route.TypeTCP)
		otherGroup := c.GatewayGroup.Create().SetOrgID(e.orgA).SetName("us").SaveX(e.sys).ID
		passUS := mk(e.orgA, otherGroup, "db-us", route.TypeTLSPassthrough)
		add := func(rt, host, prefix string) error {
			return e.tx(t, func(tx *ent.Tx) error {
				_, err := routes.AddHostname(e.sys, tx, rt, host, prefix)
				return err
			})
		}
		for _, tc := range []struct {
			name, route, host, prefix string
			want                      error
		}{
			{"a passthrough hostname", pass, "DB.example.com.", "", nil},
			{"a second passthrough route on it", pass2, "db.example.com", "", routes.ErrHostnameTaken},
			{"an http route on a passthrough hostname", web, "db.example.com", "/", routes.ErrHostnameTaken},
			{"the same hostname in another group", passUS, "db.example.com", "", nil},
			{"an http hostname", web, "app.example.com", "", nil},
			{"another http route with a path prefix", web2, "app.example.com", "/api", nil},
			{"the same path prefix again", web2, "app.example.com", "/api", routes.ErrHostnameTaken},
			{"a passthrough route on an http hostname", pass2, "app.example.com", "", routes.ErrHostnameTaken},
			{"a wildcard http hostname", web, "*.apps.example.com", "", nil},
			{"a prefix without a slash", web2, "x.example.com", "api", routes.ErrPathPrefix},
			{"a passthrough prefix", pass2, "y.example.com", "/x", routes.ErrPathPrefix},
			{"a tcp route", tcp, "z.example.com", "", routes.ErrNoHostnames},
			{"a name no domain covers", web, "example.net", "", domains.ErrNotOwned},
			{"another org's domain", web, "other.example", "", domains.ErrNotOwned},
			{"an invalid name", web, "bad_name.example.com", "", domains.ErrInvalid},
		} {
			if err := add(tc.route, tc.host, tc.prefix); !errors.Is(err, tc.want) {
				t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
			}
		}
		h := c.RouteHostname.Query().AllX(e.sys)
		if len(h) != 5 {
			t.Fatalf("%d hostnames, want 5", len(h))
		}
		if err := e.tx(t, func(tx *ent.Tx) error { return routes.RemoveHostnames(e.sys, tx, pass) }); err != nil {
			t.Fatal(err)
		}
		if err := add(web, "db.example.com", ""); err != nil {
			t.Fatalf("an http route once the passthrough route left: %v", err)
		}
	})
}
