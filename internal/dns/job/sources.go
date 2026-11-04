// SPDX-License-Identifier: Apache-2.0

package job

import (
	"context"
	"net/netip"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/dns/compile"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
)

// sources reads everything the compiler needs for one zone, in the read transaction tx, which
// every replica sees the same way for the same revision (docs/15-dns.md, "The DNS job"). Routes
// count by existence: a disabled route still publishes.
func sources(ctx context.Context, tx *ent.Tx, z *ent.DNSZone, reserved []string) (compile.Input, error) {
	in := compile.Input{
		Zone: compile.Zone{Name: z.Name, OrgID: z.OrgID, State: compile.State(z.SyncState), PublishRouteHostnames: z.PublishRouteHostnames,
			AllowProxied: z.AllowProxied, AllowWildcards: z.AllowWildcards},
		Reserved: reserved,
	}
	groups, err := tx.GatewayGroup.Query().All(ctx)
	if err != nil {
		return in, err
	}
	for _, g := range groups {
		t := compile.Target{CNAME: g.DNSCname}
		for _, a := range g.DNSAddresses {
			if addr, err := netip.ParseAddr(a); err == nil {
				t.Addresses = append(t.Addresses, addr)
			}
		}
		in.Groups = append(in.Groups, compile.Group{ID: g.ID, Target: t})
	}
	inZone := func(hostname string) bool { return hostname == z.Name || strings.HasSuffix(hostname, "."+z.Name) }
	hosts, err := tx.RouteHostname.Query().Where(routehostname.Or(routehostname.HostnameEQ(z.Name), routehostname.HostnameHasSuffix("."+z.Name))).All(ctx)
	if err != nil {
		return in, err
	}
	proxied := map[string]bool{}
	if len(hosts) > 0 {
		var routeIDs []string
		for _, h := range hosts {
			routeIDs = append(routeIDs, h.RouteID)
		}
		https, err := tx.RouteHTTP.Query().Where(routehttp.RouteIDIn(routeIDs...)).All(ctx)
		if err != nil {
			return in, err
		}
		for _, h := range https {
			proxied[h.RouteID] = h.DNSProxied
		}
	}
	for _, h := range hosts {
		in.Routes = append(in.Routes, compile.Route{OrgID: h.OrgID, Hostname: h.Hostname, Kind: compile.RouteKind(h.RouteType),
			GroupID: h.GatewayGroupID, Proxied: proxied[h.RouteID]})
	}
	names, err := tx.DNSName.Query().Where(dnsname.Or(dnsname.FqdnEQ(z.Name), dnsname.FqdnHasSuffix("."+z.Name))).All(ctx)
	if err != nil {
		return in, err
	}
	for _, n := range names {
		in.Names = append(in.Names, compile.Name{OrgID: n.OrgID, Name: n.Fqdn, GroupID: n.GatewayGroupID})
	}
	doms, err := tx.Domain.Query().Where(domain.StatusIn(domain.StatusVerified, domain.StatusPending)).All(ctx)
	if err != nil {
		return in, err
	}
	for _, d := range doms {
		switch d.Status {
		case domain.StatusVerified:
			in.Domains = append(in.Domains, compile.Domain{OrgID: d.OrgID, FQDN: d.Fqdn, Wildcard: d.Wildcard, Verified: true})
		case domain.StatusPending:
			if inZone(d.Fqdn) {
				in.Claims = append(in.Claims, compile.Claim{OrgID: d.OrgID, FQDN: d.Fqdn, Value: d.ChallengeValue})
			}
		}
	}
	// The proxy state that is published now, for a name whose routes disagree.
	rows, err := tx.DNSRecord.Query().Where(dnsrecord.DNSZoneID(z.ID), dnsrecord.ProxiedEQ(true)).All(ctx)
	if err != nil {
		return in, err
	}
	in.Published = map[string]bool{}
	for _, r := range rows {
		in.Published[r.Name] = true
	}
	return in, nil
}
