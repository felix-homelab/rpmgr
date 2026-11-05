// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"fmt"
	"sort"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsnamestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// routeHostnames are the hostnames of an http or tls_passthrough route; other routes have none.
func routeHostnames(r *rpmgrv1.Route) []string {
	switch s := r.GetSpec().(type) {
	case *rpmgrv1.Route_Http:
		return s.Http.GetHostnames()
	case *rpmgrv1.Route_TlsPassthrough:
		return s.TlsPassthrough.GetHostnames()
	}
	return nil
}

// fillDNSStatus sets Route.dns_status of routes, all of org, from the names the DNS job recorded
// (docs/15-dns.md, "Publication rules"): one line per hostname that has a status, with the records
// published at it. A hostname the job has not seen has none, so an instance without DNS shows
// nothing. A name that waits while the zone's provider rate-limits is shown as `rate_limited`. It
// reads, never writes, and never changes the route's own status.
func fillDNSStatus(ctx context.Context, c *ent.Client, org string, routes []*rpmgrv1.Route) error {
	want := map[string]bool{}
	for _, r := range routes {
		for _, h := range routeHostnames(r) {
			want[h] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	rows, err := c.DNSNameStatus.Query().Where(dnsnamestatus.OrgID(org), dnsnamestatus.NameIn(names...)).All(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	zoneIDs := map[string]bool{}
	for _, r := range rows {
		zoneIDs[r.DNSZoneID] = true
	}
	ids := make([]string, 0, len(zoneIDs))
	for id := range zoneIDs {
		ids = append(ids, id)
	}
	zones, err := c.DNSZone.Query().Where(dnszone.OrgID(org), dnszone.IDIn(ids...)).All(ctx)
	if err != nil {
		return err
	}
	limited := map[string]bool{}
	for _, z := range zones {
		limited[z.ID] = z.ProviderStatus == dnszone.ProviderStatusRateLimited
	}
	recs, err := c.DNSRecord.Query().Where(dnsrecord.OrgID(org), dnsrecord.NameIn(names...),
		dnsrecord.StateIn(dnsrecord.StateSynced, dnsrecord.StateDrifted)).Order(ent.Asc(dnsrecord.FieldID)).All(ctx)
	if err != nil {
		return err
	}
	type key struct{ zone, name string }
	records := map[key][]string{}
	for _, r := range recs {
		k := key{r.DNSZoneID, r.Name}
		records[k] = append(records[k], fmt.Sprintf("%s %s", r.Type, r.Content))
	}
	by := map[string]*ent.DNSNameStatus{}
	for _, r := range rows {
		by[r.Name] = r // one row per zone and name; a name lies in one zone
	}
	for _, rt := range routes {
		for _, h := range routeHostnames(rt) {
			r, ok := by[h]
			if !ok {
				continue
			}
			s := string(r.Status)
			if r.Status == dnsnamestatus.StatusPending && limited[r.DNSZoneID] {
				s = "rate_limited"
			}
			rt.DnsStatus = append(rt.DnsStatus, &rpmgrv1.HostnameDnsStatus{Hostname: h, Status: s, Reason: r.Reason,
				Records: records[key{r.DNSZoneID, h}]})
		}
	}
	return nil
}
