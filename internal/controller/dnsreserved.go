// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"slices"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
)

// DNSReserved returns the names the DNS job never writes (docs/15-dns.md, "Publication rules",
// rule 6): the controller's public URL, its aliases and the endpoints it advertises to agents, and
// each gateway's tunnel endpoints and WSS hostname, for a wrong record at one of them would cut
// the agents off or lock the operators out of the UI they need to put it right. It is read at each
// full pass, so a change of the instance settings is followed then. A failed read gives the names
// it has, which are at least the public URL's: the pass is not held back by it.
func DNSReserved(db *store.DB, publicURL string) func(ctx context.Context) []string {
	return func(ctx context.Context) []string {
		names := []string{apisvc.HostOf(publicURL)}
		c := db.ReadClient()
		if inst, _, err := settings.Instance(ctx, c); err == nil {
			for _, ep := range append(settings.ControllerEndpoints(inst, publicURL), inst.GetPublicUrlAliases()...) {
				names = append(names, apisvc.HostOf(ep))
			}
		}
		gws, err := c.Gateway.Query().Where(gateway.DecommissionedAtIsNil()).Select(gateway.FieldTunnelEndpoints, gateway.FieldWssHostname).All(ctx)
		if err != nil {
			return names
		}
		for _, g := range gws {
			for _, ep := range g.TunnelEndpoints {
				names = append(names, apisvc.HostOf(ep))
			}
			if g.WssHostname != nil {
				names = append(names, *g.WssHostname)
			}
		}
		out := names[:0]
		for _, n := range names {
			if n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".")); n != "" {
				out = append(out, n)
			}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
}
