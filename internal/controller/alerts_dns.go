// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsnamestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsprovider"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// observeDNS adds the DNS alerts of docs/10-operations.md, "Suggested alerts", for each org: a name
// in conflict or ambiguous, a zone that is held, a zone whose provider does not answer well, an
// owned record that drifted, and a provider whose token is refused or about to expire. A zone that
// is disabled raises none of the zone alerts: someone turned it off. Nothing is observed where
// nothing is connected.
func observeDNS(ctx context.Context, c *ent.Client, now time.Time, add func(org, kind, typ, id, name string, since time.Time)) error {
	zones, err := c.DNSZone.Query().Where(dnszone.SyncStateNEQ(dnszone.SyncStateDisabled)).All(ctx)
	if err != nil {
		return err
	}
	live := map[string]*ent.DNSZone{}
	for _, z := range zones {
		live[z.ID] = z
		if z.SyncState == dnszone.SyncStateHeld {
			add(z.OrgID, alerts.DNSZoneHeld, "dns_zone", z.ID, z.Name, time.Time{})
		}
		if z.ProviderStatus != dnszone.ProviderStatusOk {
			add(z.OrgID, alerts.DNSSyncFailing, "dns_zone", z.ID, z.Name, time.Time{})
		}
	}
	drifted, err := c.DNSRecord.Query().Where(dnsrecord.StateEQ(dnsrecord.StateDrifted)).All(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range drifted {
		if z, ok := live[r.DNSZoneID]; ok && !seen[z.ID] {
			seen[z.ID] = true
			add(z.OrgID, alerts.DNSRecordDrifted, "dns_zone", z.ID, z.Name, time.Time{})
		}
	}
	names, err := c.DNSNameStatus.Query().Where(dnsnamestatus.StatusIn(dnsnamestatus.StatusConflict, dnsnamestatus.StatusAmbiguous)).All(ctx)
	if err != nil {
		return err
	}
	for _, n := range names {
		if _, ok := live[n.DNSZoneID]; ok {
			add(n.OrgID, alerts.DNSConflict, "dns_name", n.ID, n.Name, n.Since)
		}
	}
	provs, err := c.DNSProvider.Query().All(ctx)
	if err != nil {
		return err
	}
	for _, p := range provs {
		if p.Status == dnsprovider.StatusInvalid || providers.Expiring(p.TokenExpiresAt, now) {
			add(p.OrgID, alerts.DNSTokenProblem, "dns_provider", p.ID, p.Name, time.Time{})
		}
	}
	return nil
}
