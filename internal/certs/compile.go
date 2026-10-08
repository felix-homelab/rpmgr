// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"slices"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
)

// Gateway compiles a gateway's certificates: every active certificate that covers a hostname of an
// enabled http route of its gateway group, of the certificate's own org, with those hostnames. A
// certificate never serves another org's hostname, even one it covers. Expired certificates stay
// in the snapshot, which depends only on the configuration; the gateway passes them over. A
// disabled or decommissioned gateway gets none.
func Gateway(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !gw.Enabled || gw.DecommissionedAt != nil {
		return nil, err
	}
	hosts, err := tx.RouteHostname.Query().Where(routehostname.GatewayGroupID(gw.GatewayGroupID),
		routehostname.RouteTypeEQ(routehostname.RouteTypeHTTP), routehostname.HasRouteWith(route.Enabled(true))).All(ctx)
	if err != nil || len(hosts) == 0 {
		return nil, err
	}
	byOrg := map[string][]string{}
	for _, h := range hosts {
		if !slices.Contains(byOrg[h.OrgID], h.Hostname) {
			byOrg[h.OrgID] = append(byOrg[h.OrgID], h.Hostname)
		}
	}
	orgs := make([]string, 0, len(byOrg))
	for org := range byOrg {
		orgs = append(orgs, org)
	}
	cs, err := tx.Certificate.Query().Where(certificate.OrgIDIn(orgs...), certificate.StatusEQ(certificate.StatusActive)).
		Order(ent.Asc(certificate.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*agentv1.Resource
	for _, c := range cs {
		var served []string
		for _, h := range byOrg[c.OrgID] {
			if slices.ContainsFunc(c.Sans, func(san string) bool { return Covers(san, h) }) {
				served = append(served, h)
			}
		}
		if len(served) == 0 {
			continue
		}
		slices.Sort(served)
		out = append(out, &agentv1.Resource{Id: c.ID, Kind: &agentv1.Resource_GatewayCertificate{GatewayCertificate: &agentv1.GatewayCertificate{
			ContentSha256: c.ContentSha256, Hostnames: served, NotAfter: timestamppb.New(c.NotAfter)}}})
	}
	return out, nil
}
