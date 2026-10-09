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
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
)

// Gateway compiles a gateway's certificates: for every enabled http route of its gateway group,
// the certificate its tls_mode names, with the route hostnames that certificate covers. In
// certificate mode that is the route's uploaded certificate, which the composite foreign key keeps
// in the route's org; in acme mode the org's active ACME certificates. Expired certificates stay in
// the snapshot, which depends only on the configuration; the gateway passes them over. A disabled
// or decommissioned gateway gets none.
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
	routes, err := tx.Route.Query().Where(route.GatewayGroupID(gw.GatewayGroupID), route.TypeEQ(route.TypeHTTP),
		route.Enabled(true)).All(ctx)
	if err != nil {
		return nil, err
	}
	served := map[string]*ent.Certificate{}
	hostnames := map[string][]string{}
	acme := map[string][]*ent.Certificate{} // by org, loaded once
	for _, r := range routes {
		h, err := tx.RouteHTTP.Query().Where(routehttp.RouteID(r.ID)).Only(ctx)
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var candidates []*ent.Certificate
		switch {
		case h.TLSMode == routehttp.TLSModeCertificate && h.CertificateID != nil:
			c, err := tx.Certificate.Query().Where(certificate.ID(*h.CertificateID), certificate.StatusEQ(certificate.StatusActive)).Only(ctx)
			if err != nil && !ent.IsNotFound(err) {
				return nil, err
			}
			if c != nil {
				candidates = []*ent.Certificate{c}
			}
		case h.TLSMode == routehttp.TLSModeAcme:
			if _, ok := acme[r.OrgID]; !ok {
				acme[r.OrgID], err = tx.Certificate.Query().Where(certificate.OrgID(r.OrgID), certificate.SourceEQ(certificate.SourceAcme),
					certificate.StatusEQ(certificate.StatusActive)).All(ctx)
				if err != nil {
					return nil, err
				}
			}
			candidates = acme[r.OrgID]
		}
		if len(candidates) == 0 {
			continue
		}
		names, err := tx.RouteHostname.Query().Where(routehostname.RouteID(r.ID)).Select(routehostname.FieldHostname).Strings(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range candidates {
			for _, n := range names {
				if slices.ContainsFunc(c.Sans, func(san string) bool { return Covers(san, n) }) && !slices.Contains(hostnames[c.ID], n) {
					served[c.ID] = c
					hostnames[c.ID] = append(hostnames[c.ID], n)
				}
			}
		}
	}
	ids := make([]string, 0, len(served))
	for id := range served {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]*agentv1.Resource, 0, len(ids))
	for _, id := range ids {
		c := served[id]
		if len(c.ContentSha256) == 0 || c.NotAfter == nil {
			continue // an ACME certificate not obtained yet
		}
		hosts := hostnames[id]
		slices.Sort(hosts)
		out = append(out, &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayCertificate{GatewayCertificate: &agentv1.GatewayCertificate{
			ContentSha256: c.ContentSha256, Hostnames: hosts, NotAfter: timestamppb.New(*c.NotAfter)}}})
	}
	return out, nil
}
