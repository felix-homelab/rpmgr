// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaypage"
)

// PageKinds are the store's page kinds as the protos name them.
var PageKinds = map[gatewaypage.Kind]rpmgrv1.GatewayPageKind{
	gatewaypage.KindNotFound:    rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_NOT_FOUND,
	gatewaypage.KindUnavailable: rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_UNAVAILABLE,
	gatewaypage.KindMaintenance: rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE,
}

// GatewayPages compiles the pages a gateway's group replaced with its own (D132), each by the
// SHA-256 of its HTML, which the gateway fetches. A gateway without the capability pages.custom
// gets none and serves its built-in pages; so does a decommissioned one.
func GatewayPages(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway || !a.Has(agentproto.CapPagesCustom) {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || gw.DecommissionedAt != nil {
		return nil, err
	}
	pages, err := tx.GatewayPage.Query().Where(gatewaypage.GatewayGroupID(gw.GatewayGroupID)).Order(ent.Asc(gatewaypage.FieldID)).
		Select(gatewaypage.FieldID, gatewaypage.FieldKind, gatewaypage.FieldContentSha256).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.Resource, 0, len(pages))
	for _, p := range pages {
		out = append(out, &agentv1.Resource{Id: p.ID, Kind: &agentv1.Resource_GatewayPage{GatewayPage: &agentv1.GatewayPage{
			Kind: PageKinds[p.Kind], ContentSha256: p.ContentSha256}}})
	}
	return out, nil
}
