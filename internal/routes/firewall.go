// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
)

// GatewayPortPools compiles the port pools of a gateway's group for its snapshot, if it announces
// firewall.ranges: a gateway of an earlier release would refuse a resource it does not know, and
// one that does not manage its host's firewall has no use for them. A disabled or decommissioned
// gateway gets none, so its ranges are closed; a tcp or udp route adds nothing, as the pools
// already hold its port (D152).
func GatewayPortPools(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway || !a.Has(agentproto.CapFirewallRanges) {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !gw.Enabled || gw.DecommissionedAt != nil {
		return nil, err
	}
	pools, err := tx.PortPool.Query().Where(portpool.GatewayGroupID(gw.GatewayGroupID)).Order(ent.Asc(portpool.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.Resource, 0, len(pools))
	for _, p := range pools {
		out = append(out, &agentv1.Resource{Id: p.ID, Kind: &agentv1.Resource_GatewayPortPool{GatewayPortPool: &agentv1.GatewayPortPool{
			Protocol: string(p.Protocol), PortFrom: uint32(p.PortFrom), PortTo: uint32(p.PortTo)}}}) //nolint:gosec // G115: 1 to 65535
	}
	return out, nil
}
