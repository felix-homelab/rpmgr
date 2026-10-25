// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
)

// ErrWSSHostnameTaken is the reason a WSS hostname is refused: a route of the gateway's group
// serves the name, or another gateway has it.
var ErrWSSHostnameTaken = errors.New("routes: the WSS hostname is a route hostname of the gateway group or another gateway's")

// SetWSSHostname sets the WSS hostname of a gateway (docs/03-connections.md, "Transport
// selection"; docs/04-security.md, "Route edge rules"): a name, no wildcard, under a verified domain
// of the gateway's org, which is the group's owner org, so that no org can make a gateway present a
// name it does not hold; no route hostname of the group, nor covered by a wildcard one, so that a
// name's SNI never means two things; and no other gateway's. An empty name removes it. It must run in a configuration
// transaction.
func SetWSSHostname(ctx context.Context, tx *ent.Tx, gatewayID, hostname string) (*ent.Gateway, error) {
	gw, err := tx.Gateway.Get(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	if hostname == "" {
		return gw.Update().ClearWssHostname().Save(ctx)
	}
	name, err := domains.Normalize(hostname, false)
	if err != nil {
		return nil, err
	}
	if _, err := domains.Covering(ctx, tx, gw.OrgID, name); err != nil {
		return nil, err
	}
	names := []string{name}
	if _, parent, ok := strings.Cut(name, "."); ok {
		names = append(names, "*."+parent)
	}
	taken, err := tx.RouteHostname.Query().Where(routehostname.GatewayGroupID(gw.GatewayGroupID), routehostname.HostnameIn(names...)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, fmt.Errorf("%w: %s", ErrWSSHostnameTaken, name)
	}
	gw, err = gw.Update().SetWssHostname(name).Save(ctx)
	if store.IsUniqueViolation(err) {
		return nil, fmt.Errorf("%w: %s", ErrWSSHostnameTaken, name)
	}
	return gw, err
}

// GatewayWSS compiles a gateway's WSS hostname for its snapshot, if it has one and announces
// tunnel.wss: a gateway of an earlier release would refuse a resource it does not know. A disabled
// or decommissioned gateway gets none.
func GatewayWSS(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
	if a.Identity.Kind != pki.KindGateway || !a.Has(agentproto.CapTunnelWSS) {
		return nil, nil
	}
	gw, err := tx.Gateway.Get(ctx, a.Identity.ID)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil || !gw.Enabled || gw.DecommissionedAt != nil || gw.WssHostname == nil {
		return nil, err
	}
	return []*agentv1.Resource{{Id: gw.ID + ".wss", Kind: &agentv1.Resource_GatewayWss{GatewayWss: &agentv1.GatewayWSS{Hostname: *gw.WssHostname}}}}, nil
}

// wssHostnameTaken reports whether a gateway of a group has name as its WSS hostname, or, for a
// wildcard name, one it covers.
func wssHostnameTaken(ctx context.Context, tx *ent.Tx, groupID, name string) (bool, error) {
	parent, wildcard := strings.CutPrefix(name, "*.")
	if !wildcard {
		return tx.Gateway.Query().Where(gateway.GatewayGroupID(groupID), gateway.WssHostname(name)).Exist(ctx)
	}
	hosts, err := tx.Gateway.Query().Where(gateway.GatewayGroupID(groupID), gateway.WssHostnameHasSuffix("."+parent)).
		Select(gateway.FieldWssHostname).Strings(ctx)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(hosts, func(h string) bool { return !strings.Contains(strings.TrimSuffix(h, "."+parent), ".") }), nil
}
