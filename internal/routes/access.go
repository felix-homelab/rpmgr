// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
)

// accessOf compiles who may use a route (docs/03-connections.md, "Access policies"): the IP rules
// of its access policies, in the order of the policies and of each policy's rules. The kinds of
// other slices are compiled there; until a kind is, the API does not create it.
func accessOf(ctx context.Context, tx *ent.Tx, routeID string) (*agentv1.RouteAccess, error) {
	rps, err := tx.RoutePolicy.Query().Where(routepolicy.RouteID(routeID)).Order(ent.Asc(routepolicy.FieldPosition)).All(ctx)
	if err != nil || len(rps) == 0 {
		return nil, err
	}
	access := &agentv1.RouteAccess{}
	for _, rp := range rps {
		rules, err := tx.PolicyRule.Query().Where(policyrule.PolicyID(rp.PolicyID),
			policyrule.KindIn(policyrule.KindIPAllow, policyrule.KindIPDeny)).Order(ent.Asc(policyrule.FieldPosition)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			var params rpmgrv1.PolicyRuleParams
			if err := proto.Unmarshal(r.Params, &params); err != nil || params.GetIp() == nil {
				// The API stores only valid parameters: a rule that does not parse is a store
				// fault, and the route is not compiled rather than served without it.
				return nil, fmt.Errorf("routes: rule %s of policy %s: parameters do not parse", r.ID, rp.PolicyID)
			}
			access.IpRules = append(access.IpRules, &agentv1.IPRule{Allow: r.Kind == policyrule.KindIPAllow, Cidrs: params.GetIp().GetCidrs()})
		}
	}
	return access, nil
}
