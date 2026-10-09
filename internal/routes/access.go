// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
)

// accessOf compiles who may use a route (docs/03-connections.md, "Access policies"): the IP rules
// and, for an http route, the basic_auth rules of its access policies, in the order of the
// policies and of each policy's rules. A basic_auth rule on another route type, which the API does
// not create, denies everyone: no client could pass it. Kinds of later phases are compiled with
// them; until then the API does not create them.
func accessOf(ctx context.Context, tx *ent.Tx, routeID string, http bool) (*agentv1.RouteAccess, error) {
	rps, err := tx.RoutePolicy.Query().Where(routepolicy.RouteID(routeID)).Order(ent.Asc(routepolicy.FieldPosition)).All(ctx)
	if err != nil || len(rps) == 0 {
		return nil, err
	}
	access := &agentv1.RouteAccess{}
	for _, rp := range rps {
		rules, err := tx.PolicyRule.Query().Where(policyrule.PolicyID(rp.PolicyID),
			policyrule.KindIn(policyrule.KindIPAllow, policyrule.KindIPDeny, policyrule.KindBasicAuth)).
			Order(ent.Asc(policyrule.FieldPosition)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			var params rpmgrv1.PolicyRuleParams
			err := proto.Unmarshal(r.Params, &params)
			// The API stores only valid parameters: a rule that does not parse is a store fault,
			// and the route is not compiled rather than served without it.
			switch {
			case err == nil && r.Kind == policyrule.KindBasicAuth && params.GetBasicAuth() != nil:
				sum := sha256.Sum256(r.Params)
				access.BasicAuth = append(access.BasicAuth, &agentv1.BasicAuthRule{PolicyId: rp.PolicyID,
					CredentialVersion: r.ID + "." + hex.EncodeToString(sum[:8]), Users: params.GetBasicAuth().GetUsers()})
			case err == nil && r.Kind != policyrule.KindBasicAuth && params.GetIp() != nil:
				access.IpRules = append(access.IpRules, &agentv1.IPRule{Allow: r.Kind == policyrule.KindIPAllow, Cidrs: params.GetIp().GetCidrs()})
			default:
				return nil, fmt.Errorf("routes: rule %s of policy %s: parameters do not parse", r.ID, rp.PolicyID)
			}
		}
	}
	if !http && len(access.BasicAuth) > 0 {
		access.BasicAuth = nil
		access.IpRules = append([]*agentv1.IPRule{{Cidrs: []string{"0.0.0.0/0", "::/0"}}}, access.IpRules...)
	}
	return access, nil
}
