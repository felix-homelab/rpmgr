// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

func rateLimit(perSecond, burst uint32) *rpmgrv1.AccessRule {
	return &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_RateLimit{RateLimit: &rpmgrv1.RateLimitRule{PerSecond: perSecond, Burst: burst}}}
}

// TestAccessPolicies_RateLimit (#917, docs/03-connections.md, "Access policies"): a policy keeps
// its rate_limit rules and returns them; a rate or burst outside its bounds is refused; the rule
// is accepted on every route type (D131), whether the policy is attached afterwards or gets the
// rule while a tcp or tls_passthrough route applies it.
func TestAccessPolicies_RateLimit(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	create := func(name string, rules ...*rpmgrv1.AccessRule) (*rpmgrv1.AccessPolicy, error) {
		r, err := ada.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
			AccessPolicy: &rpmgrv1.AccessPolicy{Name: name, Rules: rules}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetAccessPolicy(), nil
	}
	pol, err := create("polite", ipAllow("10.0.0.0/8"), rateLimit(20, 50))
	if err != nil || len(pol.GetRules()) != 2 || !proto.Equal(pol.GetRules()[1], rateLimit(20, 50)) {
		t.Fatalf("a rate limit: %v %v", pol.GetRules(), err)
	}
	for _, bad := range []*rpmgrv1.AccessRule{rateLimit(0, 1), rateLimit(10_001, 1), rateLimit(1, 0), rateLimit(1, 10_001)} {
		if _, err := create("bad", bad); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("rule %v: %v", bad, err)
		}
	}
	if _, err := create("twice", rateLimit(20, 50), rateLimit(5, 5)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("two rate_limit rules in one policy: %v", err)
	}
	got, err := ada.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: pol.GetId()}))
	if err != nil || !proto.Equal(got.Msg.GetAccessPolicy().GetRules()[1], rateLimit(20, 50)) {
		t.Fatalf("read back: %v %v", got.Msg.GetAccessPolicy(), err)
	}

	// On a passthrough route: attached with the rule, then the rule changed while attached.
	in := passthroughRoute("db", group, "db.example.com")
	in.PolicyIds = []string{pol.GetId()}
	if _, err := createRoute(ada, org, in, ""); err != nil {
		t.Fatalf("a policy with a rate limit on a tls_passthrough route: %v", err)
	}
	up, err := ada.pol.UpdateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.UpdateAccessPolicyRequest{
		AccessPolicy: &rpmgrv1.AccessPolicy{Id: pol.GetId(), Rules: []*rpmgrv1.AccessRule{rateLimit(5, 5)}},
		UpdateMask:   &fieldmaskpb.FieldMask{Paths: []string{"rules"}}}))
	if err != nil || len(up.Msg.GetAccessPolicy().GetRules()) != 1 || !proto.Equal(up.Msg.GetAccessPolicy().GetRules()[0], rateLimit(5, 5)) {
		t.Fatalf("a changed rate limit on a policy a passthrough route applies: %v %v", up.Msg.GetAccessPolicy(), err)
	}
}
