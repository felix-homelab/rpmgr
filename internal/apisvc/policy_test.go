// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
)

func ipAllow(cidrs ...string) *rpmgrv1.AccessRule {
	return &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: cidrs}}}
}

func basicAuth(users ...*rpmgrv1.BasicAuthCredential) *rpmgrv1.AccessRule {
	return &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: users}}}
}

func user(name, pw string) *rpmgrv1.BasicAuthCredential {
	return &rpmgrv1.BasicAuthCredential{Name: name, Password: pw}
}

// TestAccessPolicies (docs/07-api.md, "Services"; docs/04-security.md, "Secrets at rest and in
// logs"): an access policy keeps its rules in order, CIDRs in their masked form, and its basic_auth
// users' passwords only as argon2id hashes made on the controller, which no read and no audit entry
// returns; bad rules are refused; a Viewer reads but creates nothing.
func TestAccessPolicies(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	const alicePW, bobPW = "correct horse battery", "staple of the bob" //nolint:gosec // G101: test passwords
	create := func(b *browser, ap *rpmgrv1.AccessPolicy) (*rpmgrv1.CreateAccessPolicyResponse, error) {
		r, err := b.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org, AccessPolicy: ap}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	created, err := create(ada, &rpmgrv1.AccessPolicy{Name: "office", Description: "the office only", Rules: []*rpmgrv1.AccessRule{
		ipAllow("10.1.2.3/8", "2001:db8::1/32"),
		{Rule: &rpmgrv1.AccessRule_IpDeny{IpDeny: &rpmgrv1.IPRuleParams{Cidrs: []string{"192.0.2.7/32"}}}},
		basicAuth(user("alice", alicePW), user("bob", bobPW))}})
	if err != nil {
		t.Fatal(err)
	}
	ap := created.GetAccessPolicy()
	want := &rpmgrv1.AccessPolicy{Id: ap.GetId(), Name: "office", Description: "the office only", Etag: "1", Rules: []*rpmgrv1.AccessRule{
		ipAllow("10.0.0.0/8", "2001:db8::/32"),
		{Rule: &rpmgrv1.AccessRule_IpDeny{IpDeny: &rpmgrv1.IPRuleParams{Cidrs: []string{"192.0.2.7/32"}}}},
		basicAuth(user("alice", ""), user("bob", ""))}}
	if !strings.HasPrefix(ap.GetId(), "ap_") || !proto.Equal(ap, want) || created.GetRevision().GetSeq() == 0 {
		t.Fatalf("created:\n%v\nwant\n%v", created, want)
	}
	got, err := ada.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: ap.GetId()}))
	if err != nil || !proto.Equal(got.Msg.GetAccessPolicy(), want) {
		t.Fatalf("read: %v %v", got, err)
	}
	list, err := ada.pol.ListAccessPolicies(ctx, connect.NewRequest(&rpmgrv1.ListAccessPoliciesRequest{OrgId: org}))
	if err != nil || len(list.Msg.GetAccessPolicies()) != 1 || !proto.Equal(list.Msg.GetAccessPolicies()[0], want) {
		t.Fatalf("listed: %v %v", list, err)
	}

	// The controller keeps argon2id hashes, which verify, and never the password.
	hashes := func() map[string]string {
		out := map[string]string{}
		for _, r := range c.PolicyRule.Query().Where(policyrule.PolicyID(ap.GetId()), policyrule.KindEQ(policyrule.KindBasicAuth)).AllX(e.sys) {
			var params rpmgrv1.PolicyRuleParams
			if err := proto.Unmarshal(r.Params, &params); err != nil {
				t.Fatal(err)
			}
			for _, u := range params.GetBasicAuth().GetUsers() {
				out[u.GetName()] = u.GetPasswordHash()
			}
		}
		return out
	}
	first := hashes()
	for name, pw := range map[string]string{"alice": alicePW, "bob": bobPW} {
		if ok, _, err := password.Verify(ctx, pw, first[name], password.Default); !ok || err != nil || !strings.HasPrefix(first[name], "$argon2id$") {
			t.Fatalf("%s's stored hash %q: %v %v", name, first[name], ok, err)
		}
	}

	// Refused rules and names.
	for name, in := range map[string]*rpmgrv1.AccessPolicy{
		"a CIDR that is not one":    {Name: "x", Rules: []*rpmgrv1.AccessRule{ipAllow("10.0.0.0/33")}},
		"an empty IP rule":          {Name: "x", Rules: []*rpmgrv1.AccessRule{ipAllow()}},
		"a rule of no kind":         {Name: "x", Rules: []*rpmgrv1.AccessRule{{}}},
		"a user twice":              {Name: "x", Rules: []*rpmgrv1.AccessRule{basicAuth(user("a", alicePW), user("a", bobPW))}},
		"an 11-character password":  {Name: "x", Rules: []*rpmgrv1.AccessRule{basicAuth(user("a", "elevenchars"))}},
		"a user without a password": {Name: "x", Rules: []*rpmgrv1.AccessRule{basicAuth(user("a", ""))}},
		"a colon in a user name":    {Name: "x", Rules: []*rpmgrv1.AccessRule{basicAuth(user("a:b", alicePW))}},
		"no name":                   {Rules: []*rpmgrv1.AccessRule{ipAllow("10.0.0.0/8")}},
	} {
		if _, err := create(ada, in); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}
	if _, err := create(ada, &rpmgrv1.AccessPolicy{Name: "office"}); code(err) != connect.CodeAlreadyExists {
		t.Errorf("a taken name: %v", err)
	}

	// A Viewer reads, and creates nothing.
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := vwr.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: ap.GetId()})); err != nil {
		t.Errorf("a Viewer reads: %v", err)
	}
	if _, err := create(vwr, &rpmgrv1.AccessPolicy{Name: "mine"}); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer creates: %v", err)
	}

	// No password reached the audit log, which records the users.
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.PolicyService.CreateAccessPolicy"), auditentry.DiffContains("alice")).
		CountX(e.sys); n != 1 {
		t.Fatalf("%d audit entries of the policy with alice", n)
	}
	for _, a := range c.AuditEntry.Query().AllX(e.sys) {
		for _, pw := range []string{alicePW, bobPW} {
			if strings.Contains(string(a.Diff), pw) {
				t.Fatalf("audit entry %s holds a password", a.Action)
			}
		}
	}
}
