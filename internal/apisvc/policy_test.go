// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
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
// returns; an update replaces the rules, and a user without a password keeps the one of its name;
// a basic_auth rule is refused while a route that is not an http route applies the policy, which
// cannot then be deleted either; bad rules are refused; a Viewer reads but changes nothing.
func TestAccessPolicies(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	const alicePW, bobPW, carolPW = "correct horse battery", "staple of the bob", "carol's own secret" //nolint:gosec // G101: test passwords
	create := func(b *browser, ap *rpmgrv1.AccessPolicy) (*rpmgrv1.CreateAccessPolicyResponse, error) {
		r, err := b.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org, AccessPolicy: ap}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	created, err := create(ada, &rpmgrv1.AccessPolicy{Name: "office", Description: "the office only", Rules: []*rpmgrv1.AccessRule{
		ipAllow("10.1.2.3/8", "2001:db8::1/32", "172.16.0.1/16"),
		{Rule: &rpmgrv1.AccessRule_IpDeny{IpDeny: &rpmgrv1.IPRuleParams{Cidrs: []string{"192.0.2.7/32"}}}},
		basicAuth(user("alice", alicePW), user("bob", bobPW))}})
	if err != nil {
		t.Fatal(err)
	}
	ap := created.GetAccessPolicy()
	want := &rpmgrv1.AccessPolicy{Id: ap.GetId(), Name: "office", Description: "the office only", Etag: "1", Rules: []*rpmgrv1.AccessRule{
		ipAllow("10.0.0.0/8", "2001:db8::/32", "172.16.0.0/16"),
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

	update := func(paths []string, in *rpmgrv1.AccessPolicy, etag string) (*rpmgrv1.AccessPolicy, error) {
		in.Id = ap.GetId()
		r, err := ada.pol.UpdateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.UpdateAccessPolicyRequest{AccessPolicy: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetAccessPolicy(), nil
	}
	// New rules replace the old: alice keeps her password, carol gets one, bob is gone.
	up, err := update([]string{"rules"}, &rpmgrv1.AccessPolicy{Rules: []*rpmgrv1.AccessRule{basicAuth(user("carol", carolPW), user("alice", ""))}}, "1")
	if err != nil || len(up.GetRules()) != 1 || up.GetEtag() != "2" || up.GetDescription() != "the office only" {
		t.Fatalf("new rules: %v %v", up, err)
	}
	second := hashes()
	if len(second) != 2 || second["alice"] != first["alice"] || second["carol"] == "" {
		t.Fatalf("hashes after the update: %v", second)
	}
	if _, err := update([]string{"rules"}, &rpmgrv1.AccessPolicy{Rules: []*rpmgrv1.AccessRule{basicAuth(user("dave", ""))}}, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a new user without a password: %v", err)
	}
	if _, err := update([]string{"description"}, &rpmgrv1.AccessPolicy{Description: "x"}, "1"); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stale etag: %v", err)
	}
	if up, err := update([]string{"description"}, &rpmgrv1.AccessPolicy{Description: "anyone with a password"}, ""); err != nil ||
		up.GetDescription() != "anyone with a password" || len(hashes()) != 2 || hashes()["carol"] != second["carol"] {
		t.Fatalf("a description alone: %v %v", up, err)
	}
	if _, err := update([]string{"route_ids"}, &rpmgrv1.AccessPolicy{RouteIds: []string{"rt_x"}}, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("an output-only field: %v", err)
	}
	if _, err := update([]string{"name"}, &rpmgrv1.AccessPolicy{}, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("no name: %v", err)
	}

	// A tcp route that applies the policy: no basic_auth then, and no delete.
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20001}})); err != nil {
		t.Fatal(err)
	}
	pg, err := createRoute(ada, org, tcpRoute("pg", group, 20000), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := update([]string{"rules"}, &rpmgrv1.AccessPolicy{Rules: []*rpmgrv1.AccessRule{ipAllow("10.0.0.0/8")}}, ""); err != nil {
		t.Fatal(err)
	}
	c.RoutePolicy.Create().SetOrgID(org).SetRouteID(pg.GetId()).SetPolicyID(ap.GetId()).SetPosition(0).ExecX(e.sys)
	if _, err := update([]string{"rules"}, &rpmgrv1.AccessPolicy{Rules: []*rpmgrv1.AccessRule{basicAuth(user("alice", alicePW))}}, ""); code(err) != connect.CodeFailedPrecondition ||
		reason(err) != apisvc.ReasonBasicAuthNotHTTP {
		t.Errorf("basic auth for a tcp route: %v", err)
	}
	read, err := ada.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: ap.GetId()}))
	if err != nil || len(read.Msg.GetAccessPolicy().GetRouteIds()) != 1 || read.Msg.GetAccessPolicy().GetRouteIds()[0] != pg.GetId() {
		t.Fatalf("the routes that apply it: %v %v", read, err)
	}
	del := func(b *browser) error {
		_, err := b.pol.DeleteAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.DeleteAccessPolicyRequest{AccessPolicyId: ap.GetId()}))
		return err
	}
	if err := del(ada); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDependantsExist {
		t.Errorf("a policy a route applies deleted: %v", err)
	}

	// A Viewer reads, and changes nothing.
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := vwr.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: ap.GetId()})); err != nil {
		t.Errorf("a Viewer reads: %v", err)
	}
	if _, err := create(vwr, &rpmgrv1.AccessPolicy{Name: "mine"}); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer creates: %v", err)
	}
	if err := del(vwr); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer deletes: %v", err)
	}

	c.RoutePolicy.Delete().Where(routepolicy.PolicyID(ap.GetId())).ExecX(e.sys)
	if err := del(ada); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: ap.GetId()})); code(err) != connect.CodeNotFound ||
		c.PolicyRule.Query().CountX(e.sys) != 0 {
		t.Fatalf("after the delete: %v", err)
	}

	// No password reached the audit log, which records the users.
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.PolicyService.CreateAccessPolicy"), auditentry.DiffContains("alice")).
		CountX(e.sys); n != 1 {
		t.Fatalf("%d audit entries of the policy with alice", n)
	}
	for _, a := range c.AuditEntry.Query().AllX(e.sys) {
		for _, pw := range []string{alicePW, bobPW, carolPW} {
			if strings.Contains(string(a.Diff), pw) {
				t.Fatalf("audit entry %s holds a password", a.Action)
			}
		}
	}
}

// TestRoutePolicies (docs/03-connections.md, "Access policies"): a route applies policies of its
// org in the order given, each once; a policy with a basic_auth rule only on an http route; an
// update reorders or clears them; a policy shows the routes that apply it.
func TestRoutePolicies(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20001}})); err != nil {
		t.Fatal(err)
	}
	policy := func(b *browser, org, name string, rules ...*rpmgrv1.AccessRule) string {
		r, err := b.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
			AccessPolicy: &rpmgrv1.AccessPolicy{Name: name, Rules: rules}}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetAccessPolicy().GetId()
	}
	ips := policy(ada, org, "ips", ipAllow("10.0.0.0/8"))
	auth := policy(ada, org, "auth", basicAuth(user("alice", "correct horse battery")))
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	theirs := policy(bob, orgB, "theirs", ipAllow("192.0.2.0/24"))

	web := httpRoute("web", group, "web.example.com")
	web.PolicyIds = []string{auth, ips}
	created, err := createRoute(ada, org, web, "")
	if err != nil || !slices.Equal(created.GetPolicyIds(), []string{auth, ips}) {
		t.Fatalf("an http route with two policies: %v %v", created, err)
	}
	for name, c := range map[string]struct {
		rt   *rpmgrv1.Route
		code connect.Code
	}{
		"basic auth on a tcp route": {&rpmgrv1.Route{Name: "pg", GatewayGroupId: group, Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{Port: 20000}},
			PolicyIds: []string{auth}}, connect.CodeFailedPrecondition},
		"another org's policy": {&rpmgrv1.Route{Name: "pg", GatewayGroupId: group, Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{Port: 20000}},
			PolicyIds: []string{theirs}}, connect.CodeNotFound},
		"a policy twice": {&rpmgrv1.Route{Name: "pg", GatewayGroupId: group, Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{Port: 20000}},
			PolicyIds: []string{ips, ips}}, connect.CodeInvalidArgument},
	} {
		if _, err := createRoute(ada, org, c.rt, ""); code(err) != c.code {
			t.Errorf("%s: %v, want %v", name, err, c.code)
		}
	}
	pg := tcpRoute("pg", group, 20000)
	pg.PolicyIds = []string{ips}
	tcpRt, err := createRoute(ada, org, pg, "")
	if err != nil {
		t.Fatal(err)
	}

	update := func(id string, ids ...string) (*rpmgrv1.Route, error) {
		r, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: &rpmgrv1.Route{Id: id, PolicyIds: ids},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"policy_ids"}}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRoute(), nil
	}
	if up, err := update(created.GetId(), ips, auth); err != nil || !slices.Equal(up.GetPolicyIds(), []string{ips, auth}) || up.GetEtag() != "2" {
		t.Fatalf("reordered: %v %v", up, err)
	}
	if _, err := update(tcpRt.GetId(), ips, auth); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonBasicAuthNotHTTP {
		t.Errorf("basic auth added to a tcp route: %v", err)
	}
	got, err := ada.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: ips}))
	if err != nil || !slices.Equal(got.Msg.GetAccessPolicy().GetRouteIds(), sorted(created.GetId(), tcpRt.GetId())) {
		t.Fatalf("the routes that apply a policy: %v %v", got, err)
	}
	if up, err := update(created.GetId()); err != nil || len(up.GetPolicyIds()) != 0 {
		t.Fatalf("cleared: %v %v", up, err)
	}
	if _, err := ada.pol.DeleteAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.DeleteAccessPolicyRequest{AccessPolicyId: auth})); err != nil {
		t.Fatalf("a policy no route applies any more: %v", err)
	}
	if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: tcpRt.GetId()})); err != nil {
		t.Fatalf("a route with a policy: %v", err)
	}
}

func requireHeader(name string, values ...string) *rpmgrv1.AccessRule {
	return &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_RequireHeader{RequireHeader: &rpmgrv1.RequireHeaderRule{Name: name, Values: values}}}
}

// TestAccessPolicies_RequireHeader (docs/04-security.md, "Route edge rules"): a require_header
// rule keeps only the SHA-256 of its values under the header's canonical name, never returns or
// audits a value, and keeps its hashes in an update that gives no values; short, invisible,
// repeated or too many values, headers that cannot be required and a header required twice are
// refused; neither the rule on a policy a tcp route applies, nor that policy on a tcp route.
func TestAccessPolicies_RequireHeader(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	const valueA, valueB, valueC = "origin-secret-a-0123456789abcdefghijkl", "origin-secret-b-0123456789abcdefghijkl",
		"origin-secret-c-0123456789abcdefghijkl" //nolint:gosec // G101: test values
	create := func(name string, rules ...*rpmgrv1.AccessRule) (*rpmgrv1.AccessPolicy, error) {
		r, err := ada.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
			AccessPolicy: &rpmgrv1.AccessPolicy{Name: name, Rules: rules}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetAccessPolicy(), nil
	}
	ap, err := create("cdn", requireHeader("x-origin-token", valueA, valueB))
	if err != nil {
		t.Fatal(err)
	}
	want := []*rpmgrv1.AccessRule{requireHeader("X-Origin-Token")}
	got, err := ada.pol.GetAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.GetAccessPolicyRequest{AccessPolicyId: ap.GetId()}))
	if err != nil || !slices.EqualFunc(got.Msg.GetAccessPolicy().GetRules(), want, func(a, b *rpmgrv1.AccessRule) bool { return proto.Equal(a, b) }) {
		t.Fatalf("read: %v %v, want the header without values", got, err)
	}
	stored := func() *rpmgrv1.RequireHeaderParams {
		r := c.PolicyRule.Query().Where(policyrule.PolicyID(ap.GetId()), policyrule.KindEQ(policyrule.KindRequireHeader)).OnlyX(e.sys)
		var params rpmgrv1.PolicyRuleParams
		if err := proto.Unmarshal(r.Params, &params); err != nil {
			t.Fatal(err)
		}
		return params.GetRequireHeader()
	}
	sums := func(values ...string) [][]byte {
		var out [][]byte
		for _, v := range values {
			s := sha256.Sum256([]byte(v))
			out = append(out, s[:])
		}
		return out
	}
	if s := stored(); s.GetName() != "X-Origin-Token" || !slices.EqualFunc(s.GetValueSha256(), sums(valueA, valueB), bytes.Equal) {
		t.Fatalf("stored %v", s)
	}

	for name, rule := range map[string]*rpmgrv1.AccessRule{
		"a 31-character value":        requireHeader("X-Origin", valueA[:31]),
		"a value with a space":        requireHeader("X-Origin", "origin secret a 0123456789abcdefghijkl"),
		"a value with a tab":          requireHeader("X-Origin", "origin\tsecret-a-0123456789abcdefghijkl"),
		"a non-ASCII value":           requireHeader("X-Origin", "origin-secret-ä-0123456789abcdefghijkl"),
		"a value twice":               requireHeader("X-Origin", valueA, valueA),
		"five values":                 requireHeader("X-Origin", valueA, valueB, valueC, valueA+"d", valueA+"e"),
		"no value":                    requireHeader("X-Origin"),
		"a name with a space":         requireHeader("X Origin", valueA),
		"Host":                        requireHeader("host", valueA),
		"Authorization":               requireHeader("Authorization", valueA),
		"Cookie":                      requireHeader("Cookie", valueA),
		"an rpmgr header":             requireHeader("Rpmgr-User-Email", valueA),
		"a forwarding header":         requireHeader("X-Forwarded-For", valueA),
		"Traceparent":                 requireHeader("traceparent", valueA),
		"Tracestate":                  requireHeader("Tracestate", valueA),
		"Baggage":                     requireHeader("Baggage", valueA),
		"a 129-character name":        requireHeader("X-"+strings.Repeat("a", 127), valueA),
		"a 1025-character value":      requireHeader("X-Origin", valueA+strings.Repeat("x", 1025-len(valueA))),
		"a value of one character":    requireHeader("X-Origin", strings.Repeat("a", 40)),
		"a value of seven characters": requireHeader("X-Origin", strings.Repeat("abcdefg", 6)),
		"a connection's header":       requireHeader("Transfer-Encoding", valueA),
	} {
		if _, err := create("x", rule); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}
	if _, err := create("x", requireHeader("X-Origin", valueA), requireHeader("x-origin", valueB)); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a header required twice: %v", err)
	}

	update := func(rules ...*rpmgrv1.AccessRule) error {
		_, err := ada.pol.UpdateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.UpdateAccessPolicyRequest{
			AccessPolicy: &rpmgrv1.AccessPolicy{Id: ap.GetId(), Rules: rules}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}}}))
		return err
	}
	// Without values, the rule keeps its hashes; with values, they replace them.
	if err := update(ipAllow("10.0.0.0/8"), requireHeader("X-Origin-Token")); err != nil {
		t.Fatal(err)
	}
	if s := stored(); !slices.EqualFunc(s.GetValueSha256(), sums(valueA, valueB), bytes.Equal) {
		t.Fatalf("kept %v", s)
	}
	if err := update(requireHeader("X-Origin-Token", valueC)); err != nil {
		t.Fatal(err)
	}
	if s := stored(); !slices.EqualFunc(s.GetValueSha256(), sums(valueC), bytes.Equal) {
		t.Fatalf("rotated %v", s)
	}
	if err := update(requireHeader("X-Other")); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a new header without a value: %v", err)
	}

	// Only http routes: neither the rule on a policy a tcp route applies, nor the policy on one.
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20001}})); err != nil {
		t.Fatal(err)
	}
	pg := tcpRoute("pg", group, 20000)
	pg.PolicyIds = []string{ap.GetId()}
	if _, err := createRoute(ada, org, pg, ""); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonRequireHeaderNotHTTP {
		t.Errorf("the policy on a tcp route: %v", err)
	}
	ips, err := create("ips", ipAllow("10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	pg.PolicyIds = []string{ips.GetId()}
	tcpRt, err := createRoute(ada, org, pg, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{
		Route:      &rpmgrv1.Route{Id: tcpRt.GetId(), PolicyIds: []string{ips.GetId(), ap.GetId()}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"policy_ids"}}})); code(err) != connect.CodeFailedPrecondition ||
		reason(err) != apisvc.ReasonRequireHeaderNotHTTP {
		t.Errorf("the policy added to a tcp route: %v", err)
	}
	if _, err := create("eight", requireHeader("X-Origin", strings.Repeat("abcdefgh", 5))); err != nil {
		t.Errorf("a value of eight different characters: %v", err)
	}
	if _, err := ada.pol.UpdateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.UpdateAccessPolicyRequest{
		AccessPolicy: &rpmgrv1.AccessPolicy{Id: ips.GetId(), Rules: []*rpmgrv1.AccessRule{requireHeader("X-Origin", valueA)}},
		UpdateMask:   &fieldmaskpb.FieldMask{Paths: []string{"rules"}}})); code(err) != connect.CodeFailedPrecondition ||
		reason(err) != apisvc.ReasonRequireHeaderNotHTTP {
		t.Errorf("the rule on a policy a tcp route applies: %v", err)
	}

	// No value and no hash reached the audit log, which records the header.
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.PolicyService.CreateAccessPolicy"), auditentry.DiffContains("X-Origin-Token")).
		CountX(e.sys); n == 0 {
		t.Error("no audit entry names the header")
	}
	for _, a := range c.AuditEntry.Query().AllX(e.sys) {
		for _, v := range []string{valueA, valueB, valueC} {
			s := sha256.Sum256([]byte(v))
			if strings.Contains(a.Diff, v) || strings.Contains(a.Diff, string(s[:])) || strings.Contains(a.Diff, hex.EncodeToString(s[:])) ||
				strings.Contains(a.Diff, base64.StdEncoding.EncodeToString(s[:])) {
				t.Fatalf("audit entry %s holds a value or its hash", a.Action)
			}
		}
	}
}
