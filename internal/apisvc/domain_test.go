// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func claim(b *browser, org, fqdn string, wildcard bool, method rpmgrv1.DomainMethod) (*rpmgrv1.Domain, error) {
	r, err := b.dom.CreateDomain(context.Background(), connect.NewRequest(&rpmgrv1.CreateDomainRequest{OrgId: org,
		Domain: &rpmgrv1.Domain{Fqdn: fqdn, Wildcard: wildcard, Method: method}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetDomain(), nil
}

// TestDomains: a claim is pending with the proof its method asks for; names are normalised and
// unique in the instance, whatever the org; a claim is listed, read, and deleted unless route
// hostnames lie under it; a Viewer reads but claims nothing.
func TestDomains(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	txt, err := claim(ada, org, "Example.COM.", false, rpmgrv1.DomainMethod_DOMAIN_METHOD_UNSPECIFIED)
	if err != nil || txt.GetFqdn() != "example.com" || txt.GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING ||
		txt.GetMethod() != rpmgrv1.DomainMethod_DOMAIN_METHOD_DNS_TXT || txt.GetChallenge().GetTxtName() != "_rpmgr-challenge.example.com" ||
		len(txt.GetChallenge().GetValue()) != 32 || txt.GetChallenge().GetHttpUrl() != "" {
		t.Fatalf("a DNS claim: %v %v", txt, err)
	}
	web, err := claim(ada, org, "apps.example.org", true, rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP)
	if err != nil || !web.GetWildcard() || web.GetChallenge().GetHttpUrl() != "http://apps.example.org/.well-known/rpmgr-challenge/"+web.GetId() ||
		web.GetChallenge().GetTxtName() != "" {
		t.Fatalf("an HTTP claim: %v %v", web, err)
	}
	for name, c := range map[string]struct {
		fqdn   string
		method rpmgrv1.DomainMethod
		want   connect.Code
	}{
		"taken":            {"example.com", 0, connect.CodeAlreadyExists},
		"one label":        {"localhost", 0, connect.CodeInvalidArgument},
		"an IP address":    {"192.0.2.1", 0, connect.CodeInvalidArgument},
		"a bad label":      {"exa_mple.com", 0, connect.CodeInvalidArgument},
		"trusted on claim": {"other.example", rpmgrv1.DomainMethod_DOMAIN_METHOD_TRUSTED, connect.CodeInvalidArgument},
		"too long":         {strings.Repeat("a.", 127) + "com", 0, connect.CodeInvalidArgument},
	} {
		if _, err := claim(ada, org, c.fqdn, false, c.method); code(err) != c.want {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// Another org cannot claim the name either.
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := claim(bob, orgB, "example.com", false, 0); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("another org's claim on a taken name: %v", err)
	}

	list, err := ada.dom.ListDomains(ctx, connect.NewRequest(&rpmgrv1.ListDomainsRequest{OrgId: org}))
	if err != nil || len(list.Msg.GetDomains()) != 2 {
		t.Fatalf("the claims: %v %v", list, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := claim(vwr, org, "viewer.example", false, 0); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer claims: %v", err)
	}
	if r, err := vwr.dom.GetDomain(ctx, connect.NewRequest(&rpmgrv1.GetDomainRequest{DomainId: txt.GetId()})); err != nil ||
		r.Msg.GetDomain().GetFqdn() != "example.com" {
		t.Fatalf("a Viewer reads: %v %v", r, err)
	}

	route := e.db.Client().Route.Create().SetOrgID(org).SetName("web").SetType("http").SetGatewayGroupID(group).SaveX(e.sys)
	e.db.Client().RouteHostname.Create().SetOrgID(org).SetRouteID(route.ID).SetGatewayGroupID(group).SetRouteType("http").
		SetHostname("www.example.com").SetDomainID(txt.GetId()).ExecX(e.sys)
	del := func(id, etag string) error {
		_, err := ada.dom.DeleteDomain(ctx, connect.NewRequest(&rpmgrv1.DeleteDomainRequest{DomainId: id, Etag: etag}))
		return err
	}
	if err := del(txt.GetId(), ""); reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("a claim with a route hostname: %v", err)
	}
	if err := del(web.GetId(), "7"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if err := del(web.GetId(), web.GetEtag()); err != nil {
		t.Fatal(err)
	}
	if _, err := claim(ada, org, "apps.example.org", false, 0); err != nil {
		t.Fatalf("a deleted name claimed again: %v", err)
	}
}

// TestDomain_TrustedOnlyByInstanceAdmin (docs/12-testing-and-quality.md, "Security testing"):
// only the Instance Admin, after a step-up, marks a claim trusted, also of an org they are not a
// member of; an org Owner cannot; the trusted claim is verified without a proof, the change is
// audited, and the name stays unique in the instance.
func TestDomain_TrustedOnlyByInstanceAdmin(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	d, err := claim(bob, orgB, "bob.example", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	trust := func(b *browser) (*rpmgrv1.Domain, error) {
		r, err := b.dom.MarkDomainTrusted(ctx, connect.NewRequest(&rpmgrv1.MarkDomainTrustedRequest{DomainId: d.GetId()}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetDomain(), nil
	}
	if _, err := trust(ada); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("the Instance Admin without a step-up: %v", err)
	}
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := trust(bob); code(err) != connect.CodePermissionDenied {
		t.Fatalf("the org's Owner trusts their own claim: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	own, _ := e.join(t, ada, org, "own@example.com", "owner")
	if err := own.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := trust(own); code(err) != connect.CodePermissionDenied {
		t.Fatalf("another org's Owner: %v", err)
	}
	got, err := trust(ada)
	if err != nil || got.GetStatus() != rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED || got.GetMethod() != rpmgrv1.DomainMethod_DOMAIN_METHOD_TRUSTED ||
		got.GetVerifyTime() == nil || got.GetChallenge() != nil {
		t.Fatalf("the Instance Admin trusts it: %v %v", got, err)
	}
	audited := func(r auditentry.Result) int {
		return e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.DomainService.MarkDomainTrusted"), auditentry.ResultEQ(r)).
			CountX(e.sys)
	}
	if audited(auditentry.ResultSuccess) != 1 || audited(auditentry.ResultDenied) != 3 {
		t.Errorf("audited: %d successes, %d refusals", audited(auditentry.ResultSuccess), audited(auditentry.ResultDenied))
	}
	if again, err := trust(ada); err != nil || !again.GetVerifyTime().AsTime().Equal(got.GetVerifyTime().AsTime()) {
		t.Fatalf("a second time: %v %v", again, err)
	}
	if _, err := claim(ada, org, "bob.example", false, 0); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a claim on a trusted name: %v", err)
	}
	if _, err := ada.dom.MarkDomainTrusted(ctx, connect.NewRequest(&rpmgrv1.MarkDomainTrustedRequest{DomainId: "dom_missing"})); code(err) !=
		connect.CodeNotFound {
		t.Fatalf("a missing claim: %v", err)
	}
}

// addOwner adds a user who owns org and returns them signed in.
func (e *env) addOwner(t *testing.T, org, email string) (*browser, string) {
	t.Helper()
	h, err := password.Hash(context.Background(), pw, password.LowMemory)
	if err != nil {
		t.Fatal(err)
	}
	u := e.db.Client().User.Create().SetEmail(email).SetDisplayName(email).SetPasswordHash(h).SaveX(e.sys)
	e.db.Client().Membership.Create().SetOrgID(org).SetUserID(u.ID).SetRole("owner").SetCreatedBy("test").ExecX(e.sys)
	b := e.browser()
	if err := b.login(email, pw); err != nil {
		t.Fatal(err)
	}
	return b, u.ID
}
