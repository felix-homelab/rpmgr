// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// TestTokenScopesBoundedByCreator (docs/12-testing-and-quality.md, "Security testing"): a token's
// scopes are permissions its creator holds in its org when it is made; a token acts only within
// its scopes, its org and its owner's current role, so a demotion limits it at once; it works
// only as a Bearer header, never from a query string; it cannot make another token; revoked or
// expired, it is refused, and its revocation is in the revocation log.
func TestTokenScopesBoundedByCreator(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	create := func(b *browser, scopes []string, ttl time.Duration) (string, error) {
		req := &rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "ci", Scopes: scopes}
		if ttl != 0 {
			req.Ttl = durationpb.New(ttl)
		}
		r, err := b.token.CreateAPIToken(ctx, connect.NewRequest(req))
		if err != nil {
			return "", err
		}
		return r.Msg.GetToken(), nil
	}
	if _, err := create(ada, []string{"org.read"}, 0); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a token without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}

	// An Admin, invited by the Owner, makes a token for members.
	inv, err := ada.org.CreateInvitation(ctx, connect.NewRequest(&rpmgrv1.CreateInvitationRequest{OrgId: org, Email: "adm@example.com",
		Role: "admin"}))
	if err != nil {
		t.Fatal(err)
	}
	_, tok, _ := strings.Cut(inv.Msg.GetUrl(), "#")
	adm := e.browser()
	accepted, err := adm.org.AcceptInvitation(ctx, connect.NewRequest(&rpmgrv1.AcceptInvitationRequest{Token: tok, DisplayName: "Adm", Password: pw}))
	if err != nil {
		t.Fatal(err)
	}
	if err := adm.login("adm@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := adm.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	for name, scopes := range map[string][]string{
		"a permission the Admin lacks": {"org.write"},
		"Instance Admin":               {"instance.admin"},
		"not a permission":             {"everything"},
		"a special permission":         {"authenticated"},
	} {
		if _, err := create(adm, scopes, 0); code(err) != connect.CodePermissionDenied {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := create(adm, []string{"org.read"}, 366*24*time.Hour); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a token for more than a year: %v", err)
	}
	admTok, err := create(adm, []string{"org.read", "members.write"}, 0)
	if err != nil || !strings.HasPrefix(admTok, "rpmgr_pat_") {
		t.Fatalf("the Admin's token: %q %v", admTok, err)
	}
	cli := e.browser()
	cli.bearer = admTok
	invite := func() error {
		_, err := cli.org.CreateInvitation(ctx, connect.NewRequest(&rpmgrv1.CreateInvitationRequest{OrgId: org, Email: "x@example.com",
			Role: "viewer"}))
		return err
	}
	if err := invite(); err != nil {
		t.Fatalf("the token within its scopes: %v", err)
	}
	if _, err := cli.org.UpdateOrg(ctx, connect.NewRequest(&rpmgrv1.UpdateOrgRequest{OrgId: org, Name: "x"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("the token outside its scopes: %v", err)
	}
	if _, err := cli.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "x",
		Scopes: []string{"org.read"}})); err == nil {
		t.Fatal("a token made a token")
	}

	// The Owner demotes the Admin: the token loses members.write at once, keeps org.read.
	if _, err := ada.org.UpdateMember(ctx, connect.NewRequest(&rpmgrv1.UpdateMemberRequest{OrgId: org,
		UserId: accepted.Msg.GetUserId(), Role: "viewer"})); err != nil {
		t.Fatal(err)
	}
	if err := invite(); code(err) != connect.CodePermissionDenied {
		t.Fatalf("the token after its owner's demotion: %v", err)
	}
	if _, err := cli.org.ListMembers(ctx, connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: org})); err != nil {
		t.Fatalf("org.read after the demotion: %v", err)
	}

	// Only the Authorization header carries a token.
	req, _ := http.NewRequest(http.MethodPost, e.url+"/rpmgr.v1.TokenService/ListAPITokens?token="+admTok+"&access_token="+admTok,
		strings.NewReader(`{"orgId":"`+org+`"}`))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a token in the query string: %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}

	// Revoked, the token is refused, and the revocation log has it.
	list, err := adm.token.ListAPITokens(ctx, connect.NewRequest(&rpmgrv1.ListAPITokensRequest{OrgId: org}))
	if err != nil || len(list.Msg.GetApiTokens()) != 1 || list.Msg.GetApiTokens()[0].GetLastUseTime() == nil ||
		!strings.HasPrefix(admTok, list.Msg.GetApiTokens()[0].GetPrefix()) {
		t.Fatalf("the Admin's tokens: %v %v", list, err)
	}
	id := list.Msg.GetApiTokens()[0].GetId()
	if _, err := ada.token.RevokeAPIToken(ctx, connect.NewRequest(&rpmgrv1.RevokeAPITokenRequest{OrgId: org, TokenId: id})); code(err) != connect.CodeNotFound {
		t.Fatalf("another user's token: %v", err)
	}
	if _, err := adm.token.RevokeAPIToken(ctx, connect.NewRequest(&rpmgrv1.RevokeAPITokenRequest{OrgId: org, TokenId: id})); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.org.ListMembers(ctx, connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: org})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a revoked token: %v", err)
	}
	entries, err := revlog.Read(e.log)
	found := false
	for _, en := range entries {
		found = found || en.Kind == revlog.APITokenRevoked && en.Subject == id && en.Org == org
	}
	if err != nil || !found {
		t.Fatalf("the revocation log: %+v %v", entries, err)
	}

	// Expired, a token is refused.
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	short, err := create(ada, []string{"org.read"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cli.bearer = short
	if _, err := cli.org.GetOrg(ctx, connect.NewRequest(&rpmgrv1.GetOrgRequest{OrgId: org})); err != nil {
		t.Fatalf("a fresh token: %v", err)
	}
	e.clock = e.clock.Add(time.Hour)
	if _, err := cli.org.GetOrg(ctx, connect.NewRequest(&rpmgrv1.GetOrgRequest{OrgId: org})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("an expired token: %v", err)
	}
}
