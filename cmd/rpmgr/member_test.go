// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// memberAPI has the members alice (Owner) and bob (Operator) and one token; granting or inviting
// Admin or Owner needs a step-up, and the last Owner stays.
type memberAPI struct {
	rpmgrv1connect.UnimplementedOrgServiceHandler
	rpmgrv1connect.UnimplementedTokenServiceHandler
	stepUpAPI

	mu       sync.Mutex
	updated  *rpmgrv1.UpdateMemberRequest
	removed  *rpmgrv1.RemoveMemberRequest
	invited  *rpmgrv1.CreateInvitationRequest
	revoked  *rpmgrv1.RevokeAPITokenRequest
	mailed   bool
	attempts int
}

func (a *memberAPI) ListMembers(context.Context, *connect.Request[rpmgrv1.ListMembersRequest]) (*connect.Response[rpmgrv1.ListMembersResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListMembersResponse{Members: []*rpmgrv1.Member{
		{UserId: "usr_alice", Email: "alice@example.com", DisplayName: "Alice", Role: "owner"},
		{UserId: "usr_bob", Email: "bob@example.com", DisplayName: "Bob", Role: "operator"},
	}}), nil
}

// privileged answers STEP_UP_REQUIRED for a role above Operator until the token stepped up.
func (a *memberAPI) privileged(role string) error {
	a.stepUpAPI.mu.Lock()
	defer a.stepUpAPI.mu.Unlock()
	if (role == "owner" || role == "admin") && !a.stepped {
		return stepUpError()
	}
	return nil
}

func (a *memberAPI) UpdateMember(_ context.Context, req *connect.Request[rpmgrv1.UpdateMemberRequest]) (*connect.Response[rpmgrv1.UpdateMemberResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attempts++
	if err := a.privileged(req.Msg.GetRole()); err != nil {
		return nil, err
	}
	a.updated = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateMemberResponse{}), nil
}

func (a *memberAPI) RemoveMember(_ context.Context, req *connect.Request[rpmgrv1.RemoveMemberRequest]) (*connect.Response[rpmgrv1.RemoveMemberResponse], error) {
	if req.Msg.GetUserId() == "usr_alice" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("accounts: an org keeps one Owner"))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removed = req.Msg
	return connect.NewResponse(&rpmgrv1.RemoveMemberResponse{}), nil
}

func (a *memberAPI) CreateInvitation(_ context.Context, req *connect.Request[rpmgrv1.CreateInvitationRequest]) (
	*connect.Response[rpmgrv1.CreateInvitationResponse], error) {
	if err := a.privileged(req.Msg.GetRole()); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.invited = req.Msg
	return connect.NewResponse(&rpmgrv1.CreateInvitationResponse{Url: "https://rpmgr.example.com/invite#rpmgr_inv_abc",
		ExpireTime: timestamppb.New(time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)), EmailSent: a.mailed}), nil
}

func (a *memberAPI) ListAPITokens(context.Context, *connect.Request[rpmgrv1.ListAPITokensRequest]) (*connect.Response[rpmgrv1.ListAPITokensResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListAPITokensResponse{ApiTokens: []*rpmgrv1.APIToken{
		{Id: "atk_1", Name: "laptop", Prefix: "rpmgr_pat_Ab3d", Scopes: []string{"org.read", "routes.write"}},
	}}), nil
}

func (a *memberAPI) RevokeAPIToken(_ context.Context, req *connect.Request[rpmgrv1.RevokeAPITokenRequest]) (
	*connect.Response[rpmgrv1.RevokeAPITokenResponse], error) {
	if req.Msg.GetTokenId() != "atk_1" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("accounts: no such token"))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked = req.Msg
	return connect.NewResponse(&rpmgrv1.RevokeAPITokenResponse{}), nil
}

// TestMembersAndTokens (docs/16-cli.md): members and tokens are listed in one answer; a member is
// named by user ID or e-mail address; granting Admin or Owner and inviting as one take a step-up;
// the invitation link is printed once; the API's refusals reach the user; tokens are revoked but
// not made from the command line.
func TestMembersAndTokens(t *testing.T) {
	a := &memberAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewOrgServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewTokenServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { return "right", nil }
	t.Cleanup(func() { stepUpPrompt = old })

	code, out, errOut := run("list", "member")
	if code != cli.ExitOK || !strings.Contains(out, "usr_alice") || !strings.Contains(out, "Bob") || !strings.Contains(out, "operator") ||
		!strings.Contains(out, "bob@example.com") {
		t.Fatalf("list member: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := run("list", "token"); code != cli.ExitOK || !strings.Contains(out, "atk_1") || !strings.Contains(out, "laptop") ||
		!strings.Contains(out, "org.read,routes.write") {
		t.Fatalf("list token: %d %q %q", code, out, errOut)
	}
	if code, _, _ := run("get", "member", "usr_bob"); code != cli.ExitUsage {
		t.Errorf("get member: %d", code)
	}

	if code, out, _ := run("update", "member", "--role", "operator", "usr_bob"); code != cli.ExitOK || len(a.stepUps) != 0 ||
		a.updated.GetUserId() != "usr_bob" || a.updated.GetOrgId() != "org_1" || !strings.Contains(out, "bob@example.com is now operator") {
		t.Fatalf("a role below Admin: %d %q", code, out)
	}
	if code, _, _ := run("update", "member", "--role", "admin", "Bob@Example.com"); code != cli.ExitOK || len(a.stepUps) != 1 ||
		a.updated.GetUserId() != "usr_bob" || a.updated.GetRole() != "admin" || a.attempts != 3 {
		t.Fatalf("granting Admin: %d, %d step-ups, %d attempts", code, len(a.stepUps), a.attempts)
	}
	for name, args := range map[string][]string{
		"an unknown role": {"--role", "superuser", "usr_bob"},
		"no role":         {"usr_bob"},
		"no member":       {"--role", "viewer"},
	} {
		attempts := a.attempts
		if code, _, _ := run(append([]string{"update", "member"}, args...)...); code != cli.ExitUsage || a.attempts != attempts {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _, errOut := run("update", "member", "--role", "viewer", "nobody@example.com"); code != cli.ExitError ||
		!strings.Contains(errOut, `no member "nobody@example.com"`) {
		t.Errorf("an unknown member: %d %q", code, errOut)
	}

	if code, out, _ := run("remove", "member", "bob@example.com"); code != cli.ExitOK || a.removed.GetUserId() != "usr_bob" ||
		!strings.Contains(out, "Removed bob@example.com") {
		t.Fatalf("remove: %d %q", code, out)
	}
	if code, _, errOut := run("remove", "member", "usr_alice"); code != cli.ExitError || !strings.Contains(errOut, "keeps one Owner") {
		t.Errorf("the last Owner: %d %q", code, errOut)
	}

	a.stepUpAPI.mu.Lock()
	a.stepped = false
	a.stepUpAPI.mu.Unlock()
	code, out, _ = run("create", "invitation", "--email", "carol@example.com", "--role", "owner")
	if code != cli.ExitOK || len(a.stepUps) != 2 || a.invited.GetRole() != "owner" || a.invited.GetEmail() != "carol@example.com" ||
		!strings.Contains(out, "https://rpmgr.example.com/invite#rpmgr_inv_abc") || !strings.Contains(out, "2026-10-16 12:00 UTC") ||
		!strings.Contains(out, "pass it on to carol@example.com yourself") {
		t.Fatalf("an invitation as Owner: %d %q", code, out)
	}
	a.mailed = true
	if code, out, _ := run("create", "invitation", "--email", "dave@example.com"); code != cli.ExitOK || a.invited.GetRole() != "viewer" ||
		!strings.Contains(out, "also e-mailed to dave@example.com") {
		t.Fatalf("an e-mailed invitation: %d %q", code, out)
	}
	for name, args := range map[string][]string{"no address": {"--role", "viewer"}, "an unknown role": {"--email", "e@example.com", "--role", "root"}} {
		if code, _, _ := run(append([]string{"create", "invitation"}, args...)...); code != cli.ExitUsage {
			t.Errorf("an invitation with %s: %d", name, code)
		}
	}

	if code, out, _ := run("revoke", "token", "atk_1"); code != cli.ExitOK || a.revoked.GetOrgId() != "org_1" || !strings.Contains(out, "Revoked token atk_1") {
		t.Fatalf("revoke: %d %q", code, out)
	}
	if code, _, errOut := run("revoke", "token", "atk_9"); code != cli.ExitError || !strings.Contains(errOut, "no such token") {
		t.Errorf("an unknown token: %d %q", code, errOut)
	}
	if code, _, errOut := run("create", "token"); code != cli.ExitUsage || !strings.Contains(errOut, "web UI") {
		t.Errorf("create token: %d %q", code, errOut)
	}
}
