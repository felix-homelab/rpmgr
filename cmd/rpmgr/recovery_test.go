// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

// recoveryAPI is memberAPI with the account-recovery methods, each needing a step-up. Its users
// are the members and carol, who is in no org of the token; ListUsers answers two pages, or
// PERMISSION_DENIED unless instanceAdmin.
type recoveryAPI struct {
	memberAPI
	rpmgrv1connect.UnimplementedUserServiceHandler

	instanceAdmin bool
	linked, freed string
	admin         *rpmgrv1.SetInstanceAdminRequest
}

func (a *recoveryAPI) stepped() error {
	a.stepUpAPI.mu.Lock()
	defer a.stepUpAPI.mu.Unlock()
	if !a.stepUpAPI.stepped {
		return stepUpError()
	}
	return nil
}

func (a *recoveryAPI) ListUsers(_ context.Context, req *connect.Request[rpmgrv1.ListUsersRequest]) (*connect.Response[rpmgrv1.ListUsersResponse], error) {
	if !a.instanceAdmin {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("api: the permission instance.admin is missing"))
	}
	if req.Msg.GetPageToken() == "" {
		return connect.NewResponse(&rpmgrv1.ListUsersResponse{Users: []*rpmgrv1.User{{Id: "usr_alice", Email: "alice@example.com"}},
			NextPageToken: "p2"}), nil
	}
	return connect.NewResponse(&rpmgrv1.ListUsersResponse{Users: []*rpmgrv1.User{{Id: "usr_carol", Email: "carol@example.com"}}}), nil
}

func (a *recoveryAPI) CreatePasswordResetLink(_ context.Context, req *connect.Request[rpmgrv1.CreatePasswordResetLinkRequest]) (
	*connect.Response[rpmgrv1.CreatePasswordResetLinkResponse], error) {
	if err := a.stepped(); err != nil {
		return nil, err
	}
	if req.Msg.GetUserId() == "usr_alice" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("accounts: no such user"))
	}
	a.linked = req.Msg.GetUserId()
	return connect.NewResponse(&rpmgrv1.CreatePasswordResetLinkResponse{Url: "https://rpmgr.example.com/reset#rpmgr_prs_abc",
		ExpireTime: timestamppb.New(time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC))}), nil
}

func (a *recoveryAPI) RemoveUserTOTP(_ context.Context, req *connect.Request[rpmgrv1.RemoveUserTOTPRequest]) (
	*connect.Response[rpmgrv1.RemoveUserTOTPResponse], error) {
	if err := a.stepped(); err != nil {
		return nil, err
	}
	if req.Msg.GetUserId() == "usr_alice" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("accounts: no authenticator is set up"))
	}
	a.freed = req.Msg.GetUserId()
	return connect.NewResponse(&rpmgrv1.RemoveUserTOTPResponse{}), nil
}

func (a *recoveryAPI) SetInstanceAdmin(_ context.Context, req *connect.Request[rpmgrv1.SetInstanceAdminRequest]) (
	*connect.Response[rpmgrv1.SetInstanceAdminResponse], error) {
	if err := a.stepped(); err != nil {
		return nil, err
	}
	a.admin = req.Msg
	return connect.NewResponse(&rpmgrv1.SetInstanceAdminResponse{User: &rpmgrv1.User{Id: req.Msg.GetUserId(), InstanceAdmin: req.Msg.GetInstanceAdmin()}}), nil
}

// TestRecoveryCommands (D95; docs/16-cli.md): a reset link, the removal of a second factor and the
// Instance Admin role, each after a step-up, for a user named by ID, by a member's e-mail address
// or, for the Instance Admin, any user's; the API's refusals reach the user; wrong arguments are
// usage errors before any call.
func TestRecoveryCommands(t *testing.T) {
	a := &recoveryAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewOrgServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewUserServiceHandler(a))
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

	code, out, errOut := run("create", "reset-link", "Bob@Example.com")
	if code != cli.ExitOK || a.linked != "usr_bob" || len(a.stepUps) != 1 || !strings.Contains(out, "https://rpmgr.example.com/reset#rpmgr_prs_abc") ||
		!strings.Contains(out, "2026-10-17 09:00 UTC") || !strings.Contains(out, "for bob@example.com") {
		t.Fatalf("a member's reset link: %d %q %q", code, out, errOut)
	}
	if code, _, _ := run("create", "reset-link", "usr_dave"); code != cli.ExitOK || a.linked != "usr_dave" {
		t.Errorf("a user ID: %d %q", code, a.linked)
	}
	if code, _, errOut := run("create", "reset-link", "carol@example.com"); code != cli.ExitError || !strings.Contains(errOut, `no member "carol@example.com"`) {
		t.Errorf("a non-member without the Instance Admin role: %d %q", code, errOut)
	}
	a.instanceAdmin = true
	if code, _, errOut := run("create", "reset-link", "carol@example.com"); code != cli.ExitOK || a.linked != "usr_carol" {
		t.Errorf("a user of the instance, on the second page: %d %q", code, errOut)
	}
	if code, _, errOut := run("create", "reset-link", "zed@example.com"); code != cli.ExitError || !strings.Contains(errOut, `no user has the address "zed@example.com"`) {
		t.Errorf("an unknown address: %d %q", code, errOut)
	}
	if code, _, errOut := run("create", "reset-link", "alice@example.com"); code != cli.ExitError || !strings.Contains(errOut, "no such user") {
		t.Errorf("a refused user: %d %q", code, errOut)
	}

	if code, out, _ := run("remove", "second-factor", "bob@example.com"); code != cli.ExitOK || a.freed != "usr_bob" ||
		!strings.Contains(out, "Removed the second factor of bob@example.com") {
		t.Errorf("remove second-factor: %d %q", code, out)
	}
	if code, _, errOut := run("remove", "second-factor", "usr_alice"); code != cli.ExitError || !strings.Contains(errOut, "no authenticator") {
		t.Errorf("a user without one: %d %q", code, errOut)
	}

	if code, out, _ := run("update", "user", "--instance-admin", "carol@example.com"); code != cli.ExitOK || a.admin.GetUserId() != "usr_carol" ||
		!a.admin.GetInstanceAdmin() || !strings.Contains(out, "carol@example.com is Instance Admin") {
		t.Errorf("grant: %d %q", code, out)
	}
	if code, out, _ := run("update", "user", "--instance-admin=false", "usr_carol"); code != cli.ExitOK || a.admin.GetInstanceAdmin() ||
		!strings.Contains(out, "usr_carol is no Instance Admin") {
		t.Errorf("revoke: %d %q", code, out)
	}
	for name, args := range map[string][]string{
		"reset-link without a user":    {"create", "reset-link"},
		"reset-link with two":          {"create", "reset-link", "usr_a", "usr_b"},
		"second-factor without a user": {"remove", "second-factor"},
		"user without the flag":        {"update", "user", "usr_carol"},
		"user with a wrong value":      {"update", "user", "--instance-admin=maybe", "usr_carol"},
		"user without a user":          {"update", "user", "--instance-admin"},
	} {
		if code, _, _ := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d", name, code)
		}
	}
}
