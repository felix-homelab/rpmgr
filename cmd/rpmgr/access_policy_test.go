// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// policyAPI has the policy ap_1 and records the writes; like the controller, it never returns a
// password.
type policyAPI struct {
	rpmgrv1connect.UnimplementedPolicyServiceHandler

	mu      sync.Mutex
	created *rpmgrv1.CreateAccessPolicyRequest
	updated *rpmgrv1.UpdateAccessPolicyRequest
}

var ap1 = &rpmgrv1.AccessPolicy{Id: "ap_1", Name: "office", Etag: "3", Rules: []*rpmgrv1.AccessRule{
	{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: []*rpmgrv1.BasicAuthCredential{{Name: "alice"}}}}},
}}

func withoutPasswords(p *rpmgrv1.AccessPolicy) *rpmgrv1.AccessPolicy {
	p = proto.Clone(p).(*rpmgrv1.AccessPolicy)
	for _, r := range p.GetRules() {
		for _, u := range r.GetBasicAuth().GetUsers() {
			u.Password = ""
		}
	}
	return p
}

func (a *policyAPI) CreateAccessPolicy(_ context.Context, req *connect.Request[rpmgrv1.CreateAccessPolicyRequest]) (
	*connect.Response[rpmgrv1.CreateAccessPolicyResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.created = req.Msg
	p := withoutPasswords(req.Msg.GetAccessPolicy())
	p.Id = "ap_1"
	return connect.NewResponse(&rpmgrv1.CreateAccessPolicyResponse{AccessPolicy: p}), nil
}

func (a *policyAPI) GetAccessPolicy(context.Context, *connect.Request[rpmgrv1.GetAccessPolicyRequest]) (*connect.Response[rpmgrv1.GetAccessPolicyResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetAccessPolicyResponse{AccessPolicy: ap1}), nil
}

func (a *policyAPI) UpdateAccessPolicy(_ context.Context, req *connect.Request[rpmgrv1.UpdateAccessPolicyRequest]) (
	*connect.Response[rpmgrv1.UpdateAccessPolicyResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updated = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateAccessPolicyResponse{AccessPolicy: withoutPasswords(req.Msg.GetAccessPolicy())}), nil
}

// TestAccessPolicies (docs/16-cli.md): rules are sent in the order given; basic-auth passwords
// come from a file or the prompt, never from an argument; an update keeps a user's password when
// the prompt is left empty; bad rules and bad password files are usage errors.
func TestAccessPolicies(t *testing.T) {
	a := &policyAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewPolicyServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }
	file := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	type ask struct {
		user string
		keep bool
	}
	var asked []ask
	answers := map[string]string{}
	old := passwordPrompt
	passwordPrompt = func(user string, keep bool) (string, error) {
		asked = append(asked, ask{user, keep})
		pw, ok := answers[user]
		if !ok {
			return "", errors.New("no terminal")
		}
		return pw, nil
	}
	t.Cleanup(func() { passwordPrompt = old })
	users := func(r *rpmgrv1.AccessRule) map[string]string {
		out := map[string]string{}
		for _, u := range r.GetBasicAuth().GetUsers() {
			out[u.GetName()] = u.GetPassword()
		}
		return out
	}

	pwFile := file("passwords", "# office users\nalice:alice-password-1\n\nbob:has:colons:in-it\r\n", 0o600)
	code, out, errOut := run("create", "access-policy", "--name", "office", "--rule", "allow:10.0.0.0/8,2001:db8::/32",
		"--rule", "basic-auth:alice,bob", "--rule", "deny:0.0.0.0/0", "--passwords-file", pwFile)
	rules := a.created.GetAccessPolicy().GetRules()
	if code != cli.ExitOK || errOut != "" || len(asked) != 0 || !strings.Contains(out, "Created access policy ap_1") || len(rules) != 3 ||
		!slices.Equal(rules[0].GetIpAllow().GetCidrs(), []string{"10.0.0.0/8", "2001:db8::/32"}) ||
		users(rules[1])["alice"] != "alice-password-1" || users(rules[1])["bob"] != "has:colons:in-it" ||
		!slices.Equal(rules[2].GetIpDeny().GetCidrs(), []string{"0.0.0.0/0"}) || a.created.GetOrgId() != "org_1" {
		t.Fatalf("create from a file: %d %q %q %v %v", code, out, errOut, asked, a.created)
	}
	if strings.Contains(out, "alice-password-1") {
		t.Fatalf("a password printed: %q", out)
	}

	answers["carol"] = "carol-password-1"
	if code, _, errOut := run("create", "access-policy", "--name", "lab", "--rule", "basic-auth:alice,carol",
		"--passwords-file", file("open", "alice:alice-password-1\n", 0o644)); code != cli.ExitOK ||
		!strings.Contains(errOut, "open to other users (mode 0644)") || !slices.Equal(asked, []ask{{"carol", false}}) ||
		users(a.created.GetAccessPolicy().GetRules()[0])["carol"] != "carol-password-1" {
		t.Fatalf("create with a prompt: %d %q %v", code, errOut, asked)
	}

	for name, args := range map[string][]string{
		"no name":             {"--rule", "allow:10.0.0.0/8"},
		"no colon":            {"--name", "x", "--rule", "allow"},
		"no values":           {"--name", "x", "--rule", "basic-auth:"},
		"unknown kind":        {"--name", "x", "--rule", "permit:10.0.0.0/8"},
		"password in argv":    {"--name", "x", "--rule", "basic-auth:alice:secret-password"},
		"empty password":      {"--name", "x", "--rule", "basic-auth:dave"},
		"bad passwords file":  {"--name", "x", "--rule", "basic-auth:alice", "--passwords-file", file("bad", "alice\n", 0o600)},
		"invalid name":        {"--name", "Not A Name", "--rule", "allow:10.0.0.0/8"},
		"unexpected argument": {"--name", "x", "ap_1"},
	} {
		answers["dave"] = ""
		a.created = nil
		if code, _, _ := run(append([]string{"create", "access-policy"}, args...)...); code != cli.ExitUsage || a.created != nil {
			t.Errorf("%s: %d, sent %v", name, code, a.created)
		}
	}
	asked = nil
	if code, _, errOut := run("create", "access-policy", "--name", "x", "--rule", "basic-auth:erin"); code != cli.ExitError ||
		!strings.Contains(errOut, "no terminal") || a.created != nil {
		t.Errorf("no terminal: %d %q", code, errOut)
	}
	if code, _, _ := run("create", "access-policy", "--name", "x", "--passwords-file", filepath.Join(dir, "missing")); code != cli.ExitError {
		t.Errorf("a missing passwords file: %d", code)
	}

	asked, answers["alice"] = nil, ""
	if code, _, _ := run("update", "access-policy", "--rule", "basic-auth:alice", "--rule", "allow:192.0.2.0/24", "ap_1"); code != cli.ExitOK ||
		!slices.Equal(asked, []ask{{"alice", true}}) || !slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"rules"}) ||
		a.updated.GetEtag() != "3" || len(a.updated.GetAccessPolicy().GetRules()) != 2 ||
		users(a.updated.GetAccessPolicy().GetRules()[0])["alice"] != "" || a.updated.GetAccessPolicy().GetName() != "office" {
		t.Fatalf("an update keeping alice's password: %d %v %v", code, asked, a.updated)
	}
	asked = nil
	if code, _, _ := run("update", "access-policy", "--name", "office-2", "--force", "ap_1"); code != cli.ExitOK || len(asked) != 0 ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"name"}) || a.updated.GetEtag() != "" ||
		a.updated.GetAccessPolicy().GetName() != "office-2" || len(a.updated.GetAccessPolicy().GetRules()) != 1 {
		t.Fatalf("a rename: %d %v", code, a.updated)
	}
	for name, args := range map[string][]string{"no field": {"ap_1"}, "no ID": {"--name", "x"}} {
		if code, _, _ := run(append([]string{"update", "access-policy"}, args...)...); code != cli.ExitUsage {
			t.Errorf("update with %s: %d", name, code)
		}
	}
}
