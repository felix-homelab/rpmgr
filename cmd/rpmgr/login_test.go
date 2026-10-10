// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// orgs answers GetOrg for the token rpmgr_pat_good of org_1; the others are revoked or lack the
// scope.
type orgs struct {
	rpmgrv1connect.UnimplementedOrgServiceHandler
}

func (orgs) GetOrg(_ context.Context, req *connect.Request[rpmgrv1.GetOrgRequest]) (*connect.Response[rpmgrv1.GetOrgResponse], error) {
	switch req.Header().Get("Authorization") {
	case "Bearer rpmgr_pat_good":
		if req.Msg.GetOrgId() != "org_1" {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("not found"))
		}
		return connect.NewResponse(&rpmgrv1.GetOrgResponse{Org: &rpmgrv1.Org{Id: "org_1", Name: "Home"}}), nil
	case "Bearer rpmgr_pat_narrow":
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("the permission org.read is missing"))
	}
	return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
}

// apiServer is a controller's API over TLS with a certificate in a CA file.
func apiServer(t *testing.T) (url, caFile string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewOrgServiceHandler(orgs{}))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, writeCA(t, srv)
}

// writeCA writes a test server's certificate to a CA file.
func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile
}

func runWith(env map[string]string, prompt string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	root := commands()
	for i, c := range root.Sub {
		if c.Name == "login" {
			root.Sub[i] = loginCommand(func() (string, error) { return prompt, nil })
		}
	}
	code := cli.Main(context.Background(), root, args, &cli.Env{Stdout: &out, Stderr: &errOut, Getenv: func(k string) string { return env[k] }})
	return code, out.String(), errOut.String()
}

// TestLogin (docs/16-cli.md): login checks a personal API token against the controller and stores
// it, with the controller, the org and the CA file, in a credentials file only the user can read;
// the token comes from a file, RPMGR_TOKEN or a prompt, never the command line; an unknown,
// revoked or narrow token, another org and a controller that is not https are refused and store
// nothing; logout removes the file.
func TestLogin(t *testing.T) {
	url, ca := apiServer(t)
	creds := filepath.Join(t.TempDir(), "rpmgr", "credentials.yaml")
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte("rpmgr_pat_good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runWith(env, "", "login", "--controller", url+"/", "--org", "org_1", "--ca-file", ca, "--token-file", tokFile)
	if code != cli.ExitOK || !strings.Contains(out, "org Home (org_1)") {
		t.Fatalf("login: %d %q %q", code, out, errOut)
	}
	st, err := os.Stat(creds)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the credentials file: %v %v", st, err)
	}
	c, err := apicli.Load(creds)
	if err != nil || c.Controller != url || c.Org != "org_1" || c.Token.Reveal() != "rpmgr_pat_good" || c.CAFile != ca { //nolint:forbidigo // the test reads back the token it stored
		t.Fatalf("stored: %+v %v", c, err)
	}

	// The environment and the prompt.
	fromEnv := map[string]string{"RPMGR_CREDENTIALS": creds, "RPMGR_TOKEN": "rpmgr_pat_good"} //nolint:gosec // G101: a test token
	if code, _, errOut := runWith(fromEnv, "",
		"login", "--controller", url, "--org", "org_1", "--ca-file", ca); code != cli.ExitOK {
		t.Errorf("a token from RPMGR_TOKEN: %d %s", code, errOut)
	}
	if code, _, errOut := runWith(env, "rpmgr_pat_good", "login", "--controller", url, "--org", "org_1", "--ca-file", ca); code != cli.ExitOK {
		t.Errorf("a token from the prompt: %d %s", code, errOut)
	}

	// Refused: nothing is stored.
	if err := os.Remove(creds); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		token, org, controller string
		code                   int
		says                   string
	}{
		"a revoked token":         {"rpmgr_pat_revoked", "org_1", url, cli.ExitError, "unknown, expired or revoked"},
		"a token without scope":   {"rpmgr_pat_narrow", "org_1", url, cli.ExitError, "org.read"},
		"another org":             {"rpmgr_pat_good", "org_2", url, cli.ExitError, "org_2"},
		"not a token":             {"hunter2", "org_1", url, cli.ExitError, "not a personal API token"},
		"a plain-text URL":        {"rpmgr_pat_good", "org_1", strings.Replace(url, "https", "http", 1), cli.ExitUsage, "https"},
		"no org":                  {"rpmgr_pat_good", "", url, cli.ExitUsage, "--org"},
		"an untrusted controller": {"rpmgr_pat_good", "org_1", url, cli.ExitError, "certificate"},
	} {
		args := []string{"login", "--controller", c.controller, "--org", c.org}
		if name != "an untrusted controller" {
			args = append(args, "--ca-file", ca)
		}
		code, _, errOut := runWith(map[string]string{"RPMGR_CREDENTIALS": creds, "RPMGR_TOKEN": c.token}, "", args...)
		if _, err := os.Stat(creds); code != c.code || !strings.Contains(errOut, c.says) || err == nil {
			t.Errorf("%s: exit %d, %q, credentials stored: %t", name, code, errOut, err == nil)
		}
	}

	if code, out, _ := runWith(env, "", "logout"); code != cli.ExitOK || !strings.Contains(out, "Not logged in") {
		t.Errorf("logout without credentials: %d %q", code, out)
	}
	if code, _, _ := runWith(env, "", "login", "--controller", url, "--org", "org_1", "--ca-file", ca, "--token-file", tokFile); code != cli.ExitOK {
		t.Fatal("login again")
	}
	if code, out, _ := runWith(env, "", "logout"); code != cli.ExitOK || !strings.Contains(out, "revoke it") {
		t.Errorf("logout: %d %q", code, out)
	}
	if _, err := apicli.Load(creds); !errors.Is(err, apicli.ErrNotLoggedIn) {
		t.Errorf("after logout: %v", err)
	}
}
