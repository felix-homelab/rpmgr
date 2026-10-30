// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// exportAPI answers the exports with fixed lines, in two parts, or its error.
type exportAPI struct {
	rpmgrv1connect.UnimplementedAuditServiceHandler
	stepUpAPI
	orgs  []string
	needs bool // answer STEP_UP_REQUIRED until the token stepped up
	calls int
	err   error
}

func (a *exportAPI) ExportAudit(_ context.Context, req *connect.Request[rpmgrv1.ExportAuditRequest], st *connect.ServerStream[rpmgrv1.ExportAuditResponse]) error {
	a.orgs = append(a.orgs, req.Msg.GetOrgId())
	return a.send(func(l []string) error { return st.Send(&rpmgrv1.ExportAuditResponse{Lines: l}) }, "org")
}

func (a *exportAPI) ExportInstanceAudit(_ context.Context, _ *connect.Request[rpmgrv1.ExportInstanceAuditRequest], st *connect.ServerStream[rpmgrv1.ExportInstanceAuditResponse]) error {
	return a.send(func(l []string) error { return st.Send(&rpmgrv1.ExportInstanceAuditResponse{Lines: l}) }, "instance")
}

func (a *exportAPI) needStepUp() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.stepped {
		return stepUpError()
	}
	return nil
}

func (a *exportAPI) send(send func([]string) error, chain string) error {
	a.calls++
	if a.needs {
		if err := a.needStepUp(); err != nil {
			return err
		}
	}
	if a.err != nil {
		return a.err
	}
	if err := send([]string{`{"type":"header","chain":"` + chain + `"}`}); err != nil {
		return err
	}
	return send([]string{`{"type":"entry","seq":1}`, `{"type":"entry","seq":2}`})
}

func auditEnv(t *testing.T, a *exportAPI) map[string]string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewAuditServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(&a.stepUpAPI))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"RPMGR_CREDENTIALS": creds}
}

// TestAuditExport (docs/16-cli.md): export writes the org's lines to a new file with mode 0600,
// or the instance chain's with --instance, or standard output for -; it never replaces a file;
// a refusal leaves no file behind; a missing --out is a usage error.
func TestAuditExport(t *testing.T) {
	a := &exportAPI{}
	env := auditEnv(t, a)
	dir := t.TempDir()
	file := filepath.Join(dir, "org.jsonl")

	code, out, errOut := runWith(env, "", "audit", "export", "--out", file)
	got, err := os.ReadFile(file)
	if code != cli.ExitOK || err != nil || string(got) != "{\"type\":\"header\",\"chain\":\"org\"}\n{\"type\":\"entry\",\"seq\":1}\n{\"type\":\"entry\",\"seq\":2}\n" ||
		!strings.Contains(out, "Wrote "+file+": 3 lines") || a.orgs[0] != "org_1" {
		t.Fatalf("export: %d %q %v\n%s\n%s", code, got, err, out, errOut)
	}
	if st, err := os.Stat(file); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode of the export: %v %v", st, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".rpmgr-audit-export-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}

	calls := a.calls
	if code, _, errOut := runWith(env, "", "audit", "export", "--out", file); code != cli.ExitError || !strings.Contains(errOut, "never overwrites") || a.calls != calls {
		t.Fatalf("an existing file: %d %s (calls %d)", code, errOut, a.calls)
	}
	if again, _ := os.ReadFile(file); string(again) != string(got) {
		t.Fatal("an existing export was replaced")
	}

	inst := filepath.Join(dir, "instance.jsonl")
	if code, _, _ := runWith(env, "", "audit", "export", "--instance", "--out", inst); code != cli.ExitOK {
		t.Fatalf("export --instance: %d", code)
	}
	if b, _ := os.ReadFile(inst); !strings.Contains(string(b), `"chain":"instance"`) {
		t.Fatalf("the instance export: %s", b)
	}
	if code, out, _ := runWith(env, "", "audit", "export", "--out", "-"); code != cli.ExitOK || !strings.HasPrefix(out, `{"type":"header"`) || strings.Contains(out, "Wrote") {
		t.Fatalf("export to standard output: %d %q", code, out)
	}

	for name, args := range map[string][]string{"no --out": {"audit", "export"}, "an argument": {"audit", "export", "--out", file + "2", "x"}} {
		if code, _, _ := runWith(env, "", args...); code != cli.ExitUsage {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	// A step-up is asked for on the terminal, and the export then runs again into a new file.
	a.needs = true
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { return "right", nil }
	t.Cleanup(func() { stepUpPrompt = old })
	stepped := filepath.Join(dir, "stepped.jsonl")
	if code, _, errOut := runWith(env, "", "audit", "export", "--out", stepped); code != cli.ExitOK {
		t.Fatalf("an export after a step-up: %d %s", code, errOut)
	}
	if b, _ := os.ReadFile(stepped); strings.Count(string(b), "\n") != 3 || len(a.stepUps) != 1 {
		t.Fatalf("the export after a step-up: %q, %d step-ups", b, len(a.stepUps))
	}
	a.needs = false
	a.err = connect.NewError(connect.CodePermissionDenied, os.ErrPermission)
	refused := filepath.Join(dir, "refused.jsonl")
	if code, _, errOut := runWith(env, "", "audit", "export", "--out", refused); code != cli.ExitError || !strings.Contains(errOut, "permission") {
		t.Fatalf("a refused export: %d %s", code, errOut)
	}
	if _, err := os.Stat(refused); err == nil {
		t.Fatal("a refused export left a file")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".rpmgr-audit-export-*")); len(left) != 0 {
		t.Fatalf("temporary files left after a refusal: %v", left)
	}
}

// selfSigned returns a root certificate and its pin.
func selfSigned(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, pki.RootPin(c)
}

// TestAuditVerifyExport (docs/16-cli.md): verify-export needs no controller; an export of an empty
// chain verifies; a wrong pin, an entry that does not link, a missing file and a malformed pin
// are refused, the first two as not verified.
func TestAuditVerifyExport(t *testing.T) {
	root, pin := selfSigned(t)
	hdr, err := json.Marshal(audit.ExportHeader{Type: audit.LineHeader, Format: audit.ExportFormat, Chain: "org_1", Root: root.Raw})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	bad := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(good, append(hdr, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, append(hdr, "\n"+`{"type":"entry","seq":1,"prev_hash":"AAAA","hash":"AAAA"}`+"\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	if code, out, errOut := runWith(env, "", "audit", "verify-export", "--ca-pin", pin, good); code != cli.ExitOK || !strings.Contains(out, "Verified the chain org_1: 0 entries") {
		t.Fatalf("an empty chain: %d %s %s", code, out, errOut)
	}
	_, otherPin := selfSigned(t)
	for name, c := range map[string]struct {
		args []string
		code int
		msg  string
	}{
		"a wrong pin":                 {[]string{"--ca-pin", otherPin, good}, cli.ExitError, "does not match the pin"},
		"an entry that does not link": {[]string{"--ca-pin", pin, bad}, cli.ExitError, "NOT VERIFIED"},
		"a missing file":              {[]string{"--ca-pin", pin, filepath.Join(dir, "none")}, cli.ExitError, "no such file"},
		"a malformed pin":             {[]string{"--ca-pin", "sha256:x", good}, cli.ExitUsage, "--ca-pin"},
		"no pin":                      {[]string{good}, cli.ExitUsage, "--ca-pin"},
		"no file":                     {[]string{"--ca-pin", pin}, cli.ExitUsage, "--ca-pin"},
	} {
		code, out, errOut := runWith(env, "", append([]string{"audit", "verify-export"}, c.args...)...)
		if code != c.code || !strings.Contains(errOut, c.msg) || strings.Contains(out, "Verified") {
			t.Errorf("%s: %d %q %q", name, code, out, errOut)
		}
	}
}
