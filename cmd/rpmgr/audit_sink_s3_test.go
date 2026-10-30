// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// sinkSession serves AuditSinkService from a and returns a runner of rpmgr commands logged in to it.
func sinkSession(t *testing.T, a *sinkAPI) (run func(args ...string) (int, string, string), dir string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewAuditSinkServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	dir = t.TempDir()
	creds := filepath.Join(dir, "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { return "right", nil }
	t.Cleanup(func() { stepUpPrompt = old })
	return func(args ...string) (int, string, string) {
		return runWith(map[string]string{"RPMGR_CREDENTIALS": creds}, "", args...)
	}, dir
}

// TestAuditSinkCommands_S3 (#656): create audit-sink --kind s3 sends the store's settings and the
// secret key from a file, without its line break and never printed; update names the fields it
// changes; input that cannot be a sink sends nothing.
func TestAuditSinkCommands_S3(t *testing.T) {
	a := &sinkAPI{}
	run, dir := sinkSession(t, a)
	keyFile := filepath.Join(dir, "s3.key")
	const key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" //nolint:gosec // G101: the AWS documentation's example
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"create", "audit-sink", "--name", "vault", "--kind", "s3", "--endpoint", "https://s3.example.com", "--region", "eu-central-1",
		"--bucket", "rpmgr-audit", "--access-key-id", "AKIAIOSFODNN7EXAMPLE", "--secret-file", keyFile}
	for name, args := range map[string][]string{
		"a lock that is no number": append(slices.Clone(base), "--retention-days", "many"),
		"a missing key file":       append(slices.Clone(base[:len(base)-1]), filepath.Join(dir, "missing")),
		"a missing CA file":        append(slices.Clone(base), "--ca-file", filepath.Join(dir, "missing.pem")),
	} {
		if code, _, _ := run(args...); code == cli.ExitOK || a.created != nil {
			t.Errorf("%s: %d, request %v", name, code, a.created)
		}
	}

	code, out, errOut := run(append(slices.Clone(base), "--retention-days", "90", "--entries")...)
	got := a.created.GetAuditSink()
	if code != cli.ExitOK || got.GetKind() != rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_S3 || got.GetEndpoint() != "https://s3.example.com" ||
		got.GetRegion() != "eu-central-1" || got.GetBucket() != "rpmgr-audit" || got.GetAccessKeyId() != "AKIAIOSFODNN7EXAMPLE" || //nolint:gosec // G101: AWS documentation example credentials, not secrets
		got.GetRetentionDays() != 90 || got.GetSecret() != key || !got.GetEntries() || strings.Contains(out+errOut, key) {
		t.Fatalf("create: %d %q %q %v", code, out, errOut, a.created)
	}
	if code, _, _ := run("update", "audit-sink", "ask_1", "--region", "eu-west-1", "--bucket", "other-bucket", "--force"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"region", "bucket"}) || a.updated.GetAuditSink().GetBucket() != "other-bucket" {
		t.Fatalf("update: %d %v", code, a.updated)
	}
}
