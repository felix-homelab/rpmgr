// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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

// domainAPI records the domain, certificate and CA bundle requests; trusting needs a step-up.
type domainAPI struct {
	rpmgrv1connect.UnimplementedDomainServiceHandler
	rpmgrv1connect.UnimplementedCertificateServiceHandler
	stepUpAPI

	mu       sync.Mutex
	domain   *rpmgrv1.CreateDomainRequest
	upload   *rpmgrv1.UploadCertificateRequest
	renewals int
	bundle   *rpmgrv1.CreateCABundleRequest
	bundleUp *rpmgrv1.UpdateCABundleRequest
}

func (a *domainAPI) CreateDomain(_ context.Context, req *connect.Request[rpmgrv1.CreateDomainRequest]) (*connect.Response[rpmgrv1.CreateDomainResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.domain = req.Msg
	d := proto.Clone(req.Msg.GetDomain()).(*rpmgrv1.Domain)
	d.Id, d.Status = "dom_1", rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING
	d.Challenge = &rpmgrv1.DomainChallenge{TxtName: "_rpmgr-challenge." + d.GetFqdn(), Value: "v123",
		HttpUrl: "http://" + d.GetFqdn() + "/.well-known/rpmgr-challenge/dom_1"}
	return connect.NewResponse(&rpmgrv1.CreateDomainResponse{Domain: d}), nil
}

func (a *domainAPI) VerifyDomain(context.Context, *connect.Request[rpmgrv1.VerifyDomainRequest]) (*connect.Response[rpmgrv1.VerifyDomainResponse], error) {
	return connect.NewResponse(&rpmgrv1.VerifyDomainResponse{Domain: &rpmgrv1.Domain{Id: "dom_1", Fqdn: "example.com",
		Status: rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING, LastError: "no TXT record at the authoritative servers"}}), nil
}

func (a *domainAPI) MarkDomainTrusted(context.Context, *connect.Request[rpmgrv1.MarkDomainTrustedRequest]) (*connect.Response[rpmgrv1.MarkDomainTrustedResponse], error) {
	a.stepUpAPI.mu.Lock()
	stepped := a.stepped
	a.stepUpAPI.mu.Unlock()
	if !stepped {
		return nil, stepUpError()
	}
	return connect.NewResponse(&rpmgrv1.MarkDomainTrustedResponse{Domain: &rpmgrv1.Domain{Id: "dom_1", Fqdn: "example.com",
		Status: rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED}}), nil
}

func (a *domainAPI) UploadCertificate(_ context.Context, req *connect.Request[rpmgrv1.UploadCertificateRequest]) (*connect.Response[rpmgrv1.UploadCertificateResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upload = req.Msg
	return connect.NewResponse(&rpmgrv1.UploadCertificateResponse{Certificate: &rpmgrv1.Certificate{Id: "crt_1", Sans: []string{"app.example.com"}}}), nil
}

func (a *domainAPI) RenewCertificate(context.Context, *connect.Request[rpmgrv1.RenewCertificateRequest]) (*connect.Response[rpmgrv1.RenewCertificateResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.renewals++
	return connect.NewResponse(&rpmgrv1.RenewCertificateResponse{Started: a.renewals == 1}), nil
}

func (a *domainAPI) CreateCABundle(_ context.Context, req *connect.Request[rpmgrv1.CreateCABundleRequest]) (*connect.Response[rpmgrv1.CreateCABundleResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bundle = req.Msg
	b := proto.Clone(req.Msg.GetCaBundle()).(*rpmgrv1.CABundle)
	b.Id = "cab_1"
	return connect.NewResponse(&rpmgrv1.CreateCABundleResponse{CaBundle: b}), nil
}

func (a *domainAPI) GetCABundle(context.Context, *connect.Request[rpmgrv1.GetCABundleRequest]) (*connect.Response[rpmgrv1.GetCABundleResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetCABundleResponse{CaBundle: &rpmgrv1.CABundle{Id: "cab_1", Name: "internal", Pem: "old", Etag: "2"}}), nil
}

func (a *domainAPI) UpdateCABundle(_ context.Context, req *connect.Request[rpmgrv1.UpdateCABundleRequest]) (*connect.Response[rpmgrv1.UpdateCABundleResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bundleUp = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateCABundleResponse{CaBundle: req.Msg.GetCaBundle()}), nil
}

// TestDomainsAndCertificates (docs/16-cli.md): a domain claim is made and its proof explained, a
// TXT record or an HTTP token; verify shows the outcome and why it failed; trust takes a step-up;
// a certificate is uploaded from files, with a warning for a key file others may read; a renewal
// says whether it started one; a CA bundle is created and updated from a PEM file.
func TestDomainsAndCertificates(t *testing.T) {
	a := &domainAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewDomainServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewCertificateServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
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

	code, out, errOut := run("create", "domain", "--fqdn", "example.com", "--wildcard")
	if code != cli.ExitOK || !a.domain.GetDomain().GetWildcard() || !strings.Contains(out, `_rpmgr-challenge.example.com  TXT  "v123"`) ||
		!strings.Contains(out, "rpmgr verify domain dom_1") {
		t.Fatalf("a TXT claim: %d %q %q %v", code, out, errOut, a.domain)
	}
	if code, out, _ := run("create", "domain", "--fqdn", "app.example.org", "--method", "http"); code != cli.ExitOK ||
		a.domain.GetDomain().GetMethod() != rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP || !strings.Contains(out, "/.well-known/rpmgr-challenge/dom_1") {
		t.Fatalf("an HTTP claim: %d %q", code, out)
	}
	if code, _, _ := run("create", "domain", "--fqdn", "x.example.com", "--method", "smoke-signal"); code != cli.ExitUsage {
		t.Errorf("an unknown method: %d", code)
	}
	if code, out, _ := run("verify", "domain", "dom_1"); code != cli.ExitOK || !strings.Contains(out, "is PENDING: no TXT record") {
		t.Fatalf("verify: %d %q", code, out)
	}
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { return "right", nil }
	t.Cleanup(func() { stepUpPrompt = old })
	if code, out, _ := run("trust", "domain", "dom_1"); code != cli.ExitOK || !strings.Contains(out, "is VERIFIED") || len(a.stepUps) != 1 {
		t.Fatalf("trust: %d %q", code, out)
	}

	chain := file("chain.pem", "CHAIN", 0o644)
	if code, out, errOut := run("upload", "certificate", "--chain", chain, "--key", file("open.key", "KEY", 0o644)); code != cli.ExitOK ||
		!strings.Contains(errOut, "open to other users (mode 0644)") || a.upload.GetChainPem() != "CHAIN" || a.upload.GetPrivateKeyPem() != "KEY" ||
		!strings.Contains(out, "Uploaded certificate crt_1") {
		t.Fatalf("an upload with an open key file: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := run("upload", "certificate", "--chain", chain, "--key", file("closed.key", "KEY", 0o600)); code != cli.ExitOK || errOut != "" {
		t.Fatalf("an upload with a closed key file: %d %q", code, errOut)
	}
	if code, _, _ := run("upload", "certificate", "--chain", chain); code != cli.ExitUsage {
		t.Errorf("no key: %d", code)
	}
	if code, out, _ := run("renew", "certificate", "crt_1"); code != cli.ExitOK || !strings.Contains(out, "started") {
		t.Fatalf("a renewal: %d %q", code, out)
	}
	if code, out, _ := run("renew", "certificate", "crt_1"); code != cli.ExitOK || !strings.Contains(out, "runs already") {
		t.Fatalf("a renewal running: %d %q", code, out)
	}

	if code, out, _ := run("create", "ca-bundle", "--name", "internal", "--pem-file", file("ca.pem", "PEM1", 0o644)); code != cli.ExitOK ||
		a.bundle.GetCaBundle().GetPem() != "PEM1" || !strings.Contains(out, "Created ca bundle cab_1") {
		t.Fatalf("a bundle: %d %q %v", code, out, a.bundle)
	}
	if code, _, _ := run("update", "ca-bundle", "--pem-file", file("ca2.pem", "PEM2", 0o644), "cab_1"); code != cli.ExitOK ||
		a.bundleUp.GetCaBundle().GetPem() != "PEM2" || a.bundleUp.GetEtag() != "2" || !slices.Equal(a.bundleUp.GetUpdateMask().GetPaths(), []string{"pem"}) {
		t.Fatalf("a bundle update: %d %v", code, a.bundleUp)
	}
	if code, _, _ := run("create", "ca-bundle", "--name", "x", "--pem-file", filepath.Join(dir, "missing.pem")); code != cli.ExitError {
		t.Errorf("a missing PEM file: %d", code)
	}
}
