// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// fakeAPI serves routes, a certificate and their manifests, as the controller would, and records
// what the commands send.
type fakeAPI struct {
	rpmgrv1connect.UnimplementedRouteServiceHandler
	rpmgrv1connect.UnimplementedCertificateServiceHandler
	rpmgrv1connect.UnimplementedManifestServiceHandler

	mu        sync.Mutex
	routes    map[string]*rpmgrv1.Route
	changeOn  bool // a read is followed by someone else's change
	gets      int
	exportReq *rpmgrv1.ExportManifestsRequest
}

func (f *fakeAPI) authorized(h http.Header) error {
	if h.Get("Authorization") != "Bearer rpmgr_pat_good" {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	return nil
}

func (f *fakeAPI) GetRoute(_ context.Context, req *connect.Request[rpmgrv1.GetRouteRequest]) (*connect.Response[rpmgrv1.GetRouteResponse], error) {
	if err := f.authorized(req.Header()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	r, ok := f.routes[req.Msg.GetRouteId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("not found"))
	}
	out := &rpmgrv1.GetRouteResponse{Route: r}
	if f.changeOn {
		f.routes[r.GetId()] = &rpmgrv1.Route{Id: r.GetId(), Name: r.GetName(), Description: "changed meanwhile", Etag: "9"}
	}
	return connect.NewResponse(out), nil
}

func (f *fakeAPI) GetCertificate(context.Context, *connect.Request[rpmgrv1.GetCertificateRequest]) (*connect.Response[rpmgrv1.GetCertificateResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetCertificateResponse{Certificate: &rpmgrv1.Certificate{Id: "crt_1",
		Source: rpmgrv1.CertificateSource_CERTIFICATE_SOURCE_UPLOADED, Sans: []string{"a.example.com", "b.example.com"}}}), nil
}

func (f *fakeAPI) ExportManifests(_ context.Context, req *connect.Request[rpmgrv1.ExportManifestsRequest]) (*connect.Response[rpmgrv1.ExportManifestsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exportReq = req.Msg
	return connect.NewResponse(&rpmgrv1.ExportManifestsResponse{Yaml: "kind: Route\nmetadata:\n  name: web\n", Count: 1}), nil
}

// apiEnv logs in to a fake API and returns the environment for the commands.
func apiEnv(t *testing.T, token string) (*fakeAPI, map[string]string) {
	t.Helper()
	f := &fakeAPI{routes: map[string]*rpmgrv1.Route{
		"rt_1": {Id: "rt_1", Name: "web", GatewayGroupId: "gwg_1", Enabled: true, Etag: "3",
			Status: &rpmgrv1.RouteStatus{State: rpmgrv1.RouteState_ROUTE_STATE_READY}},
		"rt_2": {Id: "rt_2", Name: "db", GatewayGroupId: "gwg_1", Etag: "1"},
	}}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewRouteServiceHandler(f))
	mux.Handle(rpmgrv1connect.NewCertificateServiceHandler(f))
	mux.Handle(rpmgrv1connect.NewManifestServiceHandler(f))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	ca := writeCA(t, srv)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte(token)), CAFile: ca}); err != nil {
		t.Fatal(err)
	}
	return f, map[string]string{"RPMGR_CREDENTIALS": creds}
}

// TestGet (docs/16-cli.md): get shows a resource as a table, as JSON, or as the manifest the
// controller exports, or for a kind without manifests as YAML; an unknown kind or output, a wrong
// number of arguments, missing credentials, a revoked token and an unknown resource are refused.
func TestGet(t *testing.T) {
	f, env := apiEnv(t, "rpmgr_pat_good")
	code, out, errOut := runWith(env, "", "get", "route", "rt_1")
	if code != cli.ExitOK || !strings.Contains(out, "ID") || !strings.Contains(out, "rt_1") || !strings.Contains(out, "web") ||
		!strings.Contains(out, "ROUTE_STATE_READY") {
		t.Fatalf("get as a table: %d %q %q", code, out, errOut)
	}
	code, out, _ = runWith(env, "", "get", "-o", "json", "route", "rt_1")
	var got map[string]any
	if code != cli.ExitOK || json.Unmarshal([]byte(out), &got) != nil || got["id"] != "rt_1" || got["etag"] != "3" {
		t.Fatalf("get as JSON: %d %q", code, out)
	}
	if code, out, _ := runWith(env, "", "get", "-o", "yaml", "route", "rt_1"); code != cli.ExitOK || !strings.HasPrefix(out, "kind: Route") ||
		f.exportReq.GetOrgId() != "org_1" || len(f.exportReq.GetResourceIds()) != 1 || f.exportReq.GetResourceIds()[0] != "rt_1" {
		t.Fatalf("get as YAML: %d %q %v", code, out, f.exportReq)
	}
	if code, out, _ := runWith(env, "", "get", "-o", "yaml", "certificate", "crt_1"); code != cli.ExitOK || !strings.Contains(out, "id: crt_1") ||
		!strings.Contains(out, "- a.example.com") {
		t.Fatalf("a certificate as YAML: %d %q", code, out)
	}
	if code, out, _ := runWith(env, "", "get", "certificate", "crt_1"); code != cli.ExitOK || !strings.Contains(out, "a.example.com,b.example.com") {
		t.Fatalf("a certificate as a table: %d %q", code, out)
	}

	for name, args := range map[string][]string{
		"an unknown kind":   {"get", "secret", "x"},
		"no ID":             {"get", "route"},
		"an extra argument": {"get", "route", "rt_1", "rt_2"},
		"an unknown output": {"get", "-o", "xml", "route", "rt_1"},
	} {
		if code, _, errOut := runWith(env, "", args...); code != cli.ExitUsage {
			t.Errorf("%s: exit %d %q", name, code, errOut)
		}
	}
	if code, _, errOut := runWith(map[string]string{"RPMGR_CREDENTIALS": filepath.Join(t.TempDir(), "none.yaml")}, "", "get", "route", "rt_1"); code != cli.ExitError ||
		!strings.Contains(errOut, "rpmgr login") {
		t.Errorf("without credentials: %d %q", code, errOut)
	}
	_, revoked := apiEnv(t, "rpmgr_pat_revoked")
	if code, _, errOut := runWith(revoked, "", "get", "route", "rt_1"); code != cli.ExitError || !strings.Contains(errOut, "log in again") {
		t.Errorf("a revoked token: %d %q", code, errOut)
	}
	if code, _, errOut := runWith(env, "", "get", "route", "rt_9"); code != cli.ExitError || !strings.Contains(errOut, "not found") {
		t.Errorf("an unknown route: %d %q", code, errOut)
	}
}
