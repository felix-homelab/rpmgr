// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

// routeAPI records the route writes the commands send; it has one gateway group, "eu", and one
// access policy, "office".
type routeAPI struct {
	rpmgrv1connect.UnimplementedRouteServiceHandler
	rpmgrv1connect.UnimplementedGatewayServiceHandler
	rpmgrv1connect.UnimplementedPolicyServiceHandler

	mu      sync.Mutex
	created *rpmgrv1.CreateRouteRequest
	updated *rpmgrv1.UpdateRouteRequest
	route   *rpmgrv1.Route
	calls   int
}

func (a *routeAPI) CreateRoute(_ context.Context, req *connect.Request[rpmgrv1.CreateRouteRequest]) (*connect.Response[rpmgrv1.CreateRouteResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	a.created = req.Msg
	if req.Msg.GetRoute().GetTcp().GetPort() == 20001 {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("routes: the port is taken"))
	}
	r := proto.Clone(req.Msg.GetRoute()).(*rpmgrv1.Route)
	r.Id, r.Etag = "rt_new", "1"
	return connect.NewResponse(&rpmgrv1.CreateRouteResponse{Route: r, Revision: &rpmgrv1.Revision{Seq: 7}}), nil
}

func (a *routeAPI) GetRoute(context.Context, *connect.Request[rpmgrv1.GetRouteRequest]) (*connect.Response[rpmgrv1.GetRouteResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return connect.NewResponse(&rpmgrv1.GetRouteResponse{Route: a.route}), nil
}

func (a *routeAPI) UpdateRoute(_ context.Context, req *connect.Request[rpmgrv1.UpdateRouteRequest]) (*connect.Response[rpmgrv1.UpdateRouteResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	a.updated = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateRouteResponse{Route: a.route, Revision: &rpmgrv1.Revision{Seq: 8}}), nil
}

func (a *routeAPI) ListGatewayGroups(context.Context, *connect.Request[rpmgrv1.ListGatewayGroupsRequest]) (*connect.Response[rpmgrv1.ListGatewayGroupsResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListGatewayGroupsResponse{GatewayGroups: []*rpmgrv1.GatewayGroup{{Id: "gwg_1", Name: "eu"}}}), nil
}

func (a *routeAPI) ListAccessPolicies(context.Context, *connect.Request[rpmgrv1.ListAccessPoliciesRequest]) (*connect.Response[rpmgrv1.ListAccessPoliciesResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListAccessPoliciesResponse{AccessPolicies: []*rpmgrv1.AccessPolicy{{Id: "ap_1", Name: "office"}}}), nil
}

func routeEnv(t *testing.T) (*routeAPI, map[string]string) {
	t.Helper()
	a := &routeAPI{route: &rpmgrv1.Route{Id: "rt_1", Name: "web", Etag: "4", Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: []string{"web.example.com"}}}}}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewRouteServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewPolicyServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	return a, map[string]string{"RPMGR_CREDENTIALS": creds}
}

// TestCreateRoute (docs/16-cli.md): create route builds the route its flags describe, naming its
// group and policies by name, and checks it with the API's own rules before sending it; a flag of
// another route type, two types, an invalid name and a taken port are refused.
func TestCreateRoute(t *testing.T) {
	a, env := routeEnv(t)
	code, out, errOut := runWith(env, "", "create", "route", "--http", "--name", "web", "--group", "eu", "--hostname", "web.example.com",
		"--hostname", "www.example.com", "--policy", "office", "--tls-mode", "acme", "--set-request-header", "X-Env=prod", "--label", "site=home",
		"--hsts", "8760h", "--transport", "quic")
	r := a.created.GetRoute()
	if code != cli.ExitOK || !strings.Contains(out, "Created route rt_new in revision 7") || a.created.GetOrgId() != "org_1" ||
		r.GetGatewayGroupId() != "gwg_1" || !slices.Equal(r.GetPolicyIds(), []string{"ap_1"}) || len(r.GetHttp().GetHostnames()) != 2 ||
		r.GetHttp().GetTlsMode() != rpmgrv1.TLSMode_TLS_MODE_ACME || r.GetHttp().GetRequestHeadersSet()["X-Env"] != "prod" ||
		r.GetHttp().GetHstsMaxAgeSeconds() != 31536000 || r.GetLabels()["site"] != "home" || !r.GetEnabled() ||
		r.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC {
		t.Fatalf("an http route: %d %q %q\n%v", code, out, errOut, a.created)
	}
	if code, _, errOut := runWith(env, "", "create", "route", "--tcp", "--name", "pg", "--group", "gwg_1", "--port", "20001", "--idle-timeout", "10m"); code != cli.ExitError ||
		!strings.Contains(errOut, "already exists") || a.created.GetRoute().GetTcp().GetIdleTimeoutSeconds() != 600 {
		t.Fatalf("a taken port: %d %q", code, errOut)
	}
	calls := a.calls
	for name, args := range map[string][]string{
		"no type":                {"--name", "x", "--group", "eu"},
		"two types":              {"--tcp", "--udp", "--name", "x", "--group", "eu"},
		"a hostname on tcp":      {"--tcp", "--name", "x", "--group", "eu", "--hostname", "a.example.com"},
		"a port on http":         {"--http", "--name", "x", "--group", "eu", "--hostname", "a.example.com", "--port", "80"},
		"a name the API refuses": {"--http", "--name", "Not_A_Name", "--group", "eu", "--hostname", "a.example.com"},
		"a port above 65535":     {"--udp", "--name", "x", "--group", "eu", "--port", "70000"},
		"an unknown transport":   {"--tcp", "--name", "x", "--group", "eu", "--transport", "carrier-pigeon"},
		"an unknown TLS mode":    {"--http", "--name", "x", "--group", "eu", "--hostname", "a.example.com", "--tls-mode", "self"},
	} {
		if code, _, errOut := runWith(env, "", append([]string{"create", "route"}, args...)...); code != cli.ExitUsage {
			t.Errorf("%s: exit %d %q", name, code, errOut)
		}
	}
	if a.calls != calls {
		t.Errorf("refused command lines reached the API %d times", a.calls-calls)
	}
	if code, _, errOut := runWith(env, "", "create", "route", "--tcp", "--name", "x", "--group", "us"); code != cli.ExitError || !strings.Contains(errOut, `no gateway-group named "us"`) {
		t.Errorf("an unknown group: %d %q", code, errOut)
	}
}

// TestUpdateRoute (docs/16-cli.md): update route sends only the fields its flags name, in the
// mask, with the etag it read, or none with --force; an update that names no field is refused.
func TestUpdateRoute(t *testing.T) {
	a, env := routeEnv(t)
	code, out, errOut := runWith(env, "", "update", "route", "--hostname", "web.example.com", "--hostname", "new.example.com", "--port80", "off", "rt_1")
	u := a.updated
	if code != cli.ExitOK || !strings.Contains(out, "Updated route rt_1 in revision 8") || u.GetEtag() != "4" ||
		!slices.Equal(u.GetUpdateMask().GetPaths(), []string{"http.hostnames", "http.port80"}) && !slices.Equal(u.GetUpdateMask().GetPaths(), []string{"http.port80", "http.hostnames"}) ||
		u.GetRoute().GetHttp().GetPort80() != rpmgrv1.Port80Mode_PORT80_MODE_OFF || u.GetRoute().GetId() != "rt_1" {
		t.Fatalf("an update: %d %q %q\n%v", code, out, errOut, u)
	}
	// One field of the spec: the others go along as they are, so the route passes the API's checks.
	if code, _, errOut := runWith(env, "", "update", "route", "--port80", "serve", "rt_1"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"http.port80"}) ||
		!slices.Equal(a.updated.GetRoute().GetHttp().GetHostnames(), []string{"web.example.com"}) {
		t.Fatalf("one field of the spec: %d %q %v", code, errOut, a.updated)
	}
	if code, _, errOut := runWith(env, "", "update", "route", "--policy", "office", "rt_1"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetRoute().GetPolicyIds(), []string{"ap_1"}) {
		t.Fatalf("a policy: %d %q", code, errOut)
	}
	for name, args := range map[string][]string{
		"no field":          {"rt_1"},
		"only --force":      {"--force", "rt_1"},
		"--force alone":     {"--force", "--wait", "1s", "rt_1"},
		"a port on http":    {"--port", "443", "rt_1"},
		"no ID":             {"--name", "x"},
		"an unknown policy": {"--policy", "nope", "rt_1"},
	} {
		want := cli.ExitUsage
		if name == "an unknown policy" {
			want = cli.ExitError
		}
		if code, _, errOut := runWith(env, "", append([]string{"update", "route"}, args...)...); code != want {
			t.Errorf("%s: exit %d %q", name, code, errOut)
		}
	}
}
