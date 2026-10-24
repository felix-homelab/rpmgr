// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
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
	preview *rpmgrv1.PreviewRouteRequest
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

func (a *routeAPI) PreviewRoute(_ context.Context, req *connect.Request[rpmgrv1.PreviewRouteRequest]) (*connect.Response[rpmgrv1.PreviewRouteResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.preview = req.Msg
	return connect.NewResponse(&rpmgrv1.PreviewRouteResponse{Route: req.Msg.GetRoute(), GatewayIds: []string{"gw_1", "gw_2"},
		Problems: []*rpmgrv1.ApplyError{{ResourceId: "gw_2", Message: "port 20001 is taken"}}}), nil
}

func (a *routeAPI) ListGatewayGroups(context.Context, *connect.Request[rpmgrv1.ListGatewayGroupsRequest]) (*connect.Response[rpmgrv1.ListGatewayGroupsResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListGatewayGroupsResponse{GatewayGroups: []*rpmgrv1.GatewayGroup{{Id: "gwg_1", Name: "eu"}}}), nil
}

func (a *routeAPI) ListRoutes(context.Context, *connect.Request[rpmgrv1.ListRoutesRequest]) (*connect.Response[rpmgrv1.ListRoutesResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return connect.NewResponse(&rpmgrv1.ListRoutesResponse{Routes: []*rpmgrv1.Route{a.route}}), nil
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
	// With -o json or yaml, standard output is the route alone and the confirmation goes to standard
	// error, so that a script can parse it (yaml is the manifest, which this fake API does not export).
	code, out, errOut = runWith(env, "", "create", "route", "--http", "--name", "web", "--group", "eu", "--hostname", "web.example.com", "-o", "json")
	var created map[string]any
	if code != cli.ExitOK || json.Unmarshal([]byte(out), &created) != nil || created["id"] != "rt_new" ||
		!strings.Contains(errOut, "Created route rt_new in revision 7") {
		t.Fatalf("an http route with -o json: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runWith(env, "", "create", "route", "--tcp", "--name", "pg", "--group", "gwg_1", "--port", "20001", "--idle-timeout", "10m"); code != cli.ExitError ||
		!strings.Contains(errOut, "already exists") || a.created.GetRoute().GetTcp().GetIdleTimeoutSeconds() != 600 {
		t.Fatalf("a taken port: %d %q", code, errOut)
	}
	if code, _, errOut := runWith(env, "", "create", "route", "--tcp-udp", "--name", "dns", "--group", "eu", "--port", "5353",
		"--idle-timeout", "10m", "--flow-idle-timeout", "30s"); code != cli.ExitOK || a.created.GetRoute().GetTcpUdp().GetPort() != 5353 ||
		a.created.GetRoute().GetTcpUdp().GetIdleTimeoutSeconds() != 600 || a.created.GetRoute().GetTcpUdp().GetFlowIdleTimeoutSeconds() != 30 {
		t.Fatalf("a tcp_udp route: %d %q %v", code, errOut, a.created)
	}
	calls := a.calls
	for name, args := range map[string][]string{
		"no type":                {"--name", "x", "--group", "eu"},
		"tcp-udp and udp":        {"--tcp-udp", "--udp", "--name", "x", "--group", "eu"},
		"a flow idle on tcp":     {"--tcp", "--name", "x", "--group", "eu", "--flow-idle-timeout", "30s"},
		"a zero flow idle":       {"--tcp-udp", "--name", "x", "--group", "eu", "--flow-idle-timeout", "0s"},
		"two types":              {"--tcp", "--udp", "--name", "x", "--group", "eu"},
		"a hostname on tcp":      {"--tcp", "--name", "x", "--group", "eu", "--hostname", "a.example.com"},
		"maintenance on tcp":     {"--tcp", "--name", "x", "--group", "eu", "--maintenance"},
		"a header match on tcp":  {"--tcp", "--name", "x", "--group", "eu", "--match-header", "X-Env=a"},
		"a message on udp":       {"--udp", "--name", "x", "--group", "eu", "--maintenance-message", "back soon"},
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
// mask, with the etag it read, or none with --force; enable and disable change only enabled; an
// update that names no field is refused.
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
	if code, _, errOut := runWith(env, "", "disable", "route", "--force", "rt_1"); code != cli.ExitOK || a.updated.GetEtag() != "" ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"enabled"}) || a.updated.GetRoute().GetEnabled() {
		t.Fatalf("disable: %d %q %v", code, errOut, a.updated)
	}
	if code, _, _ := runWith(env, "", "enable", "route", "rt_1"); code != cli.ExitOK || !a.updated.GetRoute().GetEnabled() || a.updated.GetEtag() != "4" {
		t.Fatalf("enable: %d %v", code, a.updated)
	}
	// Maintenance (D88): the switch and its message, each in the mask only when given.
	if code, _, errOut := runWith(env, "", "update", "route", "--maintenance", "--maintenance-message", "Back at 18:00.", "rt_1"); code != cli.ExitOK ||
		!slices.Equal(slices.Sorted(slices.Values(a.updated.GetUpdateMask().GetPaths())), []string{"http.maintenance", "http.maintenance_message"}) ||
		!a.updated.GetRoute().GetHttp().GetMaintenance() || a.updated.GetRoute().GetHttp().GetMaintenanceMessage() != "Back at 18:00." {
		t.Fatalf("into maintenance: %d %q %v", code, errOut, a.updated)
	}
	if code, _, errOut := runWith(env, "", "update", "route", "--maintenance=false", "rt_1"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"http.maintenance"}) || a.updated.GetRoute().GetHttp().GetMaintenance() {
		t.Fatalf("out of maintenance: %d %q %v", code, errOut, a.updated)
	}
	// A message the API's rules refuse is refused before anything is sent.
	calls := a.calls
	for name, msg := range map[string]string{"501 characters": strings.Repeat("a", 501), "a tab": "back\tsoon"} {
		if code, _, errOut := runWith(env, "", "update", "route", "--maintenance-message", msg, "rt_1"); code != cli.ExitUsage {
			t.Errorf("a message with %s: exit %d %q", name, code, errOut)
		}
	}
	if a.calls != calls {
		t.Errorf("refused messages reached the API %d times", a.calls-calls)
	}
	if code, _, errOut := runWith(env, "", "update", "route", "--policy", "office", "rt_1"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetRoute().GetPolicyIds(), []string{"ap_1"}) {
		t.Fatalf("a policy: %d %q", code, errOut)
	}
	a.updated = nil
	if code, _, errOut := runWith(env, "", "update", "route", "rt_1", "--policy", "office"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetRoute().GetPolicyIds(), []string{"ap_1"}) || !slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"policy_ids"}) {
		t.Fatalf("a policy after the ID: %d %q", code, errOut)
	}
	// An empty value of a repeatable flag sets an empty list or map: the policies come off.
	a.route.PolicyIds, a.route.Labels = []string{"ap_1"}, map[string]string{"site": "home"}
	a.route.GetHttp().RequestHeadersSet = map[string]string{"X-Env": "prod"}
	if code, _, errOut := runWith(env, "", "update", "route", "--policy", "", "--label", "", "--set-request-header", "", "rt_1"); code != cli.ExitOK ||
		len(a.updated.GetRoute().GetPolicyIds()) != 0 || len(a.updated.GetRoute().GetLabels()) != 0 ||
		len(a.updated.GetRoute().GetHttp().GetRequestHeadersSet()) != 0 ||
		!slices.Equal(slices.Sorted(slices.Values(a.updated.GetUpdateMask().GetPaths())), []string{"http.request_headers_set", "labels", "policy_ids"}) {
		t.Fatalf("lists emptied: %d %q %v", code, errOut, a.updated)
	}
	// Given with other values, an empty one adds nothing.
	if code, _, errOut := runWith(env, "", "update", "route", "--policy", "", "--policy", "office", "rt_1"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetRoute().GetPolicyIds(), []string{"ap_1"}) {
		t.Fatalf("an empty and a named policy: %d %q %v", code, errOut, a.updated)
	}
	a.route.PolicyIds, a.route.Labels = nil, nil
	a.route.GetHttp().RequestHeadersSet = nil
	// Header matches (D135): Name=value is an exact value, Name alone presence; empty removes them.
	if code, _, errOut := runWith(env, "", "update", "route", "--match-header", "X-Env=beta", "--match-header", "X-Tenant", "rt_1"); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"http.header_matches"}) ||
		len(a.updated.GetRoute().GetHttp().GetHeaderMatches()) != 2 ||
		a.updated.GetRoute().GetHttp().GetHeaderMatches()[0].GetExact() != "beta" || !a.updated.GetRoute().GetHttp().GetHeaderMatches()[1].GetPresent() {
		t.Fatalf("header matches: %d %q %v", code, errOut, a.updated)
	}
	a.route.GetHttp().HeaderMatches = []*rpmgrv1.HeaderMatch{{Name: "X-Env", Match: &rpmgrv1.HeaderMatch_Exact{Exact: "beta"}}}
	if code, _, errOut := runWith(env, "", "update", "route", "--match-header", "", "rt_1"); code != cli.ExitOK ||
		len(a.updated.GetRoute().GetHttp().GetHeaderMatches()) != 0 || !slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"http.header_matches"}) {
		t.Fatalf("header matches removed: %d %q %v", code, errOut, a.updated)
	}
	a.route.GetHttp().HeaderMatches = nil
	calls = a.calls
	nine := []string{"update", "route"}
	for i := range 9 {
		nine = append(nine, "--match-header", "X-"+strings.Repeat("a", i+1))
	}
	for name, args := range map[string][]string{
		"nine matches":         append(nine, "rt_1"),
		"an empty exact value": {"update", "route", "--match-header", "X-Env=", "rt_1"},
		"a bad header name":    {"update", "route", "--match-header", "X Env=a", "rt_1"},
	} {
		if code, _, errOut := runWith(env, "", args...); code != cli.ExitUsage {
			t.Errorf("%s: exit %d %q", name, code, errOut)
		}
	}
	if a.calls != calls {
		t.Errorf("refused header matches reached the API %d times", a.calls-calls)
	}
	// A route is named by its ID or its name.
	if code, _, errOut := runWith(env, "", "update", "route", "--port80", "redirect", "web"); code != cli.ExitOK ||
		a.updated.GetRoute().GetId() != "rt_1" || a.updated.GetRoute().GetHttp().GetPort80() != rpmgrv1.Port80Mode_PORT80_MODE_REDIRECT {
		t.Fatalf("an update by name: %d %q %v", code, errOut, a.updated)
	}
	if code, out, errOut := runWith(env, "", "get", "route", "web"); code != cli.ExitOK || !strings.Contains(out, "rt_1") {
		t.Fatalf("get by name: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runWith(env, "", "disable", "route", "nope"); code != cli.ExitError || !strings.Contains(errOut, `no route named "nope"`) {
		t.Fatalf("an unknown name: %d %q", code, errOut)
	}
	for name, args := range map[string][]string{
		"no field":          {"rt_1"},
		"only --force":      {"--force", "rt_1"},
		"--force alone":     {"--force", "--wait", "1s", "rt_1"},
		"a port on http":    {"--port", "443", "rt_1"},
		"a label not k=v":   {"--label", "site", "rt_1"},
		"no ID":             {"--name", "x"},
		"an unknown policy": {"--policy", "nope", "rt_1"},
		"a flag after --":   {"rt_1", "--", "--policy", "office"},
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

// TestPreviewRoute (docs/16-cli.md): preview route sends a new route, or with --route the change
// an update would make with its mask and etag, and shows the gateways, connectors and problems the
// API finds; nothing is written.
func TestPreviewRoute(t *testing.T) {
	a, env := routeEnv(t)
	code, out, errOut := runWith(env, "", "preview", "route", "--tcp", "--name", "pg", "--group", "eu", "--port", "20001")
	if code != cli.ExitOK || a.preview.GetRoute().GetTcp().GetPort() != 20001 || a.preview.GetRoute().GetGatewayGroupId() != "gwg_1" ||
		a.preview.GetUpdateMask() != nil || !strings.Contains(out, "gw_1, gw_2") || !strings.Contains(out, "Connectors it would reach: none") ||
		!strings.Contains(out, "Problem: gw_2: port 20001 is taken") || a.calls != 0 {
		t.Fatalf("a new route: %d %q %q %v", code, out, errOut, a.preview)
	}
	if code, out, errOut := runWith(env, "", "preview", "route", "--route", "rt_1", "--hostname", "web.example.com", "-o", "yaml"); code != cli.ExitOK ||
		a.preview.GetEtag() != "4" || !slices.Equal(a.preview.GetUpdateMask().GetPaths(), []string{"http.hostnames"}) ||
		a.preview.GetRoute().GetId() != "rt_1" || !strings.Contains(out, "web.example.com") || a.calls != 0 {
		t.Fatalf("a change: %d %q %q %v", code, out, errOut, a.preview)
	}
	code, out, errOut = runWith(env, "", "preview", "route", "--tcp", "--name", "pg", "--group", "eu", "--port", "20001", "-o", "json")
	if code != cli.ExitOK || !json.Valid([]byte(out)) || !strings.Contains(errOut, "Problem: gw_2: port 20001 is taken") {
		t.Fatalf("a new route with -o json: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runWith(env, "", "preview", "route", "--route", "rt_1"); code != cli.ExitUsage {
		t.Errorf("a change of nothing: %d %q", code, errOut)
	}
}
