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

// targetAPI has the route "web", the connector "nas", the CA bundle "internal" and one target, and
// records the target writes.
type targetAPI struct {
	rpmgrv1connect.UnimplementedRouteServiceHandler
	rpmgrv1connect.UnimplementedConnectorServiceHandler
	rpmgrv1connect.UnimplementedCertificateServiceHandler

	mu      sync.Mutex
	target  *rpmgrv1.RouteTarget
	created *rpmgrv1.CreateRouteTargetRequest
	updated *rpmgrv1.UpdateRouteTargetRequest
	deleted *rpmgrv1.DeleteRouteTargetRequest
}

func (a *targetAPI) ListRoutes(context.Context, *connect.Request[rpmgrv1.ListRoutesRequest]) (*connect.Response[rpmgrv1.ListRoutesResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListRoutesResponse{Routes: []*rpmgrv1.Route{{Id: "rt_1", Name: "web"}}}), nil
}

func (a *targetAPI) ListConnectors(context.Context, *connect.Request[rpmgrv1.ListConnectorsRequest]) (*connect.Response[rpmgrv1.ListConnectorsResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListConnectorsResponse{Connectors: []*rpmgrv1.Connector{{Id: "con_1", Name: "nas"}}}), nil
}

func (a *targetAPI) ListCABundles(context.Context, *connect.Request[rpmgrv1.ListCABundlesRequest]) (*connect.Response[rpmgrv1.ListCABundlesResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListCABundlesResponse{CaBundles: []*rpmgrv1.CABundle{{Id: "cab_1", Name: "internal"}}}), nil
}

func (a *targetAPI) CreateRouteTarget(_ context.Context, req *connect.Request[rpmgrv1.CreateRouteTargetRequest]) (
	*connect.Response[rpmgrv1.CreateRouteTargetResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.created = req.Msg
	t := proto.Clone(req.Msg.GetTarget()).(*rpmgrv1.RouteTarget)
	t.Id, t.Etag = "tg_2", "1"
	return connect.NewResponse(&rpmgrv1.CreateRouteTargetResponse{Target: t, Revision: &rpmgrv1.Revision{Seq: 11}}), nil
}

func (a *targetAPI) GetRouteTarget(_ context.Context, req *connect.Request[rpmgrv1.GetRouteTargetRequest]) (
	*connect.Response[rpmgrv1.GetRouteTargetResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if req.Msg.GetRouteTargetId() != a.target.GetId() {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("not found"))
	}
	return connect.NewResponse(&rpmgrv1.GetRouteTargetResponse{Target: a.target, RouteId: "rt_1"}), nil
}

func (a *targetAPI) UpdateRouteTarget(_ context.Context, req *connect.Request[rpmgrv1.UpdateRouteTargetRequest]) (
	*connect.Response[rpmgrv1.UpdateRouteTargetResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updated = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateRouteTargetResponse{Target: req.Msg.GetTarget(), Revision: &rpmgrv1.Revision{Seq: 12}}), nil
}

func (a *targetAPI) DeleteRouteTarget(_ context.Context, req *connect.Request[rpmgrv1.DeleteRouteTargetRequest]) (
	*connect.Response[rpmgrv1.DeleteRouteTargetResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deleted = req.Msg
	return connect.NewResponse(&rpmgrv1.DeleteRouteTargetResponse{Revision: &rpmgrv1.Revision{Seq: 13}}), nil
}

func targetEnv(t *testing.T) (*targetAPI, map[string]string) {
	t.Helper()
	a := &targetAPI{target: &rpmgrv1.RouteTarget{Id: "tg_1", ConnectorId: "con_1", Enabled: true, Weight: 1, Etag: "6",
		UpstreamProtocol: rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTP,
		Address:          &rpmgrv1.RouteTarget_HostPort{HostPort: &rpmgrv1.HostPort{Host: "10.0.0.5", Port: 8080}}}}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewRouteServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewConnectorServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewCertificateServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	return a, map[string]string{"RPMGR_CREDENTIALS": creds}
}

// TestRouteTargets (docs/16-cli.md): create route-target adds a target to a route, naming the
// route, the connector and the CA bundle by name; update changes the fields its flags name under
// the etag read; get and delete take a target's ID; an unknown connector, a bad address, both
// address forms, an unknown upstream and a value the API's rules refuse are refused.
func TestRouteTargets(t *testing.T) {
	a, env := targetEnv(t)
	code, out, errOut := runWith(env, "", "create", "route-target", "--route", "web", "--connector", "nas", "--address", "10.0.0.5:8443",
		"--upstream", "https", "--server-name", "app.internal", "--ca-bundle", "internal", "--weight", "3")
	c := a.created
	if code != cli.ExitOK || !strings.Contains(out, "Added route target tg_2 in revision 11") || c.GetRouteId() != "rt_1" ||
		c.GetTarget().GetConnectorId() != "con_1" || c.GetTarget().GetHostPort().GetPort() != 8443 ||
		c.GetTarget().GetUpstreamProtocol() != rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS || c.GetTarget().GetTls().GetCaBundleId() != "cab_1" ||
		c.GetTarget().GetTls().GetServerName() != "app.internal" || c.GetTarget().GetWeight() != 3 || !c.GetTarget().GetEnabled() {
		t.Fatalf("a target: %d %q %q\n%v", code, out, errOut, c)
	}
	if code, _, _ := runWith(env, "", "create", "route-target", "--route", "rt_1", "--connector", "con_1", "--unix", "/run/app.sock"); code != cli.ExitOK ||
		a.created.GetTarget().GetUnixPath() != "/run/app.sock" || a.created.GetTarget().GetTls() != nil {
		t.Fatalf("a Unix socket: %d %v", code, a.created)
	}
	if code, _, errOut := runWith(env, "", "create", "route-target", "--route", "web", "--connector", "nope", "--address", "10.0.0.5:80"); code != cli.ExitError ||
		!strings.Contains(errOut, `no connector named "nope"`) {
		t.Errorf("an unknown connector: %d %q", code, errOut)
	}
	for name, args := range map[string][]string{
		"no address":          {"--route", "web", "--connector", "nas"},
		"both forms":          {"--route", "web", "--connector", "nas", "--address", "a:1", "--unix", "/s"},
		"no port":             {"--route", "web", "--connector", "nas", "--address", "10.0.0.5"},
		"an unknown upstream": {"--route", "web", "--connector", "nas", "--address", "a:1", "--upstream", "ftp"},
		"a weight too high":   {"--route", "rt_1", "--connector", "con_1", "--address", "a:1", "--weight", "5000"},
	} {
		if code, _, errOut := runWith(env, "", append([]string{"create", "route-target"}, args...)...); code != cli.ExitUsage {
			t.Errorf("%s: exit %d %q", name, code, errOut)
		}
	}

	code, out, errOut = runWith(env, "", "update", "route-target", "--weight", "5", "--priority", "1", "tg_1")
	u := a.updated
	if code != cli.ExitOK || !strings.Contains(out, "Updated route target tg_1 in revision 12") || u.GetEtag() != "6" ||
		!slices.Equal(u.GetUpdateMask().GetPaths(), []string{"weight", "priority"}) || u.GetTarget().GetWeight() != 5 ||
		u.GetTarget().GetHostPort().GetPort() != 8080 || u.GetTarget().GetConnectorId() != "con_1" {
		t.Fatalf("an update: %d %q %q\n%v", code, out, errOut, u)
	}
	if code, _, errOut := runWith(env, "", "update", "route-target", "tg_1"); code != cli.ExitUsage {
		t.Errorf("an update of nothing: %d %q", code, errOut)
	}
	if code, out, _ := runWith(env, "", "get", "route-target", "tg_1"); code != cli.ExitOK || !strings.Contains(out, "con_1") ||
		!strings.Contains(out, "UPSTREAM_PROTOCOL_HTTP") {
		t.Fatalf("get: %d %q", code, out)
	}
	if code, _, errOut := runWith(env, "", "delete", "route-target", "tg_1"); code != cli.ExitOK || a.deleted.GetEtag() != "6" ||
		a.deleted.GetRouteTargetId() != "tg_1" {
		t.Fatalf("delete: %d %q %v", code, errOut, a.deleted)
	}
	if code, _, errOut := runWith(env, "", "list", "route-target"); code != cli.ExitUsage {
		t.Errorf("a list of targets: %d %q", code, errOut)
	}
}
