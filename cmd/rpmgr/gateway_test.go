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

// gatewayAPI has the group "eu" with four gateways, the gateway "gw1" and a TCP pool 20000–20099,
// and records the writes.
type gatewayAPI struct {
	rpmgrv1connect.UnimplementedGatewayServiceHandler

	mu          sync.Mutex
	group       *rpmgrv1.CreateGatewayGroupRequest
	groupUpdate *rpmgrv1.UpdateGatewayGroupRequest
	gateway     *rpmgrv1.CreateGatewayRequest
	gwUpdate    *rpmgrv1.UpdateGatewayRequest
	pool        *rpmgrv1.CreatePortPoolRequest
}

var (
	euGroup = &rpmgrv1.GatewayGroup{Id: "gwg_1", Name: "eu", Region: "fra", Etag: "3"}
	gw1     = &rpmgrv1.Gateway{Id: "gw_1", GatewayGroupId: "gwg_1", Name: "gw1", TunnelEndpoints: []string{"gw1.example.com:443"}, Enabled: true, Etag: "5"}
)

func (a *gatewayAPI) record(f func()) { a.mu.Lock(); defer a.mu.Unlock(); f() }

func (a *gatewayAPI) ListGatewayGroups(context.Context, *connect.Request[rpmgrv1.ListGatewayGroupsRequest]) (*connect.Response[rpmgrv1.ListGatewayGroupsResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListGatewayGroupsResponse{GatewayGroups: []*rpmgrv1.GatewayGroup{euGroup}}), nil
}

func (a *gatewayAPI) ListGateways(context.Context, *connect.Request[rpmgrv1.ListGatewaysRequest]) (*connect.Response[rpmgrv1.ListGatewaysResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListGatewaysResponse{Gateways: []*rpmgrv1.Gateway{gw1}}), nil
}

func (a *gatewayAPI) CreateGatewayGroup(_ context.Context, req *connect.Request[rpmgrv1.CreateGatewayGroupRequest]) (*connect.Response[rpmgrv1.CreateGatewayGroupResponse], error) {
	a.record(func() { a.group = req.Msg })
	g := proto.Clone(req.Msg.GetGatewayGroup()).(*rpmgrv1.GatewayGroup)
	g.Id = "gwg_2"
	return connect.NewResponse(&rpmgrv1.CreateGatewayGroupResponse{GatewayGroup: g, Revision: &rpmgrv1.Revision{Seq: 30}}), nil
}

func (a *gatewayAPI) GetGatewayGroup(context.Context, *connect.Request[rpmgrv1.GetGatewayGroupRequest]) (*connect.Response[rpmgrv1.GetGatewayGroupResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetGatewayGroupResponse{GatewayGroup: euGroup}), nil
}

func (a *gatewayAPI) UpdateGatewayGroup(_ context.Context, req *connect.Request[rpmgrv1.UpdateGatewayGroupRequest]) (*connect.Response[rpmgrv1.UpdateGatewayGroupResponse], error) {
	a.record(func() { a.groupUpdate = req.Msg })
	return connect.NewResponse(&rpmgrv1.UpdateGatewayGroupResponse{GatewayGroup: req.Msg.GetGatewayGroup(), Revision: &rpmgrv1.Revision{Seq: 31}}), nil
}

func (a *gatewayAPI) CreateGateway(_ context.Context, req *connect.Request[rpmgrv1.CreateGatewayRequest]) (*connect.Response[rpmgrv1.CreateGatewayResponse], error) {
	a.record(func() { a.gateway = req.Msg })
	if req.Msg.GetGateway().GetName() == "gw5" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the group has 4 gateways already"))
	}
	g := proto.Clone(req.Msg.GetGateway()).(*rpmgrv1.Gateway)
	g.Id = "gw_2"
	return connect.NewResponse(&rpmgrv1.CreateGatewayResponse{Gateway: g, Revision: &rpmgrv1.Revision{Seq: 32}}), nil
}

func (a *gatewayAPI) GetGateway(context.Context, *connect.Request[rpmgrv1.GetGatewayRequest]) (*connect.Response[rpmgrv1.GetGatewayResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetGatewayResponse{Gateway: proto.Clone(gw1).(*rpmgrv1.Gateway)}), nil
}

func (a *gatewayAPI) UpdateGateway(_ context.Context, req *connect.Request[rpmgrv1.UpdateGatewayRequest]) (*connect.Response[rpmgrv1.UpdateGatewayResponse], error) {
	a.record(func() { a.gwUpdate = req.Msg })
	return connect.NewResponse(&rpmgrv1.UpdateGatewayResponse{Gateway: req.Msg.GetGateway(), Revision: &rpmgrv1.Revision{Seq: 33}}), nil
}

func (a *gatewayAPI) CreatePortPool(_ context.Context, req *connect.Request[rpmgrv1.CreatePortPoolRequest]) (*connect.Response[rpmgrv1.CreatePortPoolResponse], error) {
	a.record(func() { a.pool = req.Msg })
	if req.Msg.GetPortPool().GetPortFrom() <= 20099 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the ports overlap the pool pp_1"))
	}
	p := proto.Clone(req.Msg.GetPortPool()).(*rpmgrv1.PortPool)
	p.Id = "pp_2"
	return connect.NewResponse(&rpmgrv1.CreatePortPoolResponse{PortPool: p, Revision: &rpmgrv1.Revision{Seq: 35}}), nil
}

// TestInfrastructure (docs/16-cli.md): gateway groups, gateways and port pools are created from
// flags and updated in the fields their flags name, groups by name; the API's refusal of a fifth
// gateway and of an overlapping pool is shown; flags the API's rules or the field's type refuse are
// usage errors.
func TestInfrastructure(t *testing.T) {
	a := &gatewayAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }

	code, out, errOut := run("create", "gateway-group", "--name", "us", "--region", "iad", "--public-hostname", "us.example.com")
	if code != cli.ExitOK || !strings.Contains(out, "Created gateway group gwg_2 in revision 30") || a.group.GetOrgId() != "org_1" ||
		a.group.GetGatewayGroup().GetRegion() != "iad" || !slices.Equal(a.group.GetGatewayGroup().GetPublicHostnames(), []string{"us.example.com"}) {
		t.Fatalf("a group: %d %q %q %v", code, out, errOut, a.group)
	}
	code, _, errOut = run("update", "gateway-group", "--trusted-proxy", "10.0.0.0/8", "--trusted-proxy", "192.168.0.0/16", "gwg_1")
	if u := a.groupUpdate; code != cli.ExitOK || u.GetEtag() != "3" || !slices.Equal(u.GetUpdateMask().GetPaths(), []string{"trusted_proxy_cidrs"}) ||
		len(u.GetGatewayGroup().GetTrustedProxyCidrs()) != 2 || u.GetGatewayGroup().GetName() != "eu" {
		t.Fatalf("a group update: %d %q %v", code, errOut, u)
	}
	code, out, _ = run("create", "gateway", "--group", "eu", "--name", "gw2", "--tunnel-endpoint", "gw2.example.com:443")
	if code != cli.ExitOK || a.gateway.GetGateway().GetGatewayGroupId() != "gwg_1" || !strings.Contains(out, "Created gateway gw_2") {
		t.Fatalf("a gateway: %d %q %v", code, out, a.gateway)
	}
	if code, _, errOut := run("create", "gateway", "--group", "eu", "--name", "gw5", "--tunnel-endpoint", "gw5.example.com:443"); code != cli.ExitError ||
		!strings.Contains(errOut, "4 gateways") {
		t.Errorf("a fifth gateway: %d %q", code, errOut)
	}
	if code, out, errOut := run("create", "port-pool", "--group", "eu", "--protocol", "tcp", "--from", "20100", "--to", "20199"); code != cli.ExitOK ||
		a.pool.GetPortPool().GetProtocol() != rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP || a.pool.GetPortPool().GetPortTo() != 20199 {
		t.Fatalf("a pool: %d %q %q %v", code, out, errOut, a.pool)
	}
	if code, _, errOut := run("create", "port-pool", "--group", "eu", "--protocol", "tcp", "--from", "20050", "--to", "20150"); code != cli.ExitError ||
		!strings.Contains(errOut, "overlap") {
		t.Errorf("an overlapping pool: %d %q", code, errOut)
	}
	for name, args := range map[string][]string{
		"an unknown protocol":    {"create", "port-pool", "--group", "eu", "--protocol", "sctp", "--from", "1", "--to", "2"},
		"a port that is not one": {"create", "port-pool", "--group", "eu", "--protocol", "tcp", "--from", "x", "--to", "2"},
		"a group change":         {"update", "gateway", "--group", "us", "gw_1"},
		"an update of nothing":   {"update", "gateway-group", "gwg_1"},
	} {
		if code, _, errOut := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
}
