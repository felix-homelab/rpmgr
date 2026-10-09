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
// and records the writes; the gateway token needs a step-up.
type gatewayAPI struct {
	rpmgrv1connect.UnimplementedGatewayServiceHandler
	stepUpAPI

	mu           sync.Mutex
	group        *rpmgrv1.CreateGatewayGroupRequest
	groupUpdate  *rpmgrv1.UpdateGatewayGroupRequest
	gateway      *rpmgrv1.CreateGatewayRequest
	gwUpdate     *rpmgrv1.UpdateGatewayRequest
	decommission *rpmgrv1.DecommissionGatewayRequest
	pool         *rpmgrv1.CreatePortPoolRequest
	quota        *rpmgrv1.SetPortQuotaRequest
	quotaDeleted string
	gwToken      *rpmgrv1.CreateGatewayEnrollmentTokenRequest
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

func (a *gatewayAPI) DecommissionGateway(_ context.Context, req *connect.Request[rpmgrv1.DecommissionGatewayRequest]) (
	*connect.Response[rpmgrv1.DecommissionGatewayResponse], error) {
	a.record(func() { a.decommission = req.Msg })
	return connect.NewResponse(&rpmgrv1.DecommissionGatewayResponse{Revision: &rpmgrv1.Revision{Seq: 34}}), nil
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

func (a *gatewayAPI) SetPortQuota(_ context.Context, req *connect.Request[rpmgrv1.SetPortQuotaRequest]) (*connect.Response[rpmgrv1.SetPortQuotaResponse], error) {
	a.record(func() { a.quota = req.Msg })
	return connect.NewResponse(&rpmgrv1.SetPortQuotaResponse{PortQuota: &rpmgrv1.PortQuota{Id: "pq_1", MaxPorts: req.Msg.GetMaxPorts(), AllocatedPorts: 2}}), nil
}

func (a *gatewayAPI) DeletePortQuota(_ context.Context, req *connect.Request[rpmgrv1.DeletePortQuotaRequest]) (*connect.Response[rpmgrv1.DeletePortQuotaResponse], error) {
	a.record(func() { a.quotaDeleted = req.Msg.GetPortQuotaId() })
	return connect.NewResponse(&rpmgrv1.DeletePortQuotaResponse{}), nil
}

func (a *gatewayAPI) CreateGatewayEnrollmentToken(_ context.Context, req *connect.Request[rpmgrv1.CreateGatewayEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.CreateGatewayEnrollmentTokenResponse], error) {
	a.stepUpAPI.mu.Lock()
	stepped := a.stepped
	a.stepUpAPI.mu.Unlock()
	if !stepped {
		return nil, stepUpError()
	}
	a.record(func() { a.gwToken = req.Msg })
	return connect.NewResponse(&rpmgrv1.CreateGatewayEnrollmentTokenResponse{Token: "rpmgr_enr_gateway", //nolint:gosec // G101: a test token
		EnrollmentToken: &rpmgrv1.EnrollmentToken{Id: "enr_9"}}), nil
}

// TestInfrastructure (docs/16-cli.md): gateway groups, gateways and port pools are created from
// flags and updated in the fields their flags name, groups by name; the API's refusal of a fifth
// gateway and of an overlapping pool is shown; drain, enable and decommission act on a gateway under
// its etag; quotas are set, listed and deleted; a gateway's token needs a step-up and is shown once.
func TestInfrastructure(t *testing.T) {
	a := &gatewayAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewEnrollmentServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
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
		"an unknown protocol":        {"create", "port-pool", "--group", "eu", "--protocol", "sctp", "--from", "1", "--to", "2"},
		"a port that is not one":     {"create", "port-pool", "--group", "eu", "--protocol", "tcp", "--from", "x", "--to", "2"},
		"a group change":             {"update", "gateway", "--group", "us", "gw_1"},
		"an update of nothing":       {"update", "gateway-group", "gwg_1"},
		"a quota without a protocol": {"set", "port-quota", "--group", "eu", "--max", "3"},
	} {
		if code, _, errOut := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}

	if code, out, _ := run("drain", "gateway", "gw_1"); code != cli.ExitOK || a.gwUpdate.GetGateway().GetEnabled() || a.gwUpdate.GetEtag() != "5" ||
		!slices.Equal(a.gwUpdate.GetUpdateMask().GetPaths(), []string{"enabled"}) || !strings.Contains(out, "Drained gateway gw_1") {
		t.Fatalf("drain: %d %q %v", code, out, a.gwUpdate)
	}
	if code, _, _ := run("enable", "gateway", "gw_1"); code != cli.ExitOK || !a.gwUpdate.GetGateway().GetEnabled() {
		t.Fatalf("enable: %d %v", code, a.gwUpdate)
	}
	if code, _, _ := run("decommission", "gateway", "gw_1"); code != cli.ExitOK || a.decommission.GetEtag() != "5" {
		t.Fatalf("decommission: %d %v", code, a.decommission)
	}
	if code, out, _ := run("set", "port-quota", "--group", "eu", "--protocol", "udp", "--max", "5"); code != cli.ExitOK ||
		a.quota.GetProtocol() != rpmgrv1.PortProtocol_PORT_PROTOCOL_UDP || a.quota.GetMaxPorts() != 5 || !strings.Contains(out, "at most 5 udp ports, 2 held") {
		t.Fatalf("a quota: %d %q %v", code, out, a.quota)
	}
	if code, _, errOut := run("delete", "port-quota", "pq_1"); code != cli.ExitOK || a.quotaDeleted != "pq_1" {
		t.Fatalf("a quota deleted: %d %q", code, errOut)
	}

	answer := "right"
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { return answer, nil }
	t.Cleanup(func() { stepUpPrompt = old })
	code, out, errOut = run("create", "gateway-token", "--gateway", "gw1", "--ttl", "30m")
	if code != cli.ExitOK || strings.Count(out, "rpmgr_enr_gateway") != 1 || a.gwToken.GetGatewayId() != "gw_1" || a.gwToken.GetTtl().AsDuration().Minutes() != 30 {
		t.Fatalf("a gateway token: %d %q %q %v", code, out, errOut, a.gwToken)
	}
}
