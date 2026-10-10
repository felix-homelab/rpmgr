// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
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

// connectorAPI has the connector con_1 and records what the commands send.
type connectorAPI struct {
	rpmgrv1connect.UnimplementedConnectorServiceHandler
	rpmgrv1connect.UnimplementedEnrollmentServiceHandler

	mu            sync.Mutex
	gets          int
	updated       *rpmgrv1.UpdateConnectorRequest
	decommission  *rpmgrv1.DecommissionConnectorRequest
	listConnector *rpmgrv1.ListConnectorsRequest
	listTokens    *rpmgrv1.ListEnrollmentTokensRequest
	revoked       string
	install       *rpmgrv1.GetInstallCommandRequest
}

var con1 = &rpmgrv1.Connector{Id: "con_1", Name: "nas", Labels: map[string]string{"site": "office"}, Enabled: true, Etag: "2"}

func (a *connectorAPI) GetConnector(context.Context, *connect.Request[rpmgrv1.GetConnectorRequest]) (*connect.Response[rpmgrv1.GetConnectorResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gets++
	return connect.NewResponse(&rpmgrv1.GetConnectorResponse{Connector: con1}), nil
}

func (a *connectorAPI) UpdateConnector(_ context.Context, req *connect.Request[rpmgrv1.UpdateConnectorRequest]) (*connect.Response[rpmgrv1.UpdateConnectorResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updated = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateConnectorResponse{Connector: req.Msg.GetConnector(), Revision: &rpmgrv1.Revision{Seq: 21}}), nil
}

func (a *connectorAPI) DecommissionConnector(_ context.Context, req *connect.Request[rpmgrv1.DecommissionConnectorRequest]) (
	*connect.Response[rpmgrv1.DecommissionConnectorResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decommission = req.Msg
	return connect.NewResponse(&rpmgrv1.DecommissionConnectorResponse{Connector: con1, Revision: &rpmgrv1.Revision{Seq: 22}}), nil
}

func (a *connectorAPI) ListConnectors(_ context.Context, req *connect.Request[rpmgrv1.ListConnectorsRequest]) (*connect.Response[rpmgrv1.ListConnectorsResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.listConnector = req.Msg
	return connect.NewResponse(&rpmgrv1.ListConnectorsResponse{Connectors: []*rpmgrv1.Connector{con1}}), nil
}

func (a *connectorAPI) ListEnrollmentTokens(_ context.Context, req *connect.Request[rpmgrv1.ListEnrollmentTokensRequest]) (
	*connect.Response[rpmgrv1.ListEnrollmentTokensResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.listTokens = req.Msg
	return connect.NewResponse(&rpmgrv1.ListEnrollmentTokensResponse{EnrollmentTokens: []*rpmgrv1.EnrollmentToken{{Id: "enr_1",
		Role: rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR, MaxUses: 1}}}), nil
}

func (a *connectorAPI) RevokeEnrollmentToken(_ context.Context, req *connect.Request[rpmgrv1.RevokeEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.RevokeEnrollmentTokenResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked = req.Msg.GetEnrollmentTokenId()
	return connect.NewResponse(&rpmgrv1.RevokeEnrollmentTokenResponse{}), nil
}

func (a *connectorAPI) GetInstallCommand(_ context.Context, req *connect.Request[rpmgrv1.GetInstallCommandRequest]) (
	*connect.Response[rpmgrv1.GetInstallCommandResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.install = req.Msg
	return connect.NewResponse(&rpmgrv1.GetInstallCommandResponse{Command: "curl -fsSL https://panel.example.com/install.sh | sh -s -- --role " +
		strings.ToLower(strings.TrimPrefix(req.Msg.GetRole().String(), "AGENT_ROLE_"))}), nil
}

func connectorEnv(t *testing.T) (*connectorAPI, map[string]string) {
	t.Helper()
	a := &connectorAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewConnectorServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewEnrollmentServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	return a, map[string]string{"RPMGR_CREDENTIALS": creds}
}

// TestConnectors (docs/16-cli.md): update connector changes the fields its flags name under the
// etag read; decommission connector sends the etag read, or none with --force; list --all asks for
// the decommissioned connectors and the inactive enrollment tokens; enrollment tokens are listed
// and revoked, not shown alone; get install-command asks for the role and targets given.
func TestConnectors(t *testing.T) {
	a, env := connectorEnv(t)
	code, out, errOut := runWith(env, "", "update", "connector", "--name", "nas2", "--label", "site=home", "--transport", "h2", "con_1")
	u := a.updated
	if code != cli.ExitOK || !strings.Contains(out, "Updated connector con_1 in revision 21") || u.GetEtag() != "2" ||
		!slices.Equal(u.GetUpdateMask().GetPaths(), []string{"name", "labels", "transport"}) || u.GetConnector().GetName() != "nas2" ||
		u.GetConnector().GetLabels()["site"] != "home" || u.GetConnector().GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_H2 {
		t.Fatalf("an update: %d %q %q %v", code, out, errOut, u)
	}
	for name, args := range map[string][]string{"no field": {"con_1"}, "an unknown transport": {"--transport", "x", "con_1"}, "no ID": {"--name", "x"},
		"a name the API refuses": {"--name", "Not A Name", "con_1"}} {
		if code, _, errOut := runWith(env, "", append([]string{"update", "connector"}, args...)...); code != cli.ExitUsage {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
	code, out, _ = runWith(env, "", "decommission", "connector", "con_1")
	if code != cli.ExitOK || a.decommission.GetEtag() != "2" || !strings.Contains(out, "Decommissioned connector con_1 in revision 22") {
		t.Fatalf("decommission: %d %q %v", code, out, a.decommission)
	}
	gets := a.gets
	if code, _, _ := runWith(env, "", "decommission", "connector", "--force", "con_1"); code != cli.ExitOK || a.decommission.GetEtag() != "" || a.gets != gets {
		t.Fatalf("a forced decommission: %d %v", code, a.decommission)
	}

	if code, _, _ := runWith(env, "", "list", "--all", "connector"); code != cli.ExitOK || !a.listConnector.GetShowDecommissioned() {
		t.Fatalf("all connectors: %d %v", code, a.listConnector)
	}
	if code, out, _ := runWith(env, "", "list", "enrollment-token"); code != cli.ExitOK || a.listTokens.GetShowInactive() || !strings.Contains(out, "enr_1") {
		t.Fatalf("the active tokens: %d %q %v", code, out, a.listTokens)
	}
	if code, _, _ := runWith(env, "", "list", "--all", "enrollment-token"); code != cli.ExitOK || !a.listTokens.GetShowInactive() {
		t.Fatalf("all tokens: %d %v", code, a.listTokens)
	}
	if code, _, _ := runWith(env, "", "get", "enrollment-token", "enr_1"); code != cli.ExitUsage {
		t.Errorf("a token shown alone: %d", code)
	}
	if code, out, _ := runWith(env, "", "revoke", "enrollment-token", "enr_1"); code != cli.ExitOK || a.revoked != "enr_1" || !strings.Contains(out, "Revoked") {
		t.Fatalf("revoke: %d %q", code, out)
	}

	code, out, _ = runWith(env, "", "get", "--allow-target", "10.0.0.5:80", "--allow-target", "/run/app.sock", "install-command")
	if code != cli.ExitOK || a.install.GetRole() != rpmgrv1.AgentRole_AGENT_ROLE_CONNECTOR || len(a.install.GetAllowTargets()) != 2 ||
		!strings.Contains(out, "--role connector") || a.install.GetOrgId() != "org_1" {
		t.Fatalf("a connector's install command: %d %q %v", code, out, a.install)
	}
	if code, out, _ := runWith(env, "", "get", "--role", "gateway", "install-command"); code != cli.ExitOK || !strings.Contains(out, "--role gateway") {
		t.Fatalf("a gateway's install command: %d %q", code, out)
	}
	if code, _, _ := runWith(env, "", "get", "--role", "robot", "install-command"); code != cli.ExitUsage {
		t.Errorf("an unknown role: %d", code)
	}
}
