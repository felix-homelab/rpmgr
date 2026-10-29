// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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

// drainAPI serves the two calls that end a drain, and records them.
type drainAPI struct {
	rpmgrv1connect.UnimplementedGatewayServiceHandler
	rpmgrv1connect.UnimplementedConnectorServiceHandler

	mu         sync.Mutex
	gateways   []string
	connectors []string
	none       bool // there is no old process
}

func (a *drainAPI) EndGatewayDrain(_ context.Context, req *connect.Request[rpmgrv1.EndGatewayDrainRequest]) (*connect.Response[rpmgrv1.EndGatewayDrainResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.none {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no old process drains"))
	}
	a.gateways = append(a.gateways, req.Msg.GetGatewayId())
	return connect.NewResponse(&rpmgrv1.EndGatewayDrainResponse{Ended: &rpmgrv1.DrainingProcess{Connections: 12, Flows: 3, Sessions: 2}}), nil
}

func (a *drainAPI) EndConnectorDrain(_ context.Context, req *connect.Request[rpmgrv1.EndConnectorDrainRequest]) (*connect.Response[rpmgrv1.EndConnectorDrainResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connectors = append(a.connectors, req.Msg.GetConnectorId())
	return connect.NewResponse(&rpmgrv1.EndConnectorDrainResponse{Ended: &rpmgrv1.DrainingProcess{Connections: 40}}), nil
}

// TestUpdate_EndDrain (D160): `update gateway --end-drain` and `update connector --end-drain` end
// the drain of the agent's old process and say what it cuts; the API's refusal is shown; another
// flag with it, or none or several names, is a usage error and calls nothing; without the flag the
// command still changes a field.
func TestUpdate_EndDrain(t *testing.T) {
	a := &drainAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewConnectorServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }

	code, out, errOut := run("update", "gateway", "--end-drain", "gw_1")
	if code != cli.ExitOK || !strings.Contains(out, "Ended the drain of the old process of gateway gw_1; it closes its 12 connections, 3 UDP flows and 2 sessions.") ||
		len(a.gateways) != 1 || a.gateways[0] != "gw_1" {
		t.Fatalf("a gateway: %d %q %q %v", code, out, errOut, a.gateways)
	}
	code, out, errOut = run("update", "connector", "--end-drain", "con_1")
	if code != cli.ExitOK || !strings.Contains(out, "old process of connector con_1; it closes its 40 connections") || len(a.connectors) != 1 {
		t.Fatalf("a connector: %d %q %q %v", code, out, errOut, a.connectors)
	}

	a.none = true
	if code, _, errOut := run("update", "gateway", "--end-drain", "gw_1"); code == cli.ExitOK || !strings.Contains(errOut, "no old process drains") {
		t.Fatalf("no old process: %d %q", code, errOut)
	}
	a.none = false
	for _, args := range [][]string{
		{"update", "gateway", "--end-drain", "--name", "x", "gw_1"}, // another flag
		{"update", "connector", "--end-drain", "--label", "a=b", "con_1"},
		{"update", "gateway", "--end-drain"}, // no name
		{"update", "connector", "--end-drain", "con_1", "con_2"},
	} {
		if code, _, errOut := run(args...); code != cli.ExitUsage || errOut == "" {
			t.Fatalf("%v: %d %q", args, code, errOut)
		}
	}
	if len(a.gateways) != 1 || len(a.connectors) != 1 {
		t.Fatalf("a refused command called the API: %v %v", a.gateways, a.connectors)
	}
	// Without the flag the command is the update it was: here the gateway service has no
	// UpdateGateway, which the API says.
	if code, _, _ := run("update", "gateway", "--name", "x", "gw_1"); code == cli.ExitOK {
		t.Fatal("an update without the flag ended a drain")
	}
	if len(a.gateways) != 1 {
		t.Fatal("an update without the flag ended a drain")
	}
}
