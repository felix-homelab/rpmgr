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
	"time"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// stepUpAPI mints enrollment tokens only after the token stepped up with the password "right".
type stepUpAPI struct {
	rpmgrv1connect.UnimplementedEnrollmentServiceHandler
	rpmgrv1connect.UnimplementedAuthServiceHandler
	rpmgrv1connect.UnimplementedConnectorServiceHandler

	mu       sync.Mutex
	stepped  bool
	stepUps  []*rpmgrv1.StepUpRequest
	minted   *rpmgrv1.CreateEnrollmentTokenRequest
	attempts int
}

func (a *stepUpAPI) CreateEnrollmentToken(_ context.Context, req *connect.Request[rpmgrv1.CreateEnrollmentTokenRequest]) (
	*connect.Response[rpmgrv1.CreateEnrollmentTokenResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attempts++
	if !a.stepped {
		return nil, stepUpError()
	}
	a.minted = req.Msg
	return connect.NewResponse(&rpmgrv1.CreateEnrollmentTokenResponse{Token: "rpmgr_enr_secret", //nolint:gosec // G101: a test token
		EnrollmentToken: &rpmgrv1.EnrollmentToken{Id: "enr_1", ExpireTime: timestamppb.New(time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC))}}), nil
}

// stepUpError is the API's answer to a change that needs a step-up.
func stepUpError() error {
	err := connect.NewError(connect.CodeUnauthenticated, errors.New("api: step-up required"))
	if d, derr := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: "STEP_UP_REQUIRED", Domain: "rpmgr.dev"}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

func (a *stepUpAPI) StepUp(_ context.Context, req *connect.Request[rpmgrv1.StepUpRequest]) (*connect.Response[rpmgrv1.StepUpResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stepUps = append(a.stepUps, req.Msg)
	if req.Msg.GetPassword() != "right" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("apisvc: the step-up failed"))
	}
	a.stepped = true
	return connect.NewResponse(&rpmgrv1.StepUpResponse{}), nil
}

func (a *stepUpAPI) ListConnectors(context.Context, *connect.Request[rpmgrv1.ListConnectorsRequest]) (*connect.Response[rpmgrv1.ListConnectorsResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListConnectorsResponse{Connectors: []*rpmgrv1.Connector{{Id: "con_1", Name: "nas"}}}), nil
}

// TestCreateEnrollmentToken (D63; docs/16-cli.md): create enrollment-token asks for a step-up
// when the API wants one, steps the token up and mints, printing the token once; a wrong factor
// mints nothing; a token already stepped up asks nothing; values the API's rules refuse are usage
// errors.
func TestCreateEnrollmentToken(t *testing.T) {
	a := &stepUpAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewEnrollmentServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewConnectorServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	prompts := 0
	answer := "wrong"
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { prompts++; return answer, nil }
	t.Cleanup(func() { stepUpPrompt = old })

	code, out, errOut := runWith(env, "", "create", "enrollment-token", "--connector", "nas")
	if code != cli.ExitError || prompts != 1 || strings.Contains(out, "rpmgr_enr_") || !strings.Contains(errOut, "step-up failed") {
		t.Fatalf("a wrong factor: %d %q %q, %d prompts", code, out, errOut, prompts)
	}
	answer = "right"
	code, out, errOut = runWith(env, "", "create", "enrollment-token", "--connector", "nas", "--ttl", "2h")
	if code != cli.ExitOK || prompts != 2 || strings.Count(out, "rpmgr_enr_secret") != 1 || !strings.Contains(out, "enr_1") ||
		a.minted.GetConnectorId() != "con_1" || a.minted.GetTtl().AsDuration() != 2*time.Hour || a.minted.MaxUses != nil {
		t.Fatalf("a step-up, then the token: %d %q %q, %d prompts, %v", code, out, errOut, prompts, a.minted)
	}
	last := a.stepUps[len(a.stepUps)-1]
	if last.GetPassword() != "right" || last.GetSecondFactor() != "right" {
		t.Errorf("the step-up sent %v", last)
	}
	if code, _, _ := runWith(env, "", "create", "enrollment-token", "--ephemeral", "--max-uses", "0", "--label", "site=lab"); code != cli.ExitOK ||
		prompts != 2 || a.minted.GetMaxUses() != 0 || a.minted.MaxUses == nil || a.minted.GetLabels()["site"] != "lab" {
		t.Fatalf("a token stepped up already: %d, %d prompts, %v", code, prompts, a.minted)
	}
	attempts := a.attempts
	for name, args := range map[string][]string{"a ttl above 30 days": {"--ttl", "800h"}, "too many uses": {"--max-uses", "200000"},
		"an argument": {"x"}} {
		if code, _, errOut := runWith(env, "", append([]string{"create", "enrollment-token"}, args...)...); code != cli.ExitUsage {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
	if a.attempts != attempts {
		t.Errorf("refused command lines reached the API %d times", a.attempts-attempts)
	}
}
