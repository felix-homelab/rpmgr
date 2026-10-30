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

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// webhookAPI serves the org's and the instance's endpoints and records what the commands send.
type webhookAPI struct {
	rpmgrv1connect.UnimplementedWebhookServiceHandler
	rpmgrv1connect.UnimplementedInstanceWebhookServiceHandler

	mu       sync.Mutex
	calls    []string
	created  *rpmgrv1.CreateWebhookRequest
	icreated *rpmgrv1.CreateInstanceWebhookRequest
	updated  *rpmgrv1.UpdateWebhookRequest
	iupdated *rpmgrv1.UpdateInstanceWebhookRequest
	deleted  *rpmgrv1.DeleteWebhookRequest
	tested   bool
	answer   *rpmgrv1.TestWebhookResponse
}

const (
	secretOne = "TESTSECRET-one"
	secretTwo = "TESTSECRET-two"
)

var hook1 = &rpmgrv1.Webhook{Id: "whk_1", OrgId: "org_1", Url: "https://hooks.example.com/a", EventTypes: []string{"route.*"}, Enabled: true,
	SecretSet: true, Etag: "e1"}

func (a *webhookAPI) note(s string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, s)
}

func (a *webhookAPI) CreateWebhook(_ context.Context, r *connect.Request[rpmgrv1.CreateWebhookRequest]) (*connect.Response[rpmgrv1.CreateWebhookResponse], error) {
	a.note("CreateWebhook")
	a.created = r.Msg
	if strings.HasPrefix(r.Msg.GetWebhook().GetUrl(), "http://") {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("webhook: the URL must be https"))
	}
	return connect.NewResponse(&rpmgrv1.CreateWebhookResponse{Webhook: hook1, Secret: secretOne}), nil
}

func (a *webhookAPI) CreateInstanceWebhook(_ context.Context, r *connect.Request[rpmgrv1.CreateInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.CreateInstanceWebhookResponse], error) {
	a.note("CreateInstanceWebhook")
	a.icreated = r.Msg
	return connect.NewResponse(&rpmgrv1.CreateInstanceWebhookResponse{Webhook: &rpmgrv1.Webhook{Id: "whk_i1"}, Secret: secretOne}), nil
}

func (a *webhookAPI) GetWebhook(_ context.Context, r *connect.Request[rpmgrv1.GetWebhookRequest]) (*connect.Response[rpmgrv1.GetWebhookResponse], error) {
	a.note("GetWebhook")
	if r.Msg.GetWebhookId() != "whk_1" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("webhook: no such endpoint"))
	}
	return connect.NewResponse(&rpmgrv1.GetWebhookResponse{Webhook: hook1}), nil
}

func (a *webhookAPI) GetInstanceWebhook(_ context.Context, r *connect.Request[rpmgrv1.GetInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.GetInstanceWebhookResponse], error) {
	a.note("GetInstanceWebhook")
	return connect.NewResponse(&rpmgrv1.GetInstanceWebhookResponse{Webhook: &rpmgrv1.Webhook{Id: r.Msg.GetWebhookId(), Etag: "i1"}}), nil
}

func (a *webhookAPI) ListWebhooks(context.Context, *connect.Request[rpmgrv1.ListWebhooksRequest]) (*connect.Response[rpmgrv1.ListWebhooksResponse], error) {
	a.note("ListWebhooks")
	return connect.NewResponse(&rpmgrv1.ListWebhooksResponse{Webhooks: []*rpmgrv1.Webhook{hook1}}), nil
}

func (a *webhookAPI) ListInstanceWebhooks(context.Context, *connect.Request[rpmgrv1.ListInstanceWebhooksRequest]) (
	*connect.Response[rpmgrv1.ListInstanceWebhooksResponse], error) {
	a.note("ListInstanceWebhooks")
	return connect.NewResponse(&rpmgrv1.ListInstanceWebhooksResponse{Webhooks: []*rpmgrv1.Webhook{{Id: "whk_i1", Url: "https://ops.example.com/i"}}}), nil
}

func (a *webhookAPI) UpdateWebhook(_ context.Context, r *connect.Request[rpmgrv1.UpdateWebhookRequest]) (*connect.Response[rpmgrv1.UpdateWebhookResponse], error) {
	a.note("UpdateWebhook")
	a.updated = r.Msg
	return connect.NewResponse(&rpmgrv1.UpdateWebhookResponse{Webhook: hook1}), nil
}

func (a *webhookAPI) UpdateInstanceWebhook(_ context.Context, r *connect.Request[rpmgrv1.UpdateInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.UpdateInstanceWebhookResponse], error) {
	a.note("UpdateInstanceWebhook")
	a.iupdated = r.Msg
	return connect.NewResponse(&rpmgrv1.UpdateInstanceWebhookResponse{Webhook: r.Msg.GetWebhook()}), nil
}

func (a *webhookAPI) DeleteWebhook(_ context.Context, r *connect.Request[rpmgrv1.DeleteWebhookRequest]) (*connect.Response[rpmgrv1.DeleteWebhookResponse], error) {
	a.note("DeleteWebhook")
	a.deleted = r.Msg
	return connect.NewResponse(&rpmgrv1.DeleteWebhookResponse{}), nil
}

func (a *webhookAPI) DeleteInstanceWebhook(context.Context, *connect.Request[rpmgrv1.DeleteInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.DeleteInstanceWebhookResponse], error) {
	a.note("DeleteInstanceWebhook")
	return connect.NewResponse(&rpmgrv1.DeleteInstanceWebhookResponse{}), nil
}

func (a *webhookAPI) RotateWebhookSecret(context.Context, *connect.Request[rpmgrv1.RotateWebhookSecretRequest]) (
	*connect.Response[rpmgrv1.RotateWebhookSecretResponse], error) {
	a.note("RotateWebhookSecret")
	return connect.NewResponse(&rpmgrv1.RotateWebhookSecretResponse{Webhook: hook1, Secret: secretTwo}), nil
}

func (a *webhookAPI) ListWebhookDeliveries(context.Context, *connect.Request[rpmgrv1.ListWebhookDeliveriesRequest]) (
	*connect.Response[rpmgrv1.ListWebhookDeliveriesResponse], error) {
	a.note("ListWebhookDeliveries")
	return connect.NewResponse(&rpmgrv1.ListWebhookDeliveriesResponse{Deliveries: []*rpmgrv1.WebhookDelivery{
		{Id: "whd_1", WebhookId: "whk_1", EventType: "route.create", Attempt: 2, StatusCode: 503, Error: "receiver answered 503"}}}), nil
}

func (a *webhookAPI) ListInstanceWebhookDeliveries(context.Context, *connect.Request[rpmgrv1.ListInstanceWebhookDeliveriesRequest]) (
	*connect.Response[rpmgrv1.ListInstanceWebhookDeliveriesResponse], error) {
	a.note("ListInstanceWebhookDeliveries")
	return connect.NewResponse(&rpmgrv1.ListInstanceWebhookDeliveriesResponse{}), nil
}

func (a *webhookAPI) TestWebhook(context.Context, *connect.Request[rpmgrv1.TestWebhookRequest]) (*connect.Response[rpmgrv1.TestWebhookResponse], error) {
	a.note("TestWebhook")
	a.tested = true
	return connect.NewResponse(a.answer), nil
}

func webhookEnv(t *testing.T) (*webhookAPI, map[string]string) {
	t.Helper()
	a := &webhookAPI{answer: &rpmgrv1.TestWebhookResponse{Delivered: true, StatusCode: 204}}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewWebhookServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewInstanceWebhookServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	return a, map[string]string{"RPMGR_CREDENTIALS": creds}
}

// TestWebhookSecretShownOnce (docs/16-cli.md, "Webhooks"): the signing secret is printed by create
// webhook and by update webhook --rotate-secret and by nothing else, and no command takes one as
// an argument; a refused endpoint prints none.
func TestWebhookSecretShownOnce(t *testing.T) {
	a, env := webhookEnv(t)
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }

	code, out, errOut := run("create", "webhook", "--url", "https://hooks.example.com/a", "--event", "route.*", "--event", "audit.*")
	c := a.created
	if code != cli.ExitOK || strings.Count(out, secretOne) != 1 || !strings.Contains(out, "Created webhook whk_1.") || !strings.Contains(out, "shown once") ||
		c.GetOrgId() != "org_1" || c.GetWebhook().GetUrl() != "https://hooks.example.com/a" || !c.GetWebhook().GetEnabled() ||
		!slices.Equal(c.GetWebhook().GetEventTypes(), []string{"route.*", "audit.*"}) || c.GetRequestId() == "" || strings.Contains(errOut, secretOne) {
		t.Fatalf("create: %d %q %q %v", code, out, errOut, c)
	}
	if code, out, _ := run("create", "webhook", "--url", "https://hooks.example.com/a", "--disabled"); code != cli.ExitOK || a.created.GetWebhook().GetEnabled() ||
		!strings.Contains(out, secretOne) {
		t.Fatalf("a disabled endpoint: %d %q", code, out)
	}

	for _, args := range [][]string{{"get", "webhook", "whk_1"}, {"get", "-o", "json", "webhook", "whk_1"}, {"list", "webhook"}, {"list", "-o", "yaml", "webhook"},
		{"update", "webhook", "--url", "https://hooks.example.com/b", "whk_1"}, {"enable", "webhook", "whk_1"}} {
		if code, out, errOut := run(args...); code != cli.ExitOK || strings.Contains(out+errOut, "TESTSECRET") {
			t.Errorf("%v: %d %q %q", args, code, out, errOut)
		}
	}
	if code, out, _ := run("update", "webhook", "--rotate-secret", "whk_1"); code != cli.ExitOK || strings.Count(out, secretTwo) != 1 || strings.Contains(out, "Updated") {
		t.Fatalf("rotate: %d %q", code, out)
	}

	before := len(a.calls)
	code, out, errOut = run("create", "webhook", "--url", "http://hooks.example.com/a")
	if code != cli.ExitError || strings.Contains(out+errOut, "TESTSECRET") || !strings.Contains(errOut, "must be https") || len(a.calls) != before+1 {
		t.Fatalf("a refused endpoint: %d %q %q", code, out, errOut)
	}
	if code, _, _ := run("create", "webhook", "--secret", "x", "--url", "https://hooks.example.com/a"); code != cli.ExitUsage {
		t.Errorf("a secret as a flag: %d", code)
	}
}

// TestWebhookUpdateAndSwitch: update changes the fields its flags name under the etag read, or
// none with --force; it needs a change; enable and disable change only the enabled field.
func TestWebhookUpdateAndSwitch(t *testing.T) {
	a, env := webhookEnv(t)
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }
	code, out, errOut := run("update", "webhook", "--url", "https://hooks.example.com/b", "--event", "route.*", "whk_1")
	u := a.updated
	if code != cli.ExitOK || !strings.Contains(out, "Updated webhook whk_1.") || u.GetEtag() != "e1" || u.GetWebhook().GetId() != "whk_1" ||
		!slices.Equal(u.GetUpdateMask().GetPaths(), []string{"url", "event_types"}) || !slices.Equal(u.GetWebhook().GetEventTypes(), []string{"route.*"}) {
		t.Fatalf("update: %d %q %q %v", code, out, errOut, u)
	}
	if code, _, _ := run("update", "webhook", "--all-events", "--force", "whk_1"); code != cli.ExitOK || a.updated.GetEtag() != "" ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"event_types"}) || len(a.updated.GetWebhook().GetEventTypes()) != 0 {
		t.Fatalf("all events: %v", a.updated)
	}
	if code, out, _ := run("disable", "webhook", "whk_1"); code != cli.ExitOK || !strings.Contains(out, "Disabled webhook whk_1.") ||
		a.updated.GetWebhook().GetEnabled() || !slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"enabled"}) {
		t.Fatalf("disable: %q %v", out, a.updated)
	}
	if code, out, _ := run("enable", "webhook", "whk_1"); code != cli.ExitOK || !strings.Contains(out, "Enabled webhook whk_1.") || !a.updated.GetWebhook().GetEnabled() {
		t.Fatalf("enable: %q %v", out, a.updated)
	}
	for name, args := range map[string][]string{"no change": {"whk_1"}, "no ID": {"--url", "https://x.example.com"}, "both event flags": {"--event", "a.*", "--all-events", "whk_1"},
		"two IDs": {"--all-events", "whk_1", "whk_2"}} {
		if code, _, errOut := run(append([]string{"update", "webhook"}, args...)...); code != cli.ExitUsage {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
	calls := len(a.calls)
	if code, _, errOut := run("update", "webhook", "--url", "https://x.example.com", "whk_nope"); code != cli.ExitError || !strings.Contains(errOut, "no such endpoint") || len(a.calls) != calls+1 {
		t.Errorf("an unknown endpoint: %d %q", code, errOut)
	}
}

// TestWebhookTestListDelete: test webhook says what the receiver answered and fails with the
// reason when it did not; list and delete name the endpoint by its ID, delete under the etag read;
// deliveries are listed with their endpoint.
func TestWebhookTestListDelete(t *testing.T) {
	a, env := webhookEnv(t)
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }
	if code, out, _ := run("test", "webhook", "whk_1"); code != cli.ExitOK || !strings.Contains(out, "The receiver answered 204.") {
		t.Fatalf("test: %d %q", code, out)
	}
	a.answer = &rpmgrv1.TestWebhookResponse{Delivered: false, Error: "refused: private range 10.0.0.0/8"}
	if code, _, errOut := run("test", "webhook", "whk_1"); code != cli.ExitError || !strings.Contains(errOut, "not delivered: refused: private range 10.0.0.0/8") {
		t.Fatalf("a refused test: %d %q", code, errOut)
	}
	a.answer = &rpmgrv1.TestWebhookResponse{Delivered: false, StatusCode: 503}
	if code, _, errOut := run("test", "webhook", "whk_1"); code != cli.ExitError || !strings.Contains(errOut, "HTTP 503") {
		t.Fatalf("a failed test: %d %q", code, errOut)
	}
	code, out, _ := run("list", "webhook")
	if code != cli.ExitOK || !strings.Contains(out, "whk_1") || !strings.Contains(out, "https://hooks.example.com/a") || !strings.Contains(out, "route.*") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, out, _ := run("list", "webhook-delivery", "whk_1"); code != cli.ExitOK || !strings.Contains(out, "whd_1") || !strings.Contains(out, "route.create") ||
		!strings.Contains(out, "receiver answered 503") {
		t.Fatalf("deliveries: %d %q", code, out)
	}
	if code, out, _ := run("delete", "webhook", "whk_1"); code != cli.ExitOK || a.deleted.GetEtag() != "e1" || !strings.Contains(out, "Deleted webhook whk_1") {
		t.Fatalf("delete: %d %q %v", code, out, a.deleted)
	}
	if code, _, _ := run("delete", "webhook", "--force", "whk_1"); code != cli.ExitOK || a.deleted.GetEtag() != "" {
		t.Fatalf("a forced delete: %v", a.deleted)
	}
	if code, _, errOut := run("delete", "webhook", "whk_nope"); code != cli.ExitError || !strings.Contains(errOut, "no such endpoint") {
		t.Fatalf("an unknown endpoint: %d %q", code, errOut)
	}
}

// TestWebhookInstance: --instance moves every command to the Instance Admin's endpoints, and only
// webhooks have such.
func TestWebhookInstance(t *testing.T) {
	a, env := webhookEnv(t)
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }
	if code, out, _ := run("create", "webhook", "--instance", "--url", "https://ops.example.com/i"); code != cli.ExitOK || a.icreated.GetWebhook().GetUrl() != "https://ops.example.com/i" ||
		strings.Count(out, secretOne) != 1 || a.created != nil {
		t.Fatalf("create: %q %v", out, a.icreated)
	}
	if code, out, _ := run("list", "webhook", "--instance"); code != cli.ExitOK || !strings.Contains(out, "whk_i1") || !strings.Contains(out, "https://ops.example.com/i") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, _, _ := run("list", "webhook-delivery", "--instance", "whk_i1"); code != cli.ExitOK || a.calls[len(a.calls)-1] != "ListInstanceWebhookDeliveries" {
		t.Fatalf("deliveries: %v", a.calls)
	}
	if code, out, _ := run("get", "webhook", "--instance", "whk_i1"); code != cli.ExitOK || !strings.Contains(out, "whk_i1") {
		t.Fatalf("get: %d %q", code, out)
	}
	if code, _, _ := run("update", "webhook", "--instance", "--url", "https://ops.example.com/j", "whk_i1"); code != cli.ExitOK || a.iupdated.GetEtag() != "i1" || a.updated != nil {
		t.Fatalf("update: %v", a.iupdated)
	}
	if code, _, _ := run("disable", "webhook", "--instance", "whk_i1"); code != cli.ExitOK || a.iupdated.GetWebhook().GetEnabled() {
		t.Fatalf("disable: %v", a.iupdated)
	}
	if code, _, _ := run("delete", "webhook", "--instance", "whk_i1"); code != cli.ExitOK || a.calls[len(a.calls)-1] != "DeleteInstanceWebhook" {
		t.Fatalf("delete: %v", a.calls)
	}
	for _, args := range [][]string{{"list", "route", "--instance"}, {"get", "route", "--instance", "rt_1"}, {"delete", "route", "--instance", "rt_1"}} {
		if code, _, errOut := run(args...); code != cli.ExitUsage || !strings.Contains(errOut, "--instance applies to webhook") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}
