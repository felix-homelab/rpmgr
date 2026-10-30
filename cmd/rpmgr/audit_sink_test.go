// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// sinkAPI is AuditSinkService with one sink; every change needs a step-up.
type sinkAPI struct {
	rpmgrv1connect.UnimplementedAuditSinkServiceHandler
	stepUpAPI

	mu      sync.Mutex
	created *rpmgrv1.CreateAuditSinkRequest
	updated *rpmgrv1.UpdateAuditSinkRequest
	deleted *rpmgrv1.DeleteAuditSinkRequest
	tests   []string
	refuse  string // the receiver's refusal of a test, if any
}

func (a *sinkAPI) needStepUp() error {
	a.stepUpAPI.mu.Lock()
	defer a.stepUpAPI.mu.Unlock()
	if !a.stepped {
		return stepUpError()
	}
	return nil
}

func theSink() *rpmgrv1.AuditSink {
	return &rpmgrv1.AuditSink{Id: "ask_1", Name: "siem", Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK, Url: "https://siem.example.com/hook",
		SecretSet: true, Enabled: true, Etag: "7", Status: &rpmgrv1.AuditSinkStatus{Backlog: 12, LastError: "the receiver answered 502",
			OldestUnshippedTime: timestamppb.New(timestamppb.Now().AsTime().Add(-3600e9))}}
}

func (a *sinkAPI) CreateAuditSink(_ context.Context, req *connect.Request[rpmgrv1.CreateAuditSinkRequest]) (*connect.Response[rpmgrv1.CreateAuditSinkResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.created = req.Msg
	s := proto.Clone(req.Msg.GetAuditSink()).(*rpmgrv1.AuditSink)
	s.Id, s.Secret, s.SecretSet, s.Enabled = "ask_1", "", true, true
	return connect.NewResponse(&rpmgrv1.CreateAuditSinkResponse{AuditSink: s}), nil
}

func (a *sinkAPI) GetAuditSink(context.Context, *connect.Request[rpmgrv1.GetAuditSinkRequest]) (*connect.Response[rpmgrv1.GetAuditSinkResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetAuditSinkResponse{AuditSink: theSink()}), nil
}

func (a *sinkAPI) ListAuditSinks(context.Context, *connect.Request[rpmgrv1.ListAuditSinksRequest]) (*connect.Response[rpmgrv1.ListAuditSinksResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListAuditSinksResponse{AuditSinks: []*rpmgrv1.AuditSink{theSink()}}), nil
}

func (a *sinkAPI) UpdateAuditSink(_ context.Context, req *connect.Request[rpmgrv1.UpdateAuditSinkRequest]) (*connect.Response[rpmgrv1.UpdateAuditSinkResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updated = req.Msg
	return connect.NewResponse(&rpmgrv1.UpdateAuditSinkResponse{AuditSink: req.Msg.GetAuditSink()}), nil
}

func (a *sinkAPI) DeleteAuditSink(_ context.Context, req *connect.Request[rpmgrv1.DeleteAuditSinkRequest]) (*connect.Response[rpmgrv1.DeleteAuditSinkResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deleted = req.Msg
	return connect.NewResponse(&rpmgrv1.DeleteAuditSinkResponse{}), nil
}

func (a *sinkAPI) TestAuditSink(_ context.Context, req *connect.Request[rpmgrv1.TestAuditSinkRequest]) (*connect.Response[rpmgrv1.TestAuditSinkResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tests = append(a.tests, req.Msg.GetAuditSinkId())
	return connect.NewResponse(&rpmgrv1.TestAuditSinkResponse{Ok: a.refuse == "", Error: a.refuse}), nil
}

// TestAuditSinkCommands (docs/16-cli.md): create, get, list, update, delete and test an audit sink;
// the secret comes from a file and loses its line break; every change takes a step-up; an update
// names the fields it changes and sends the etag it read; refused input sends nothing.
func TestAuditSinkCommands(t *testing.T) {
	a := &sinkAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewAuditSinkServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		return runWith(map[string]string{"RPMGR_CREDENTIALS": creds}, "", args...)
	}
	keyFile := filepath.Join(dir, "sink.key")
	if err := os.WriteFile(keyFile, []byte("signing-secret-of-the-sink\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { return "right", nil }
	t.Cleanup(func() { stepUpPrompt = old })

	// Refused input sends nothing.
	for name, args := range map[string][]string{
		"an unknown kind":    {"create", "audit-sink", "--name", "siem", "--kind", "carrier-pigeon", "--url", "https://x.example.com", "--secret-file", keyFile},
		"a missing file":     {"create", "audit-sink", "--name", "siem", "--kind", "webhook", "--url", "https://x.example.com", "--secret-file", filepath.Join(dir, "missing")},
		"an argument":        {"create", "audit-sink", "siem"},
		"enabled on create":  {"create", "audit-sink", "--name", "siem", "--kind", "webhook", "--enabled"},
		"wait on create":     {"create", "audit-sink", "--name", "siem", "--wait", "5s"},
		"nothing to update":  {"update", "audit-sink", "ask_1"},
		"the kind on update": {"update", "audit-sink", "ask_1", "--kind", "webhook"},
		"no sink to update":  {"update", "audit-sink", "--url", "https://x.example.com"},
		"no sink to test":    {"test", "audit-sink"},
	} {
		if code, _, _ := run(args...); code == cli.ExitOK {
			t.Errorf("%s was accepted", name)
		}
	}
	if code, _, _ := run("create", "audit-sink", "--name", "siem", "--kind", "carrier-pigeon"); code != cli.ExitUsage {
		t.Errorf("an unknown kind: %d", code)
	}
	if a.created != nil || a.updated != nil {
		t.Fatalf("refused input reached the API: %v %v", a.created, a.updated)
	}

	code, out, errOut := run("create", "audit-sink", "--name", "siem", "--kind", "webhook", "--url", "https://siem.example.com/hook",
		"--secret-file", keyFile, "--entries")
	got := a.created.GetAuditSink()
	if code != cli.ExitOK || got.GetSecret() != "signing-secret-of-the-sink" || got.GetKind() != rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK ||
		!got.GetEntries() || got.GetName() != "siem" || len(a.stepUps) != 1 || !strings.Contains(out, "Created audit sink ask_1") ||
		strings.Contains(out+errOut, "signing-secret-of-the-sink") {
		t.Fatalf("create: %d %q %q %v", code, out, errOut, a.created)
	}

	code, out, _ = run("get", "audit-sink", "ask_1")
	for _, want := range []string{"ask_1", "WEBHOOK", "12", "502"} {
		if code != cli.ExitOK || !strings.Contains(out, want) {
			t.Fatalf("get lacks %q: %d %q", want, code, out)
		}
	}
	if code, out, _ := run("list", "audit-sink"); code != cli.ExitOK || !strings.Contains(out, "siem") || !strings.Contains(out, "ask_1") {
		t.Fatalf("list: %d %q", code, out)
	}

	// An update by name sends the fields the flags name and the etag it read.
	if code, out, _ := run("update", "audit-sink", "siem", "--url", "https://siem.example.com/v2", "--enabled=false", "--secret-file", keyFile); code != cli.ExitOK ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"url", "secret", "enabled"}) ||
		a.updated.GetEtag() != "7" || a.updated.GetAuditSink().GetId() != "ask_1" || a.updated.GetAuditSink().GetEnabled() ||
		a.updated.GetAuditSink().GetUrl() != "https://siem.example.com/v2" || a.updated.GetAuditSink().GetSecret() != "signing-secret-of-the-sink" ||
		!strings.Contains(out, "Updated audit sink ask_1") {
		t.Fatalf("update: %d %q %v", code, out, a.updated)
	}
	if code, _, _ := run("update", "audit-sink", "ask_1", "--entries", "--force"); code != cli.ExitOK || a.updated.GetEtag() != "" ||
		!slices.Equal(a.updated.GetUpdateMask().GetPaths(), []string{"entries"}) || !a.updated.GetAuditSink().GetEntries() {
		t.Fatalf("a forced update: %d %v", code, a.updated)
	}

	if code, out, _ := run("test", "audit-sink", "siem"); code != cli.ExitOK || !strings.Contains(out, "accepted the test item") || !slices.Equal(a.tests, []string{"ask_1"}) {
		t.Fatalf("test: %d %q %v", code, out, a.tests)
	}
	a.refuse = "the receiver refused an item with 404"
	if code, _, errOut := run("test", "audit-sink", "ask_1"); code != cli.ExitError || !strings.Contains(errOut, "refused an item with 404") {
		t.Fatalf("a refused test: %d %q", code, errOut)
	}

	if code, out, _ := run("delete", "audit-sink", "siem"); code != cli.ExitOK || a.deleted.GetAuditSinkId() != "ask_1" || a.deleted.GetEtag() != "7" ||
		!strings.Contains(out, "Deleted audit-sink ask_1") {
		t.Fatalf("delete: %d %q %v", code, out, a.deleted)
	}
}
