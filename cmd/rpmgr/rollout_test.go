// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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

// releaseAPI records the release service's requests; every change but a pause needs a step-up.
type releaseAPI struct {
	rpmgrv1connect.UnimplementedReleaseServiceHandler
	rpmgrv1connect.UnimplementedGatewayServiceHandler
	stepUpAPI

	mu      sync.Mutex
	upload  *rpmgrv1.UploadReleaseRequest
	create  *rpmgrv1.CreateRolloutRequest
	advance *rpmgrv1.AdvanceRolloutRequest
	changes []string // the pause, resume and cancel calls, each with its etag
	targets *rpmgrv1.ListRolloutTargetsRequest
	upgrade *rpmgrv1.UpgradeAgentsRequest
	ctlUp   *rpmgrv1.UpdateControllerRequest
}

func (a *releaseAPI) UpdateController(_ context.Context, req *connect.Request[rpmgrv1.UpdateControllerRequest]) (*connect.Response[rpmgrv1.UpdateControllerResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ctlUp = req.Msg
	if req.Msg.GetReleaseId() == "rel_1" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("release 1.4.2 is not newer than the controller's 1.5.0"))
	}
	return connect.NewResponse(&rpmgrv1.UpdateControllerResponse{Update: &rpmgrv1.ControllerUpdate{Version: "1.6.0",
		State: rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_STAGED}}), nil
}

func (a *releaseAPI) GetControllerUpdate(context.Context, *connect.Request[rpmgrv1.GetControllerUpdateRequest]) (*connect.Response[rpmgrv1.GetControllerUpdateResponse], error) {
	return connect.NewResponse(&rpmgrv1.GetControllerUpdateResponse{RunningVersion: "1.5.0", Blocked: "the controller runs on postgres",
		Update: &rpmgrv1.ControllerUpdate{Version: "1.6.0", State: rpmgrv1.ControllerUpdateState_CONTROLLER_UPDATE_STATE_UPDATING,
			Step: "backing_up", Reason: ""}}), nil
}

func (a *releaseAPI) needStepUp() error {
	a.stepUpAPI.mu.Lock()
	defer a.stepUpAPI.mu.Unlock()
	if !a.stepped {
		return stepUpError()
	}
	return nil
}

func (a *releaseAPI) ListReleases(context.Context, *connect.Request[rpmgrv1.ListReleasesRequest]) (*connect.Response[rpmgrv1.ListReleasesResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListReleasesResponse{ControllerVersion: "1.5.0", Releases: []*rpmgrv1.Release{
		{Id: "rel_2", Version: "1.5.0", Channel: rpmgrv1.UpdateChannel_UPDATE_CHANNEL_STABLE, Mirrored: true, ControllerVersion: true},
		{Id: "rel_1", Version: "1.4.2", Channel: rpmgrv1.UpdateChannel_UPDATE_CHANNEL_STABLE, Source: rpmgrv1.ReleaseSource_RELEASE_SOURCE_UPLOAD}}}), nil
}

func (a *releaseAPI) UploadRelease(_ context.Context, req *connect.Request[rpmgrv1.UploadReleaseRequest]) (*connect.Response[rpmgrv1.UploadReleaseResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upload = req.Msg
	return connect.NewResponse(&rpmgrv1.UploadReleaseResponse{Release: &rpmgrv1.Release{Id: "rel_1", Version: "1.4.2", ManifestSeq: 87}}), nil
}

func (a *releaseAPI) CreateRollout(_ context.Context, req *connect.Request[rpmgrv1.CreateRolloutRequest]) (*connect.Response[rpmgrv1.CreateRolloutResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.create = req.Msg
	return connect.NewResponse(&rpmgrv1.CreateRolloutResponse{Rollout: &rpmgrv1.Rollout{Id: "rol_1", Version: "1.4.2",
		Stage: rpmgrv1.RolloutStage_ROLLOUT_STAGE_CANARY, State: rpmgrv1.RolloutState_ROLLOUT_STATE_RUNNING, Etag: "1"}}), nil
}

func (a *releaseAPI) GetRollout(_ context.Context, req *connect.Request[rpmgrv1.GetRolloutRequest]) (*connect.Response[rpmgrv1.GetRolloutResponse], error) {
	if req.Msg.GetRolloutId() != "rol_1" {
		return nil, connect.NewError(connect.CodeNotFound, nil)
	}
	return connect.NewResponse(&rpmgrv1.GetRolloutResponse{Rollout: &rpmgrv1.Rollout{Id: "rol_1", Version: "1.4.2", Percentage: 25,
		Stage: rpmgrv1.RolloutStage_ROLLOUT_STAGE_PERCENTAGE, State: rpmgrv1.RolloutState_ROLLOUT_STATE_RUNNING, Etag: "7"}}), nil
}

func (a *releaseAPI) AdvanceRollout(_ context.Context, req *connect.Request[rpmgrv1.AdvanceRolloutRequest]) (*connect.Response[rpmgrv1.AdvanceRolloutResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.advance = req.Msg
	return connect.NewResponse(&rpmgrv1.AdvanceRolloutResponse{Rollout: &rpmgrv1.Rollout{Id: "rol_1", Version: "1.4.2"}}), nil
}

func (a *releaseAPI) PauseRollout(_ context.Context, req *connect.Request[rpmgrv1.PauseRolloutRequest]) (*connect.Response[rpmgrv1.PauseRolloutResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.changes = append(a.changes, "pause "+req.Msg.GetEtag())
	return connect.NewResponse(&rpmgrv1.PauseRolloutResponse{Rollout: &rpmgrv1.Rollout{Id: "rol_1", Version: "1.4.2",
		State: rpmgrv1.RolloutState_ROLLOUT_STATE_PAUSED}}), nil
}

func (a *releaseAPI) ResumeRollout(_ context.Context, req *connect.Request[rpmgrv1.ResumeRolloutRequest]) (*connect.Response[rpmgrv1.ResumeRolloutResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.changes = append(a.changes, "resume "+req.Msg.GetEtag())
	return connect.NewResponse(&rpmgrv1.ResumeRolloutResponse{Rollout: &rpmgrv1.Rollout{Id: "rol_1", Version: "1.4.2"}}), nil
}

func (a *releaseAPI) CancelRollout(_ context.Context, req *connect.Request[rpmgrv1.CancelRolloutRequest]) (*connect.Response[rpmgrv1.CancelRolloutResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.changes = append(a.changes, "cancel "+req.Msg.GetEtag())
	return connect.NewResponse(&rpmgrv1.CancelRolloutResponse{Rollout: &rpmgrv1.Rollout{Id: "rol_1", Version: "1.4.2"}}), nil
}

func (a *releaseAPI) ListRolloutTargets(_ context.Context, req *connect.Request[rpmgrv1.ListRolloutTargetsRequest]) (
	*connect.Response[rpmgrv1.ListRolloutTargetsResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.targets = req.Msg
	return connect.NewResponse(&rpmgrv1.ListRolloutTargetsResponse{RolloutTargets: []*rpmgrv1.RolloutTarget{{Id: "rlt_1", AgentId: "con_1",
		AgentName: "nas", Canary: true, State: rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_ROLLED_BACK, Reason: "not ready"}}}), nil
}

func (a *releaseAPI) UpgradeAgents(_ context.Context, req *connect.Request[rpmgrv1.UpgradeAgentsRequest]) (*connect.Response[rpmgrv1.UpgradeAgentsResponse], error) {
	if err := a.needStepUp(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upgrade = req.Msg
	if slices.Contains(req.Msg.GetAgentIds(), "gw_busy") {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("a staged rollout runs or is paused"))
	}
	out := &rpmgrv1.UpgradeAgentsResponse{Rollout: &rpmgrv1.Rollout{Id: "rol_3", Version: "1.5.0", Mode: rpmgrv1.RolloutMode_ROLLOUT_MODE_EASY}}
	for i, id := range req.Msg.GetAgentIds() {
		out.RolloutTargets = append(out.RolloutTargets, &rpmgrv1.RolloutTarget{Id: "rlt_" + id, AgentId: id, Position: int32(i + 4), //nolint:gosec // G115: a few
			State: rpmgrv1.RolloutTargetState_ROLLOUT_TARGET_STATE_PENDING})
	}
	return connect.NewResponse(out), nil
}

func (a *releaseAPI) ListGateways(context.Context, *connect.Request[rpmgrv1.ListGatewaysRequest]) (*connect.Response[rpmgrv1.ListGatewaysResponse], error) {
	return connect.NewResponse(&rpmgrv1.ListGatewaysResponse{Gateways: []*rpmgrv1.Gateway{{Id: "gw_1", Name: "edge"}}}), nil
}

// TestReleasesAndRollouts (docs/16-cli.md): upload release sends a release's four signed files
// after a step-up, and refuses a directory that lacks one or a file above 1 MiB; create rollout
// names the release by version and the canary agents by name or ID; advance, resume and cancel
// send the etag they read, and with --force none, each after a step-up, a pause without one; the
// releases and a rollout's agents are listed, without an org.
func TestReleasesAndRollouts(t *testing.T) {
	a := &releaseAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewReleaseServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewConnectorServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	run := func(args ...string) (int, string, string) { return runWith(env, "", args...) }
	prompts := 0
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { prompts++; return "right", nil }
	t.Cleanup(func() { stepUpPrompt = old })

	// A pause needs no step-up, so it goes first, before the session is stepped up.
	if code, out, errOut := run("pause", "rollout", "rol_1"); code != cli.ExitOK || prompts != 0 || !strings.Contains(out, "Paused rollout rol_1 of 1.4.2") ||
		len(a.changes) != 1 || a.changes[0] != "pause 7" {
		t.Fatalf("pause: %d %q %q %v", code, out, errOut, a.changes)
	}

	rel := filepath.Join(dir, "v1.4.2")
	if err := os.Mkdir(rel, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"signing-key.json", "signing-key.json.minisig", "manifest.json"} {
		if err := os.WriteFile(filepath.Join(rel, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, errOut := run("upload", "release", rel); code != cli.ExitError || !strings.Contains(errOut, "manifest.json.minisig") || a.upload != nil {
		t.Errorf("a release without the manifest's signature: %d %q", code, errOut)
	}
	if err := os.WriteFile(filepath.Join(rel, "manifest.json.minisig"), make([]byte, maxReleaseFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run("upload", "release", rel); code != cli.ExitError || !strings.Contains(errOut, "larger than") || a.upload != nil {
		t.Errorf("an oversized signature: %d %q", code, errOut)
	}
	if err := os.WriteFile(filepath.Join(rel, "manifest.json.minisig"), []byte("sig"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run("upload", "release", rel)
	if code != cli.ExitOK || prompts != 1 || string(a.upload.GetManifest()) != "manifest.json" || string(a.upload.GetManifestSignature()) != "sig" ||
		string(a.upload.GetStatementSignature()) != "signing-key.json.minisig" || !strings.Contains(out, "Uploaded release 1.4.2 (manifest 87)") {
		t.Fatalf("upload: %d %q %q %v", code, out, errOut, a.upload)
	}
	if code, _, _ := run("upload", "release"); code != cli.ExitUsage {
		t.Errorf("upload without a directory: %d", code)
	}

	code, out, errOut = run("create", "rollout", "--release", "v1.4.2", "--canary", "nas", "--canary", "gw_9", "--canary", "edge")
	if code != cli.ExitOK || a.create.GetReleaseId() != "rel_1" || strings.Join(a.create.GetCanaryAgentIds(), ",") != "con_1,gw_9,gw_1" ||
		!strings.Contains(out, "Started rollout rol_1 of 1.4.2") {
		t.Fatalf("create rollout: %d %q %q %v", code, out, errOut, a.create)
	}
	if code, _, errOut := run("create", "rollout", "--release", "1.9.0", "--canary", "nas"); code != cli.ExitError || !strings.Contains(errOut, "no release 1.9.0") {
		t.Errorf("an unknown release: %d %q", code, errOut)
	}
	if code, _, errOut := run("create", "rollout", "--release", "1.4.2", "--canary", "nosuch"); code != cli.ExitError || !strings.Contains(errOut, "nosuch") {
		t.Errorf("an unknown canary: %d %q", code, errOut)
	}
	if code, _, _ := run("create", "rollout", "--release", "1.4.2"); code != cli.ExitUsage {
		t.Errorf("a rollout without canary agents: %d", code)
	}

	if code, out, _ := run("advance", "rollout", "--percent", "50", "rol_1"); code != cli.ExitOK || a.advance.GetPercentage() != 50 ||
		a.advance.GetEtag() != "7" || !strings.Contains(out, "Advanced rollout rol_1") {
		t.Fatalf("advance to 50 %%: %d %q %v", code, out, a.advance)
	}
	if code, _, _ := run("advance", "rollout", "--all", "--force", "rol_1"); code != cli.ExitOK || !a.advance.GetAll() || a.advance.GetEtag() != "" {
		t.Errorf("advance to all: %d %v", code, a.advance)
	}
	for _, args := range [][]string{{"--all", "--percent", "50", "rol_1"}, {"rol_1"}, {"--percent", "100", "rol_1"}, {"--percent", "-3", "rol_1"}, {"--all"}} {
		if code, _, _ := run(append([]string{"advance", "rollout"}, args...)...); code != cli.ExitUsage {
			t.Errorf("advance %v: %d", args, code)
		}
	}
	if code, _, errOut := run("advance", "rollout", "--all", "rol_2"); code != cli.ExitError || !strings.Contains(errOut, "not found") {
		t.Errorf("advance an unknown rollout: %d %q", code, errOut)
	}
	if code, _, _ := run("resume", "rollout", "rol_1"); code != cli.ExitOK {
		t.Errorf("resume: %d", code)
	}
	if code, _, _ := run("cancel", "rollout", "--force", "rol_1"); code != cli.ExitOK {
		t.Errorf("cancel: %d", code)
	}
	if strings.Join(a.changes, ",") != "pause 7,resume 7,cancel " || prompts != 1 {
		t.Errorf("the changes %v, %d prompts", a.changes, prompts)
	}

	if code, out, _ := run("list", "release"); code != cli.ExitOK || !strings.Contains(out, "1.5.0") || !strings.Contains(out, "rel_1") {
		t.Errorf("list release: %d %q", code, out)
	}
	code, out, _ = run("list", "rollout-target", "rol_1", "-o", "json")
	var listed []map[string]any
	if code != cli.ExitOK || json.Unmarshal([]byte(out), &listed) != nil || len(listed) != 1 || listed[0]["reason"] != "not ready" ||
		a.targets.GetRolloutId() != "rol_1" {
		t.Errorf("list rollout-target: %d %q %v", code, out, a.targets)
	}
	if code, _, _ := run("list", "rollout-target"); code != cli.ExitUsage {
		t.Errorf("list rollout-target without the rollout: %d", code)
	}
	if code, out, _ := run("get", "rollout", "rol_1"); code != cli.ExitOK || !strings.Contains(out, "PERCENTAGE") || !strings.Contains(out, "25") {
		t.Errorf("get rollout: %d %q", code, out)
	}
}

// TestEasyRolloutCommands (docs/16-cli.md; D129): create rollout --easy sends the queue in the
// order given and no canary; upgrade connector and upgrade gateway resolve names of their kind
// only, send each agent once, after a step-up, and say each agent's place in the queue.
func TestEasyRolloutCommands(t *testing.T) {
	a := &releaseAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewReleaseServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewAuthServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewConnectorServiceHandler(a))
	mux.Handle(rpmgrv1connect.NewGatewayServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		return runWith(map[string]string{"RPMGR_CREDENTIALS": creds}, "", args...)
	}
	prompts := 0
	old := stepUpPrompt
	stepUpPrompt = func() (string, error) { prompts++; return "right", nil }
	t.Cleanup(func() { stepUpPrompt = old })

	for _, args := range [][]string{
		{"--release", "1.4.2", "--easy"},
		{"--release", "1.4.2", "--easy", "--agent", "nas", "--canary", "edge"},
		{"--release", "1.4.2", "--agent", "nas"},
		{"--easy", "--agent", "nas"},
	} {
		if code, _, _ := run(append([]string{"create", "rollout"}, args...)...); code != cli.ExitUsage {
			t.Errorf("create rollout %v: %d", args, code)
		}
	}
	if a.create != nil {
		t.Fatalf("a refused command sent %v", a.create)
	}
	code, out, errOut := run("create", "rollout", "--release", "1.4.2", "--easy", "--agent", "edge", "--agent", "nas", "--agent", "con_7")
	if code != cli.ExitOK || a.create.GetMode() != rpmgrv1.RolloutMode_ROLLOUT_MODE_EASY || len(a.create.GetCanaryAgentIds()) != 0 ||
		strings.Join(a.create.GetAgentIds(), ",") != "gw_1,con_1,con_7" || !strings.Contains(out, "Started easy rollout rol_1 of 1.4.2") {
		t.Fatalf("create rollout --easy: %d %q %q %v", code, out, errOut, a.create)
	}

	code, out, errOut = run("upgrade", "connector", "nas", "con_7", "nas")
	if code != cli.ExitOK || strings.Join(a.upgrade.GetAgentIds(), ",") != "con_1,con_7" ||
		!strings.Contains(out, "connector con_1 is number 4 in the queue of easy rollout rol_3 of 1.5.0") ||
		!strings.Contains(out, "connector con_7 is number 5") {
		t.Fatalf("upgrade connector: %d %q %q %v", code, out, errOut, a.upgrade)
	}
	code, out, _ = run("upgrade", "gateway", "edge", "-o", "json")
	var listed []map[string]any
	if code != cli.ExitOK || json.Unmarshal([]byte(out), &listed) != nil || len(listed) != 1 || listed[0]["agentId"] != "gw_1" ||
		listed[0]["position"] != float64(4) {
		t.Errorf("upgrade gateway -o json: %d %q", code, out)
	}
	// The controller's own update (D158): by version, after a step-up; refusals are shown; --status
	// says how it stands and why none can start; the flags are exclusive.
	for _, args := range [][]string{{}, {"--release", "1.6.0", "--status"}, {"--release", "1.6.0", "extra"}} {
		if code, _, _ := run(append([]string{"upgrade", "controller"}, args...)...); code != cli.ExitUsage {
			t.Errorf("upgrade controller %v: %d", args, code)
		}
	}
	if code, out, errOut := run("upgrade", "controller", "--release", "rel_3"); code != cli.ExitOK || a.ctlUp.GetReleaseId() != "rel_3" ||
		!strings.Contains(out, "Staged 1.6.0") {
		t.Errorf("upgrade controller: %d %q %q %v", code, out, errOut, a.ctlUp)
	}
	if code, _, errOut := run("upgrade", "controller", "--release", "rel_1"); code != cli.ExitError || !strings.Contains(errOut, "not newer") {
		t.Errorf("upgrade controller to an older release: %d %q", code, errOut)
	}
	if code, out, _ := run("upgrade", "controller", "--status"); code != cli.ExitOK || !strings.Contains(out, "The controller runs 1.5.0.") ||
		!strings.Contains(out, "Update to 1.6.0: updating (backing up).") || !strings.Contains(out, "No update can be started now: the controller runs on postgres.") {
		t.Errorf("upgrade controller --status: %d %q", code, out)
	}
	a.upgrade = nil
	if code, _, errOut := run("upgrade", "connector", "edge"); code != cli.ExitError || a.upgrade != nil {
		t.Errorf("upgrade connector with a gateway's name: %d %q", code, errOut)
	}
	if code, _, _ := run("upgrade", "gateway"); code != cli.ExitUsage {
		t.Errorf("upgrade gateway without one: %d", code)
	}
	if code, _, errOut := run("upgrade", "gateway", "gw_busy"); code != cli.ExitError || !strings.Contains(errOut, "staged rollout") {
		t.Errorf("upgrade while a staged rollout runs: %d %q", code, errOut)
	}
	if prompts != 1 {
		t.Errorf("%d step-up prompts, want 1", prompts)
	}
}
