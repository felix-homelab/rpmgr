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
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// checkAPI is a release check that runs for polls polls and then ends with outcome, or refuses
// with refuse.
type checkAPI struct {
	rpmgrv1connect.UnimplementedReleaseServiceHandler

	mu      sync.Mutex
	polls   int
	outcome rpmgrv1.ReleaseCheckOutcome
	refuse  error
	asked   int
}

func (a *checkAPI) state() *rpmgrv1.ReleaseCheck {
	if a.polls > 0 {
		return &rpmgrv1.ReleaseCheck{Running: true}
	}
	st := &rpmgrv1.ReleaseCheck{CheckTime: timestamppb.New(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)), Outcome: a.outcome}
	if a.outcome == rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_FAILED {
		st.Error = "dial tcp: no route to host"
	}
	return st
}

func (a *checkAPI) CheckReleases(context.Context, *connect.Request[rpmgrv1.CheckReleasesRequest]) (*connect.Response[rpmgrv1.CheckReleasesResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked++
	if a.refuse != nil {
		return nil, a.refuse
	}
	return connect.NewResponse(&rpmgrv1.CheckReleasesResponse{ReleaseCheck: &rpmgrv1.ReleaseCheck{Running: true}}), nil
}

func (a *checkAPI) ListReleases(context.Context, *connect.Request[rpmgrv1.ListReleasesRequest]) (*connect.Response[rpmgrv1.ListReleasesResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.state()
	if a.polls > 0 {
		a.polls--
	}
	return connect.NewResponse(&rpmgrv1.ListReleasesResponse{ReleaseCheck: st}), nil
}

// TestCheckRelease (#890): check release asks for a release check and waits for it to end; a
// failed check fails the command with its error, and a refusal says why.
func TestCheckRelease(t *testing.T) {
	a := &checkAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewReleaseServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	old := checkPoll
	checkPoll = time.Millisecond
	t.Cleanup(func() { checkPoll = old })
	run := func(args ...string) (int, string, string) { return runWith(map[string]string{"RPMGR_CREDENTIALS": creds}, "", args...) }

	a.polls, a.outcome = 3, rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OK
	if code, out, errOut := run("check", "release"); code != cli.ExitOK || !strings.Contains(out, "Checked for releases at 2026-10-24T12:00:00Z") ||
		a.polls != 0 || a.asked != 1 {
		t.Errorf("a check: %d %q %q, %d polls left", code, out, errOut, a.polls)
	}
	a.polls, a.outcome = 1, rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_FAILED
	if code, _, errOut := run("check", "release"); code != cli.ExitError || !strings.Contains(errOut, "no route to host") ||
		!strings.Contains(errOut, "keeps what it had") {
		t.Errorf("a failed check: %d %q", code, errOut)
	}
	a.outcome = rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OFF
	if code, _, errOut := run("check", "release"); code != cli.ExitError || !strings.Contains(errOut, "turned off") {
		t.Errorf("a check turned off meanwhile: %d %q", code, errOut)
	}
	off := connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the release check is off; turn it on in the instance settings first"))
	if d, err := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: "RELEASE_CHECK_OFF", Domain: api.ErrorDomain}); err == nil {
		off.AddDetail(d)
	}
	a.refuse = off
	if code, _, errOut := run("check", "release"); code != cli.ExitError || !strings.Contains(errOut, "RELEASE_CHECK_OFF") {
		t.Errorf("the release check off: %d %q", code, errOut)
	}
	if code, _, _ := run("check", "release", "now"); code != cli.ExitUsage {
		t.Errorf("an argument: %d", code)
	}
}
