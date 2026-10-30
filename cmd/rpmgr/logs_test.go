// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// logsAPI answers StreamLogs with its lines, or its error.
type logsAPI struct {
	rpmgrv1connect.UnimplementedLogServiceHandler
	got []*rpmgrv1.StreamLogsRequest
	err error
}

func (a *logsAPI) StreamLogs(_ context.Context, req *connect.Request[rpmgrv1.StreamLogsRequest], st *connect.ServerStream[rpmgrv1.StreamLogsResponse]) error {
	a.got = append(a.got, req.Msg)
	if a.err != nil {
		return a.err
	}
	if err := st.Send(&rpmgrv1.StreamLogsResponse{}); err != nil { // a heartbeat, which prints nothing
		return err
	}
	at := timestamppb.New(time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC))
	for _, l := range []*rpmgrv1.LogLine{{Time: at, Level: "info", Text: "msg=before", DroppedBefore: 7, Backlog: true},
		{Time: at, Level: "info", Text: "msg=ready"},
		{Time: at, Level: "debug", Text: "msg=dialing", DroppedBefore: 3, Truncated: true}} {
		if err := st.Send(&rpmgrv1.StreamLogsResponse{Line: l}); err != nil {
			return err
		}
	}
	return nil
}

// TestLogs (docs/16-cli.md): logs connector streams the connector's lines with their time and
// level, says where lines were dropped or cut, and after the stream's end that it reached its
// deadline; its flags go into the request; a level it does not know is refused before anything is
// sent, and the API's refusal is an error.
func TestLogs(t *testing.T) {
	a := &logsAPI{}
	mux := http.NewServeMux()
	mux.Handle(rpmgrv1connect.NewLogServiceHandler(a))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	creds := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := apicli.Save(creds, &apicli.Credentials{Controller: srv.URL, Org: "org_1", Token: secret.FromBytes([]byte("rpmgr_pat_good")),
		CAFile: writeCA(t, srv)}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_CREDENTIALS": creds}
	const con = "con_01JA3B5C7D9E1F2G3H4J5K6M7N"
	code, out, errOut := runWith(env, "", "logs", "connector", "--level", "debug", "--filter", "dial", "--debug", con)
	want := "--- earlier lines ---\n… 7 older lines are no longer kept\n2026-10-25T09:00:00Z INFO  msg=before\n" +
		"--- new lines ---\n2026-10-25T09:00:00Z INFO  msg=ready\n… 3 lines dropped: the connector logged faster than they could be sent\n" +
		"2026-10-25T09:00:00Z DEBUG msg=dialing …(cut)\n"
	if code != cli.ExitOK || out != want || !strings.Contains(errOut, "ended at its deadline") {
		t.Fatalf("logs: %d\n%s\n%s", code, out, errOut)
	}
	if r := a.got[0]; r.GetAgentId() != con || r.GetLevel() != "debug" || r.GetFilter() != "dial" || !r.GetRaiseToDebug() {
		t.Fatalf("the request: %v", r)
	}
	calls := len(a.got)
	if code, _, _ := runWith(env, "", "logs", "connector", "--level", "trace", con); code != cli.ExitUsage {
		t.Errorf("an unknown level: exit %d", code)
	}
	if code, _, _ := runWith(env, "", "logs", "connector"); code != cli.ExitUsage {
		t.Errorf("no connector: exit %d", code)
	}
	if len(a.got) != calls {
		t.Error("a refused command reached the API")
	}
	a.err = connect.NewError(connect.CodeUnavailable, errors.New("apisvc: the agent is offline or runs no live logs"))
	if code, _, errOut := runWith(env, "", "logs", "gateway", "gw_01JA3B5C7D9E1F2G3H4J5K6M7N"); code != cli.ExitError ||
		!strings.Contains(errOut, "offline or runs no live logs") {
		t.Errorf("an offline gateway: %d %q", code, errOut)
	}
}

// TestPrintable: a line from an agent cannot reach the terminal as a control sequence: ESC (CSI
// and OSC 52, which writes the clipboard), the C1 CSI as a character and as a lone byte, NUL, CR
// and DEL are escaped; tabs and other text stay.
func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"msg=ready\tcount=2":          "msg=ready\tcount=2",
		"\x1b[2J\x1b[Hcleared":        `\x1b[2J\x1b[Hcleared`,
		"\x1b]52;c;cm0gLXJmIH4K\x07":  `\x1b]52;c;cm0gLXJmIH4K\x07`,
		"c1 \u009b31m red":            `c1 \u009b31m red`,
		"lone \x9b byte":              `lone \x9b byte`,
		"nul\x00 cr\r del\x7f":        `nul\x00 cr\x0d del\x7f`,
		"ünïcode ✓ and a line\nbreak": `ünïcode ✓ and a line\x0abreak`,
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
}
