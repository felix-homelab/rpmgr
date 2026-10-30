// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// TestVerifyAuditCommand (#656; docs/16-cli.md): verify audit --sink reads a sink back after a
// step-up and prints each chain's last verified checkpoint, its gap and its problem; it exits 0
// only when every chain is intact; input without a sink sends nothing; a failure of the call is
// reported as it came.
func TestVerifyAuditCommand(t *testing.T) {
	a := &sinkAPI{}
	run, _ := sinkSession(t, a)
	when := timestamppb.New(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	intact := &rpmgrv1.AuditSinkVerification{Time: when, Intact: true, Chains: []*rpmgrv1.AuditSinkChainVerification{
		{Chain: "instance", Checked: 2, CheckpointSeq: 14, CheckpointTime: when, Intact: true},
		{Chain: "org_a", Checked: 1, CheckpointSeq: 3, CheckpointTime: when, Intact: true}}}
	a.verification = intact

	for name, args := range map[string][]string{
		"no sink":             {"verify", "audit"},
		"a positional sink":   {"verify", "audit", "vault"},
		"an empty sink":       {"verify", "audit", "--sink", ""},
		"an unknown flag":     {"verify", "audit", "--sink", "ask_1", "--org", "x"},
		"a second positional": {"verify", "audit", "--sink", "ask_1", "extra"},
	} {
		if code, _, _ := run(args...); code != cli.ExitUsage || len(a.verified) != 0 {
			t.Errorf("%s: exit %d, %d requests", name, code, len(a.verified))
		}
	}

	code, out, errOut := run("verify", "audit", "--sink", "ask_1")
	for _, want := range []string{"Read the sink ask_1 back at 2026-10-30T12:00:00Z", "chain instance: intact; last verified checkpoint: seq 14",
		"chain org_a: intact; last verified checkpoint: seq 3", "2 checkpoints read"} {
		if code != cli.ExitOK || !strings.Contains(out, want) {
			t.Fatalf("an intact sink lacks %q: %d %q %q", want, code, out, errOut)
		}
	}
	if len(a.stepUps) != 1 || !slices.Equal(a.verified, []string{"ask_1"}) {
		t.Fatalf("step-ups %d, sinks read %v", len(a.stepUps), a.verified)
	}

	// A sink with a gap or a problem fails, and says where.
	a.verification = &rpmgrv1.AuditSinkVerification{Time: when, Chains: []*rpmgrv1.AuditSinkChainVerification{
		{Chain: "instance", Checked: 2, CheckpointSeq: 14, CheckpointTime: when, Intact: true},
		{Chain: "org_a", Checked: 1, CheckpointSeq: 3, CheckpointTime: when, Gap: "entries 17-19 missing from the sink",
			Problem: "the checkpoint at seq 4: the chain does not match a checkpoint held outside the database: it was rewritten"}}}
	code, out, errOut = run("verify", "audit", "--sink", "siem")
	for _, want := range []string{"chain instance: intact", "chain org_a: NOT INTACT", "gap: entries 17-19 missing from the sink", "problem: the checkpoint at seq 4"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q: %q", want, out)
		}
	}
	if code != cli.ExitError || !strings.Contains(errOut, "NOT VERIFIED") {
		t.Fatalf("a sink with a problem: exit %d %q", code, errOut)
	}

	// No chain yet; a chain no checkpoint of the sink has verified.
	a.verification = &rpmgrv1.AuditSinkVerification{Time: when, Intact: true}
	if code, out, _ := run("verify", "audit", "--sink", "ask_1"); code != cli.ExitOK || !strings.Contains(out, "no chain with entries yet") {
		t.Fatalf("no chains: %d %q", code, out)
	}
	a.verification = &rpmgrv1.AuditSinkVerification{Time: when, Intact: true, Chains: []*rpmgrv1.AuditSinkChainVerification{{Chain: "instance", Intact: true}}}
	if code, out, _ := run("verify", "audit", "--sink", "ask_1"); code != cli.ExitOK || !strings.Contains(out, "no checkpoint of the sink has verified yet") {
		t.Fatalf("no verified checkpoint: %d %q", code, out)
	}

	// The call fails: the controller's words reach the user, and nothing is printed as verified.
	a.verifyErr = connect.NewError(connect.CodeUnavailable, errors.New("the object store did not answer in time"))
	if code, out, errOut := run("verify", "audit", "--sink", "ask_1"); code == cli.ExitOK || !strings.Contains(errOut, "did not answer in time") || strings.Contains(out, "intact") {
		t.Fatalf("a failed verification: %d %q %q", code, out, errOut)
	}
	a.verifyErr = connect.NewError(connect.CodeInvalidArgument, errors.New("only an object-storage sink can be read back"))
	if code, _, errOut := run("verify", "audit", "--sink", "ask_1"); code == cli.ExitOK || !strings.Contains(errOut, "only an object-storage sink") {
		t.Fatalf("a webhook sink: %d %q", code, errOut)
	}
}
