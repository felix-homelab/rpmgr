// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const (
	exportAction         = "audit.export"
	exportInstanceAction = "audit.export"
)

func exportOrg(b *browser, org string) ([]string, error) {
	st, err := b.aud.ExportAudit(context.Background(), connect.NewRequest(&rpmgrv1.ExportAuditRequest{OrgId: org}))
	if err != nil {
		return nil, err
	}
	var lines []string
	for st.Receive() {
		lines = append(lines, st.Msg().GetLines()...)
	}
	return lines, st.Err()
}

func exportInstance(b *browser) ([]string, error) {
	st, err := b.aud.ExportInstanceAudit(context.Background(), connect.NewRequest(&rpmgrv1.ExportInstanceAuditRequest{}))
	if err != nil {
		return nil, err
	}
	var lines []string
	for st.Receive() {
		lines = append(lines, st.Msg().GetLines()...)
	}
	return lines, st.Err()
}

// exportEntries counts the audit entries of an action in a chain, by result.
func exportEntries(t *testing.T, e *env, org, action string, result audit.Result) int {
	t.Helper()
	q := e.db.Client().AuditEntry.Query().Where(auditentry.Action(action), auditentry.ResultEQ(auditentry.Result(result)))
	if org == "" {
		q.Where(auditentry.OrgIDIsNil())
	} else {
		q.Where(auditentry.OrgID(org))
	}
	return q.CountX(e.sys)
}

// TestAuditExport_StepUpAndOrgScoped (docs/04-security.md, "Audit log"): an export takes
// audit.read and a step-up; an org's export holds that org's chain only, with its own entry; the
// instance chain is for the Instance Admin; a refusal is audited; an export that breaks off is
// audited as a failure too.
func TestAuditExport_StepUpAndOrgScoped(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if err := adm.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	other := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, other, "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}

	// Without a CA the export breaks off after it was recorded: both are in the chain.
	if _, err := exportOrg(ada, org); err == nil {
		t.Fatal("an export of an instance without a CA")
	}
	if s, f := exportEntries(t, e, org, exportAction, audit.Success), exportEntries(t, e, org, exportAction, audit.Failure); s != 1 || f != 1 {
		t.Fatalf("a failed export is recorded as %d success and %d failure, want one of each", s, f)
	}

	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		return castore.InitCA(e.sys, tx, e.sealer, "rpmgr-teststor", e.clock.Add(-time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	ca, err := castore.LoadCA(e.sys, e.db, e.sealer, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"audit-eu", "audit-us"} {
		if _, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
			GatewayGroup: &rpmgrv1.GatewayGroup{Name: n}})); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := audit.WriteCheckpoints(e.sys, tx, ca.AuditSigner(), e.clock, audit.Pending)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "audit-after"}})); err != nil { // after the checkpoint
		t.Fatal(err)
	}

	lines, err := exportOrg(ada, org)
	if err != nil {
		t.Fatal(err)
	}
	var h audit.ExportHeader
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil || h.Format != audit.ExportFormat || h.Chain != org || h.FirstSeq != 1 ||
		h.AnchoredSeq == 0 || h.AnchoredSeq >= h.LastSeq {
		t.Fatalf("header %s: %v", lines[0], err)
	}
	var entries, cps, tail int
	var last audit.ExportEntry
	for _, l := range lines[1:] {
		var typ struct{ Type string }
		_ = json.Unmarshal([]byte(l), &typ)
		switch typ.Type {
		case audit.LineCheckpoint:
			cps++
		case audit.LineEntry:
			entries++
			if err := json.Unmarshal([]byte(l), &last); err != nil {
				t.Fatal(err)
			}
			if last.Unanchored {
				tail++
			}
			if last.Seq != int64(entries) {
				t.Fatalf("entry %d has seq %d: the export holds another chain or skips", entries, last.Seq)
			}
		default:
			t.Fatalf("a line of type %q", typ.Type)
		}
	}
	if int64(entries) != h.LastSeq || cps == 0 || tail == 0 || last.Action != exportAction || !last.Unanchored {
		t.Fatalf("%d entries, %d checkpoints, %d unanchored, last %+v, header %+v", entries, cps, tail, last, h)
	}

	if _, err := exportOrg(ada, ""); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an export without an org: %v", err)
	}
	if _, err := exportOrg(bob, org); connect.CodeOf(err) != connect.CodeNotFound && connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another org's Owner exports the org: %v", err)
	}
	if _, err := exportOrg(vwr, org); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer exports: %v", err)
	}
	if _, err := exportOrg(adm, org); err != nil {
		t.Fatalf("an Admin exports the org's chain: %v", err)
	}
	if _, err := exportInstance(adm); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("an Admin exports the instance chain: %v", err)
	}
	ilines, err := exportInstance(ada)
	if err != nil {
		t.Fatalf("the Instance Admin exports the instance chain: %v", err)
	}
	var ih audit.ExportHeader
	if err := json.Unmarshal([]byte(ilines[0]), &ih); err != nil || ih.Chain != audit.InstanceChain {
		t.Fatalf("the instance header %s: %v", ilines[0], err)
	}
	if n := exportEntries(t, e, "", exportInstanceAction, audit.Success); n != 1 {
		t.Fatalf("the instance export is %d times in the instance chain", n)
	}

	// The step-up window ends: the request is refused, and refused before anything is read.
	before := exportEntries(t, e, org, exportAction, audit.Success)
	e.clock = e.clock.Add(api.StepUpWindow + time.Minute)
	if _, err := exportOrg(ada, org); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("an export without a step-up: %v", err)
	}
	if _, err := exportInstance(ada); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("an instance export without a step-up: %v", err)
	}
	if n := exportEntries(t, e, org, exportAction, audit.Success); n != before {
		t.Fatalf("a refused export was recorded as a success")
	}
	if n := exportEntries(t, e, org, "rpmgr.v1.AuditService.ExportAudit", audit.Denied); n == 0 { // a refusal has the method's name
		t.Fatal("a refused export is not in the audit log")
	}
}

// TestAuditExport_DeadlineEndsTheStream (docs/03-connections.md, "Timeouts"): an export that runs
// past its deadline is ended with DEADLINE_EXCEEDED and recorded as a failure, not left open.
func TestAuditExport_DeadlineEndsTheStream(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		return castore.InitCA(e.sys, tx, e.sealer, "rpmgr-teststor", e.clock.Add(-time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	if apisvc.DefaultExportDeadline != 5*time.Minute {
		t.Fatalf("the default export deadline is %v, docs/03 says 5 min", apisvc.DefaultExportDeadline)
	}
	e.audit.ExportDeadline = time.Nanosecond // gone before the first line is written
	if _, err := exportOrg(ada, org); connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("an export past its deadline: %v", err)
	}
	if s, f := exportEntries(t, e, org, exportAction, audit.Success), exportEntries(t, e, org, exportAction, audit.Failure); s != 1 || f != 1 {
		t.Fatalf("the export is recorded as %d success and %d failure, want one of each", s, f)
	}
	e.audit.ExportDeadline = 0
	if lines, err := exportOrg(ada, org); err != nil || len(lines) == 0 {
		t.Fatalf("an export within the default deadline: %d lines, %v", len(lines), err)
	}
}
