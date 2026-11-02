// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestAuditSinks_Verify (#656; docs/04-security.md, "Audit log"): VerifyAuditSink takes the Instance
// Admin and a step-up and only an object-storage sink; it reads the sink back for every chain, keeps
// the outcome as the sink's status and audits the call; a gap or a changed object is the answer; a
// store that cannot be read is Unavailable and leaves the status as it was.
func TestAuditSinks_Verify(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		return castore.InitCA(e.sys, tx, e.sealer, "rpmgr-teststor", e.clock.Add(-time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	ca, err := castore.LoadCA(e.sys, e.db, e.sealer, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	srv := objstoretest.New(t)
	verify := func(b *browser, id string) (*rpmgrv1.AuditSinkVerification, error) {
		r, err := b.sink.VerifyAuditSink(ctx, connect.NewRequest(&rpmgrv1.VerifyAuditSinkRequest{AuditSinkId: id}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetVerification(), nil
	}
	if _, err := verify(ada, "ask_x"); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a verification without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	bob, _ := e.addOwner(t, storetest.Org(t, e.db, "org-b"), "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(bob, "ask_x"); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Owner who is no Instance Admin: %v", err)
	}
	if _, err := verify(ada, "ask_nope"); code(err) != connect.CodeNotFound {
		t.Fatalf("an unknown sink: %v", err)
	}
	hook := newSinkReceiver(t, e)
	wh, err := ada.sink.CreateAuditSink(ctx, connect.NewRequest(&rpmgrv1.CreateAuditSinkRequest{AuditSink: &rpmgrv1.AuditSink{Name: "hook",
		Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK, Url: hook.url, Secret: sinkKey}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(ada, wh.Msg.GetAuditSink().GetId()); code(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "only an object-storage sink") {
		t.Fatalf("a webhook sink: %v", err)
	}

	cr, err := ada.sink.CreateAuditSink(ctx, connect.NewRequest(&rpmgrv1.CreateAuditSinkRequest{AuditSink: &rpmgrv1.AuditSink{Name: "vault",
		Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_S3, Endpoint: srv.URL, Region: objstoretest.Region, Bucket: objstoretest.Bucket,
		AccessKeyId: objstoretest.AccessKeyID, Secret: awsKey1, Entries: true}}))
	if err != nil {
		t.Fatal(err)
	}
	id := cr.Msg.GetAuditSink().GetId()
	if cr.Msg.GetAuditSink().GetStatus().GetVerification() != nil {
		t.Fatal("a new sink has a verification")
	}
	if _, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "verify-eu"}})); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := audit.WriteCheckpoints(e.sys, tx, ca.AuditSigner(), e.clock, audit.Pending)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	runner := auditsink.NewRunner(auditsink.Options{DB: e.db, Sealer: e.sealer, Sender: e.sinks.Sender, Now: func() time.Time { return e.clock }, Logger: slog.New(slog.DiscardHandler)})
	if err := runner.Pass(e.sys, func(*ent.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}

	v, err := verify(ada, id)
	if err != nil || !v.GetIntact() || len(v.GetChains()) < 2 || v.GetTime() == nil {
		t.Fatalf("an intact sink: %v %v", v, err)
	}
	var seen []string
	for _, c := range v.GetChains() {
		seen = append(seen, c.GetChain())
		if !c.GetIntact() || c.GetCheckpointSeq() < 1 || c.GetCheckpointTime() == nil || c.GetChecked() < 1 || c.GetGap() != "" || c.GetProblem() != "" {
			t.Errorf("chain %s: %v", c.GetChain(), c)
		}
	}
	if !strings.Contains(strings.Join(seen, " "), org) || !strings.Contains(strings.Join(seen, " "), "instance") {
		t.Errorf("chains %v lack the org's or the instance chain", seen)
	}
	got, err := ada.sink.GetAuditSink(ctx, connect.NewRequest(&rpmgrv1.GetAuditSinkRequest{AuditSinkId: id}))
	if st := got.Msg.GetAuditSink().GetStatus(); err != nil || st.GetVerification().GetTime() == nil || !st.GetVerification().GetIntact() ||
		len(st.GetVerification().GetChains()) != len(v.GetChains()) || strings.Contains(got.Msg.String(), awsKey1) {
		t.Fatalf("the status keeps the verification: %v %v", got, err)
	}

	// An object of the sink goes missing: that is the answer, and the status keeps it.
	var cpKey string
	for _, k := range srv.Keys() {
		if strings.HasPrefix(k, "audit/"+org+"/checkpoints/") {
			cpKey = k
		}
	}
	srv.Remove(cpKey)
	if v, err = verify(ada, id); err != nil || v.GetIntact() {
		t.Fatalf("a sink that lost an object: %v %v", v, err)
	}
	for _, c := range v.GetChains() {
		if c.GetChain() == org && (c.GetIntact() || !strings.Contains(c.GetGap(), "checkpoints") || !strings.Contains(c.GetGap(), "missing from the sink")) {
			t.Errorf("the org's chain: %v", c)
		}
	}
	if got, _ = ada.sink.GetAuditSink(ctx, connect.NewRequest(&rpmgrv1.GetAuditSinkRequest{AuditSinkId: id})); got.Msg.GetAuditSink().GetStatus().GetVerification().GetIntact() {
		t.Fatal("the status still says intact")
	}

	// A store that cannot be read: Unavailable, and the status is as it was.
	kept := e.db.Client().AuditSink.GetX(e.sys, id).Verification
	srv.Fault = func(string, string) (int, time.Duration) { return 500, 0 }
	if _, err := verify(ada, id); code(err) != connect.CodeUnavailable || strings.Contains(err.Error(), srv.URL) || strings.Contains(err.Error(), awsKey1) {
		t.Fatalf("a store that answers 500: %v", err)
	}
	srv.Fault = nil
	if now := e.db.Client().AuditSink.GetX(e.sys, id).Verification; now == nil || !now.Time.Equal(kept.Time) {
		t.Fatal("a verification that did not finish replaced the status")
	}

	// Every call is audited.
	n := e.db.Client().AuditEntry.Query().Where(auditentry.ActionHasPrefix("rpmgr.v1.AuditSinkService.VerifyAuditSink")).CountX(e.sys)
	if n < 3 {
		t.Errorf("%d audit entries of verifications", n)
	}
}
