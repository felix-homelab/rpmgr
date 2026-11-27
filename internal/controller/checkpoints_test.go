// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestCheckpointJob (docs/04-security.md, "Audit log"): the singleton job signs a checkpoint of
// each chain that is due and appends it to the local log; at shutdown every chain with newer
// entries gets one more; both verify with the CA's certificates.
func TestCheckpointJob(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	leases := lease.New(db, "ctn_test", nil)
	at := time.Now()
	o := controller.CheckpointOptions{DB: db, CA: e.ca, Leases: leases, Now: func() time.Time { return at },
		Log: &audit.CheckpointLog{Path: filepath.Join(t.TempDir(), "audit-checkpoints.log")}}
	if _, err := audit.Record(context.Background(), db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "test", Action: "test.run",
		Result: audit.Success}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		leases.Run(ctx, controller.CheckpointJob(o), func(err error) { t.Errorf("job: %v", err) })
		close(done)
	}()
	waitUntil(t, func() bool {
		cps, err := audit.ReadCheckpointLog(o.Log.Path)
		return err == nil && len(cps) > 0
	})
	cancel()
	<-done
	first, _ := audit.ReadCheckpointLog(o.Log.Path)
	if n := e.db.Client().AuditCheckpoint.Query().CountX(e.sys); n != len(first) {
		t.Fatalf("%d checkpoints in the database, %d in the log", n, len(first))
	}

	if _, err := audit.Record(context.Background(), db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "test", Action: "test.run",
		Result: audit.Success}); err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Minute) // not due yet; shutdown writes it anyway
	if err := controller.FinalCheckpoints(e.sys, o); err != nil {
		t.Fatal(err)
	}
	all, err := audit.ReadCheckpointLog(o.Log.Path)
	if err != nil || len(all) != len(first)+1 {
		t.Fatalf("after shutdown: %d checkpoints, %v", len(all), err)
	}
	signers, inters, roots, err := castore.SignerCertificates(e.sys, db, pki.PurposeAuditCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	trust := audit.Trust{Root: roots[0], Roots: roots, Intermediates: inters, Signers: signers}
	if head, last, err := audit.VerifyChain(e.sys, db, "", trust); err != nil || last == nil || last.Seq != head.Seq {
		t.Fatalf("the instance chain: %+v %+v %v", head, last, err)
	}
	if err := controller.FinalCheckpoints(e.sys, o); err != nil {
		t.Fatal(err)
	}
	if again, _ := audit.ReadCheckpointLog(o.Log.Path); len(again) != len(all) {
		t.Fatalf("a second shutdown without new entries wrote %d checkpoints", len(again)-len(all))
	}
}

// TestRetentionJob: the singleton job keeps entries for the instance's audit retention, 365 days
// by default; past it, a chain loses its prefix up to its newest checkpoint, the removal is
// recorded in the chain, and the chain still verifies.
func TestRetentionJob(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	leases := lease.New(db, "ctn_test", nil)
	at := time.Now()
	o := controller.CheckpointOptions{DB: db, CA: e.ca, Leases: leases, Now: func() time.Time { return at },
		Log: &audit.CheckpointLog{Path: filepath.Join(t.TempDir(), "audit-checkpoints.log")}}
	for range 3 {
		if _, err := audit.Record(context.Background(), db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "test", Action: "test.run",
			Result: audit.Success}); err != nil {
			t.Fatal(err)
		}
	}
	if err := controller.FinalCheckpoints(e.sys, o); err != nil {
		t.Fatal(err)
	}
	signers, inters, roots, err := castore.SignerCertificates(e.sys, db, pki.PurposeAuditCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	trust := audit.Trust{Root: roots[0], Roots: roots, Intermediates: inters, Signers: signers}
	before, _, err := audit.VerifyChain(e.sys, db, "", trust)
	if err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		if err := runOnce(t, leases, controller.RetentionJob(o)); err != nil {
			t.Errorf("job: %v", err)
		}
	}
	run()
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("audit.prune")).CountX(e.sys); n != 0 {
		t.Fatal("entries within their retention were removed")
	}
	at = at.Add(366 * 24 * time.Hour)
	run()
	pruned := e.db.Client().AuditEntry.Query().Where(auditentry.Action("audit.prune")).AllX(e.sys)
	if len(pruned) != 1 || !strings.Contains(pruned[0].Reason, fmt.Sprintf("up to %d", before.Seq)) {
		t.Fatalf("the removal's record: %+v (head was %d)", pruned, before.Seq)
	}
	head, last, err := audit.VerifyChain(e.sys, db, "", trust)
	if err != nil || last == nil || last.Seq != before.Seq || head.Seq <= before.Seq {
		t.Fatalf("the instance chain after retention: %+v %+v %v", head, last, err)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.SeqLTE(before.Seq), auditentry.OrgIDIsNil()).CountX(e.sys); n != 0 {
		t.Fatalf("%d entries up to the checkpoint left", n)
	}
}

// TestCheckpointsAcrossRootRotation: a checkpoint signed before a root rotation verifies during the
// overlap and after the old root was dropped, as do the ones signed later: the trust holds every root
// the CA has had, not the active one alone.
func TestCheckpointsAcrossRootRotation(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	leases := lease.New(db, "ctn_test", nil)
	at := time.Now()
	o := controller.CheckpointOptions{DB: db, CA: e.ca, Leases: leases, Now: func() time.Time { return at },
		Log: &audit.CheckpointLog{Path: filepath.Join(t.TempDir(), "audit-checkpoints.log")}}
	checkpoint := func() {
		t.Helper()
		if _, err := audit.Record(context.Background(), db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "test", Action: "test.run",
			Result: audit.Success}); err != nil {
			t.Fatal(err)
		}
		if err := controller.FinalCheckpoints(e.sys, o); err != nil {
			t.Fatal(err)
		}
	}
	verify := func(wantRoots int) {
		t.Helper()
		signers, inters, roots, err := castore.SignerCertificates(e.sys, db, pki.PurposeAuditCheckpoint)
		if err != nil || len(roots) != wantRoots {
			t.Fatalf("%d roots, %v; want %d", len(roots), err, wantRoots)
		}
		trust := audit.Trust{Root: roots[0], Roots: roots, Intermediates: inters, Signers: signers}
		if head, last, err := audit.VerifyChain(e.sys, db, "", trust); err != nil || last == nil || last.Seq != head.Seq {
			t.Fatalf("the instance chain with %d roots: %+v %+v %v", wantRoots, head, last, err)
		}
		// A trust with the new root alone cannot verify what the old one's intermediate certified.
		if wantRoots == 2 {
			alone := audit.Trust{Root: roots[0], Intermediates: inters, Signers: signers}
			if _, _, err := audit.VerifyChain(e.sys, db, "", alone); err == nil {
				t.Fatal("the chain verified against the new root alone")
			}
		}
	}
	checkpoint() // before the rotation, under the old root
	e.newRootOnline(t, at)
	at = at.Add(time.Minute)
	checkpoint() // in the overlap: the signing key is the old one
	verify(2)

	co := controller.CAOptions{DB: db, CA: e.ca, Sealer: e.sealer, Leases: leases, Now: func() time.Time { return at }}
	at = at.Add(38 * rotationDay)
	if err := runOnce(t, leases, controller.CARotation(co)); err != nil {
		t.Fatal(err)
	}
	if len(e.ca.Roots()) != 1 {
		t.Fatal("the job did not drop the old root")
	}
	checkpoint() // after the drop, under the new root; the chain holds all three and R1 is retired
	verify(2)
}

// TestAuditExportAcrossRootRotation: an export that spans a root rotation verifies offline with the old
// root's pin, which trusts the new root through the cross-certificate the header carries; the new root's pin
// verifies what was signed under it and, for what the old root's chain signed, says so; an export of an
// instance that never rotated, with its single root, still verifies as it did.
func TestAuditExportAcrossRootRotation(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	leases := lease.New(db, "ctn_test", nil)
	at := time.Now()
	o := controller.CheckpointOptions{DB: db, CA: e.ca, Leases: leases, Now: func() time.Time { return at },
		Log: &audit.CheckpointLog{Path: filepath.Join(t.TempDir(), "audit-checkpoints.log")}}
	record := func(org string) {
		t.Helper()
		if _, err := audit.Record(context.Background(), db, audit.Entry{OrgID: org, ActorType: audit.ActorSystem, ActorID: "test", Action: "test.run",
			Result: audit.Success}); err != nil {
			t.Fatal(err)
		}
		if err := controller.FinalCheckpoints(e.sys, o); err != nil {
			t.Fatal(err)
		}
	}
	export := func(org string) []string {
		t.Helper()
		signers, inters, roots, err := castore.SignerCertificates(e.sys, db, pki.PurposeAuditCheckpoint)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		ctx := e.sys
		if org != "" {
			ctx = storetest.OrgCtx(t, org)
		}
		trust := audit.Trust{Root: roots[0], Roots: roots, Intermediates: inters, Signers: signers}
		if err := audit.Export(ctx, db, org, trust, at, func(l []byte) error { lines = append(lines, string(l)); return nil }); err != nil {
			t.Fatal(err)
		}
		return lines
	}
	verify := func(lines []string, r *x509.Certificate) error {
		_, err := audit.VerifyExport(strings.NewReader(strings.Join(lines, "\n")+"\n"), pki.RootPin(r))
		return err
	}
	r1 := e.ca.Root()
	record("")
	if err := verify(export(""), r1); err != nil {
		t.Fatalf("an export without a rotation: %v", err)
	}
	e.newRootOnline(t, at)
	r2 := e.ca.Root()
	at = at.Add(time.Minute)
	record("")
	if err := verify(export(""), r1); err != nil {
		t.Fatalf("an export across the switch, with the old root's pin: %v", err)
	}
	if err := verify(export(""), r2); err == nil {
		t.Fatal("what the old root's chain signed verified with the new root's pin alone")
	}

	co := controller.CAOptions{DB: db, CA: e.ca, Sealer: e.sealer, Leases: leases, Now: func() time.Time { return at }}
	at = at.Add(38 * rotationDay)
	if err := runOnce(t, leases, controller.CARotation(co)); err != nil {
		t.Fatal(err)
	}
	record("")
	if err := verify(export(""), r1); err != nil {
		t.Fatalf("an export across the drop, with the old root's pin: %v", err)
	}
	// A chain that began after the drop is signed under the new root alone, and verifies with its pin.
	org := storetest.Org(t, db, "org-x")
	record(org)
	if err := verify(export(org), r2); err != nil {
		t.Fatalf("an export of a chain signed under the new root, with the new root's pin: %v", err)
	}
	// Another root's pin is refused.
	other, err := pki.NewRoot("rpmgr-7f3k2q6m", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(export(""), other.Cert); !errors.Is(err, audit.ErrExportPin) {
		t.Fatalf("a pin of another root = %v, want ErrExportPin", err)
	}
}
