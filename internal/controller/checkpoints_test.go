// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
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
	signers, inters, root, err := pki.SignerCertificates(e.sys, db, pki.PurposeAuditCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	trust := audit.Trust{Root: root, Intermediates: inters, Signers: signers}
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
	signers, inters, root, err := pki.SignerCertificates(e.sys, db, pki.PurposeAuditCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	trust := audit.Trust{Root: root, Intermediates: inters, Signers: signers}
	before, _, err := audit.VerifyChain(e.sys, db, "", trust)
	if err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			leases.Run(ctx, controller.RetentionJob(o), func(err error) { t.Errorf("job: %v", err) })
			close(done)
		}()
		waitUntil(t, func() bool { return e.db.Client().Lease.Query().CountX(e.sys) > 0 })
		time.Sleep(200 * time.Millisecond)
		cancel()
		<-done
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
