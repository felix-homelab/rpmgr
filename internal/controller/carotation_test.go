// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestCARotation: the singleton job rotates the intermediate when it is due, records it in the
// audit log, and reloads the CA; nothing changes while it is not due.
func TestCARotation(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	leases := lease.New(db, "ctn_test", nil)
	first := e.ca.Intermediate()
	at := time.Now()
	o := controller.CAOptions{DB: db, CA: e.ca, Sealer: e.sealer, Leases: leases, Now: func() time.Time { return at }}
	run := func() {
		t.Helper()
		if err := runOnce(t, leases, controller.CARotation(o)); err != nil {
			t.Fatalf("job errors: %v", err)
		}
	}
	rotated := func() bool { return !e.ca.Intermediate().Equal(first) }
	run()
	if rotated() {
		t.Fatal("the intermediate was rotated before it was due")
	}
	at = first.NotBefore.Add(first.NotAfter.Sub(first.NotBefore)/2 + time.Hour)
	run()
	if !rotated() {
		t.Fatal("the intermediate was not rotated when it was due")
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("ca.rotate")).CountX(e.sys); n != 1 {
		t.Fatalf("%d audit records of the rotation", n)
	}
}

// TestCARotationOfflineRoot: with the root offline the job asks for a signature instead of signing,
// logs the need as a warning, and as an error from 30 days before the intermediate expires.
func TestCARotationOfflineRoot(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	plan, err := castore.PlanRootExport(e.sys, db.ReadClient().CAKey, e.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error {
		_, err := plan.Apply(e.sys, tx, "correct horse battery staple 42", func(f []byte) ([]byte, error) { return f, nil })
		return err
	}); err != nil {
		t.Fatal(err)
	}
	leases := lease.New(db, "ctn_test", nil)
	first := e.ca.Intermediate()
	var logs bytes.Buffer
	at := first.NotBefore.Add(first.NotAfter.Sub(first.NotBefore)/2 + time.Hour)
	o := controller.CAOptions{DB: db, CA: e.ca, Sealer: e.sealer, Leases: leases, Now: func() time.Time { return at },
		Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	run := func() {
		t.Helper()
		if err := runOnce(t, leases, controller.CARotation(o)); err != nil {
			t.Fatalf("job errors: %v", err)
		}
	}
	run()
	if !e.ca.Intermediate().Equal(first) {
		t.Fatal("the intermediate was replaced without a signature")
	}
	if !strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("log of the first run: %s", logs.String())
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("ca.rotate"), auditentry.Reason("intermediate needs signing")).CountX(e.sys); n != 1 {
		t.Fatalf("%d audit records of the request", n)
	}
	logs.Reset()
	at = first.NotAfter.Add(-30 * 24 * time.Hour)
	run()
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("log 30 days before expiry: %s", logs.String())
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("ca.rotate"), auditentry.Reason("intermediate needs signing")).CountX(e.sys); n != 1 {
		t.Fatalf("%d audit records of the request: it was made twice", n)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// runOnce runs job under leases until its Run has returned once, at most 10 s, then stops it. It
// returns the errors of that run and those the job reported. Stopping the job only after a whole
// run keeps a slow machine from cancelling the run, or the grant of its scope, half-way.
func runOnce(t *testing.T, leases *lease.Leases, job lease.Job) error {
	t.Helper()
	ran := make(chan struct{})
	var first error
	var once sync.Once
	inner := job.Run
	job.Run = func(ctx context.Context, l lease.Lease) error {
		err := inner(ctx, l)
		once.Do(func() { first = err; close(ran) })
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	var reported []error
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		leases.Run(ctx, job, func(err error) { reported = append(reported, err) })
	}()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Error("the job did not run within 10 s")
	}
	cancel()
	<-ended
	return errors.Join(append([]error{first}, reported...)...)
}

// TestCARotationSignedIntermediateNotValid: a signed next intermediate that is not valid when the
// schedule would activate it is not activated; the job logs it as an error at every run and writes
// no audit entry at each (it is no change), and IntermediateSigningAlert says so.
func TestCARotationSignedIntermediateNotValid(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	const pass = "correct horse battery staple 42"
	var file []byte
	plan, err := castore.PlanRootExport(e.sys, db.ReadClient().CAKey, e.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error {
		_, err := plan.Apply(e.sys, tx, pass, func(f []byte) ([]byte, error) { file = bytes.Clone(f); return f, nil })
		return err
	}); err != nil {
		t.Fatal(err)
	}
	root, err := pki.OpenRootFile(file, pass)
	if err != nil {
		t.Fatal(err)
	}
	var csr []byte
	first := e.ca.Intermediate()
	reqPlan, err := castore.PlanSigningRequest(e.sys, db.ReadClient().CAKey, e.sealer, first.NotBefore)
	if err != nil {
		t.Fatal(err)
	}
	csr = reqPlan.CSR()
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error {
		_, err := reqPlan.Apply(e.sys, tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Past the half-life, the offline host's clock being two hours ahead: the certificate it signed
	// is not valid yet, so the schedule does not activate it.
	at := first.NotBefore.Add(first.NotAfter.Sub(first.NotBefore)/2 + time.Hour)
	signedAt := at.Add(2 * time.Hour)
	cert, err := pki.SignIntermediate(root, csr, signedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error { return castore.ImportIntermediate(e.sys, tx, cert.Raw, signedAt) }); err != nil {
		t.Fatal(err)
	}
	leases := lease.New(db, "ctn_test", nil)
	var logs bytes.Buffer
	o := controller.CAOptions{DB: db, CA: e.ca, Sealer: e.sealer, Leases: leases, Now: func() time.Time { return at },
		Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	for range 3 {
		if err := runOnce(t, leases, controller.CARotation(o)); err != nil {
			t.Fatalf("job errors: %v", err)
		}
	}
	if n := strings.Count(logs.String(), "is not valid now and is not activated"); n != 3 || !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("%d error lines in %s", n, logs.String())
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("ca.rotate")).CountX(e.sys); n != 0 {
		t.Errorf("%d audit entries of a rotation that changed nothing", n)
	}
	if a, err := castore.IntermediateSigningAlert(e.sys, db, at); err != nil || a != castore.AlertNextNotValid {
		t.Errorf("alert %q %v", a, err)
	}
	if !e.ca.Intermediate().Equal(first) {
		t.Error("the intermediate that is not valid was activated")
	}
}
