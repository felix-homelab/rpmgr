// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
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
