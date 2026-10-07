// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
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
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var errs []error
		go func() {
			leases.Run(ctx, controller.CARotation(o), func(err error) { errs = append(errs, err) })
			close(done)
		}()
		waitUntil(t, func() bool {
			return e.db.Client().Lease.Query().CountX(e.sys) > 0
		})
		time.Sleep(200 * time.Millisecond)
		cancel()
		<-done
		if len(errs) > 0 {
			t.Fatalf("job errors: %v", errs)
		}
	}
	run()
	if !e.ca.Intermediate().Equal(first) {
		t.Fatal("the intermediate was rotated before it was due")
	}
	at = first.NotBefore.Add(first.NotAfter.Sub(first.NotBefore)/2 + time.Hour)
	run()
	if e.ca.Intermediate().Equal(first) {
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
