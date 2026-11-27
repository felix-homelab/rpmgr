// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// endLockSession ends the session that holds the controller lock, as a network failure or a
// restarted server does, and waits until db knows.
func endLockSession(t *testing.T, admin *store.DB, db *store.DB) {
	t.Helper()
	if _, err := admin.Writer.Exec(`SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype = 'advisory' AND classid = 1919970663 AND objid = 2 AND granted`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-db.LockLost():
	case <-time.After(10 * time.Second):
		t.Fatal("LockLost was not closed after the lock's session ended")
	}
}

// TestPostgres_NoWriteAfterLockLost (docs/06-data-model.md, "Connecting to PostgreSQL"): from the
// moment a controller knows it lost the lock, no write of any kind commits: not an API request's
// transaction, not a job's, not an Ent mutation outside a transaction helper, not a migration, and
// not a transaction that began before the loss and commits after it.
func TestPostgres_NoWriteAfterLockLost(t *testing.T) {
	store.SetLockCheckInterval(t.Cleanup, 50*time.Millisecond)
	dsn := pgDSN(t)
	db, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	dir, err := migrations.Dir(store.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Migrate(context.Background(), db, dir); err != nil {
		t.Fatal(err)
	}
	storetest.Init(t, db)
	admin, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{}) // no lock: it is not fenced
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	sys := storetest.SystemCtx(t)
	create := func(tx *ent.Tx, slug string) error { return tx.Org.Create().SetName(slug).SetSlug(slug).Exec(sys) }
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { return create(tx, "before") }); err != nil {
		t.Fatalf("a write while the lock is held: %v", err)
	}

	// A transaction that began before the loss and commits after it.
	inFlight := make(chan error, 1)
	lostSeen := make(chan struct{})
	began := make(chan struct{})
	go func() {
		inFlight <- store.WriteTx(sys, db, func(tx *ent.Tx) error {
			if err := create(tx, "in-flight"); err != nil {
				return err
			}
			close(began)
			<-lostSeen
			return nil
		})
	}()
	<-began
	endLockSession(t, admin, db)
	close(lostSeen)
	if err := <-inFlight; !errors.Is(err, store.ErrLockLost) {
		t.Errorf("a transaction that commits after the loss: %v, want ErrLockLost", err)
	}

	for name, write := range map[string]func() error{
		"an API write (ConfigTx)": func() error {
			_, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) { return []string{"org"}, create(tx, "config") })
			return err
		},
		"a job's write (WriteTx)": func() error {
			return store.WriteTx(sys, db, func(tx *ent.Tx) error { return create(tx, "job") })
		},
		"a mutation outside the helpers": func() error {
			return db.Client().Org.Create().SetName("direct").SetSlug("direct").Exec(sys)
		},
		"raw SQL": func() error {
			_, err := db.Client().ExecContext(sys, "UPDATE orgs SET name = 'x'")
			return err
		},
		"a migration": func() error {
			_, err := store.Migrate(context.Background(), db, dir)
			return err
		},
	} {
		if err := write(); !errors.Is(err, store.ErrLockLost) {
			t.Errorf("%s after the loss: %v, want ErrLockLost", name, err)
		}
	}
	// Nothing of it is in the database.
	slugs, err := admin.Client().Org.Query().Select(org.FieldSlug).Strings(sys)
	if err != nil {
		t.Fatal(err)
	}
	if len(slugs) != 1 || slugs[0] != "before" {
		t.Errorf("orgs after the loss: %v, want only the one written before it", slugs)
	}
}

// TestPostgres_LockSurvivesIdleSession (docs/12-testing-and-quality.md, "Database tests"): the
// lock's connection is made with idle_session_timeout 0, so a server that ends idle sessions
// quickly does not end it, while the pool's connections are not so protected.
func TestPostgres_LockSurvivesIdleSession(t *testing.T) {
	store.SetLockCheckInterval(t.Cleanup, 3*time.Second) // longer than the server's timeout
	dsn := pgDSN(t)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	if _, err := admin.Writer.Exec(`ALTER DATABASE ` + u.Path[1:] + ` SET idle_session_timeout = '1s'`); err != nil {
		t.Fatal(err)
	}
	db, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	select {
	case <-db.LockLost():
		t.Fatal("the lock's connection was ended for being idle")
	case <-time.After(7 * time.Second):
	}
}

// TestMigrate_WaitForLockIsBounded: a migrator that finds the migration lock held for longer than
// the wait of docs/03-connections.md gives up and says so, instead of waiting for ever.
func TestMigrate_WaitForLockIsBounded(t *testing.T) {
	store.SetMigrationLockWait(t.Cleanup, 300*time.Millisecond)
	dsn := pgDSN(t)
	db, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	holder, err := db.Writer.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if _, err := holder.ExecContext(context.Background(), "SELECT pg_advisory_lock(1919970663, 1)"); err != nil {
		t.Fatal(err)
	}
	dir, err := migrations.Dir(store.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = store.Migrate(context.Background(), db, dir)
	if err == nil || !strings.Contains(err.Error(), "migration lock") || !strings.Contains(err.Error(), "held it for more than") {
		t.Fatalf("Migrate with the lock held elsewhere: %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("Migrate waited %s with a wait of 300 ms", d)
	}
}
