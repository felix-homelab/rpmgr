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
	var n int
	if err := admin.Writer.QueryRow(`SELECT count(pg_terminate_backend(pid)) FROM pg_locks
		WHERE locktype = 'advisory' AND classid = 1919970663 AND objid = 2 AND granted
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ending the lock's session: %d %v", n, err)
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

// migratedPG makes a PostgreSQL database with the schema and an instance, and returns its DSN.
func migratedPG(t *testing.T) string {
	t.Helper()
	dsn := pgDSN(t)
	db, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
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
	return dsn
}

// TestPostgres_NewHolderEndsPreviousSessions (docs/06-data-model.md, "Connecting to PostgreSQL"):
// the controller that takes the lock ends the sessions of the one before it, so a transaction of
// that controller that is still open, as one held back by a stalled socket or a frozen process is,
// cannot commit after the new holder has started to write. The previous controller has not noticed
// the loss yet in this test, so only the server stops it.
func TestPostgres_NewHolderEndsPreviousSessions(t *testing.T) {
	dsn := migratedPG(t)
	prev, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prev.Close() }()
	admin, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	sys := storetest.SystemCtx(t)
	began, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- store.WriteTx(sys, prev, func(tx *ent.Tx) error {
			if err := tx.Org.Create().SetName("stale").SetSlug("stale").Exec(sys); err != nil {
				return err
			}
			close(began)
			<-release // the COMMIT is "on the wire"
			return nil
		})
	}()
	<-began
	// The previous controller's lock session goes (a partition ends it on the server); the new one
	// takes the lock and, as the exclusive holder, ends the other sessions of the previous one.
	if _, err := admin.Writer.Exec(`SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype = 'advisory' AND classid = 1919970663 AND objid = 2 AND granted
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`); err != nil {
		t.Fatal(err)
	}
	next, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatalf("the new holder: %v", err)
	}
	defer func() { _ = next.Close() }()
	close(release)
	if err := <-result; err == nil {
		t.Error("the previous controller's transaction committed after the new holder took over")
	}
	n, err := admin.Client().Org.Query().Where(org.Slug("stale")).Count(sys)
	if err != nil || n != 0 {
		t.Errorf("the stale write: %d %v", n, err)
	}
}

// TestPostgres_StaleEpochCannotCommit: the server refuses a write transaction of a controller
// that is not the one that claimed the database last, whenever it arrives; a claim waits for a
// transaction in flight instead of overtaking it, and does not go on when one does not end.
func TestPostgres_StaleEpochCannotCommit(t *testing.T) {
	dsn := migratedPG(t)
	ctx := context.Background()
	sys := storetest.SystemCtx(t)
	a, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if err := store.ClaimFence(ctx, a); err != nil {
		t.Fatal(err)
	}
	put := func(slug string) error {
		return store.WriteTx(sys, a, func(tx *ent.Tx) error { return tx.Org.Create().SetName(slug).SetSlug(slug).Exec(sys) })
	}
	if err := put("one"); err != nil {
		t.Fatalf("a write of the claiming controller: %v", err)
	}
	admin, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()

	// A claim by another controller waits for a transaction of a that is in flight, which then
	// commits; every later transaction of a fails.
	began, release := make(chan struct{}), make(chan struct{})
	inFlight := make(chan error, 1)
	go func() {
		inFlight <- store.WriteTx(sys, a, func(tx *ent.Tx) error {
			if err := tx.Org.Create().SetName("two").SetSlug("two").Exec(sys); err != nil {
				return err
			}
			close(began)
			<-release
			return nil
		})
	}()
	<-began
	bumped := make(chan error, 1)
	go func() {
		_, err := admin.Writer.Exec("UPDATE instance SET fence_epoch = fence_epoch + 1 WHERE id = 1")
		bumped <- err
	}()
	select {
	case err := <-bumped:
		t.Fatalf("the claim overtook a transaction in flight: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-inFlight; err != nil {
		t.Errorf("the transaction in flight: %v", err)
	}
	if err := <-bumped; err != nil {
		t.Fatal(err)
	}
	if err := put("three"); !errors.Is(err, store.ErrLockLost) {
		t.Errorf("a write after another controller claimed the database: %v, want ErrLockLost", err)
	}
	slugs, err := admin.Client().Org.Query().Select(org.FieldSlug).Strings(sys)
	if err != nil || len(slugs) != 2 {
		t.Errorf("orgs: %v %v, want one and two", slugs, err)
	}

	// A claim that finds a transaction that does not end refuses, and says so.
	store.SetClaimTimeout(t.Cleanup, 300*time.Millisecond)
	stuck, err := admin.Writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stuck.Rollback() }()
	if _, err := stuck.ExecContext(ctx, "SELECT 1 FROM instance WHERE id = 1 FOR SHARE"); err != nil {
		t.Fatal(err)
	}
	store.ResetClaim(a)
	if err := store.ClaimFence(ctx, a); err == nil || !strings.Contains(err.Error(), "cannot claim") {
		t.Errorf("a claim against a transaction that does not end: %v", err)
	}
}

// TestPostgres_ActiveNode: the node that runs the controller is recorded in the instance row.
func TestPostgres_ActiveNode(t *testing.T) {
	dsn := migratedPG(t)
	db, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	if id, err := store.ActiveNode(sys, db); err != nil || id != "" {
		t.Fatalf("a new database: %q %v", id, err)
	}
	if err := store.SetActiveNode(sys, db, "ctn_x"); err != nil {
		t.Fatal(err)
	}
	if id, err := store.ActiveNode(sys, db); err != nil || id != "ctn_x" {
		t.Errorf("after SetActiveNode: %q %v", id, err)
	}
}

// TestPostgres_PreviousSessionOfAnotherRole: a session of the controller before it that the new
// holder may see but not end stops the start with an error that says what to grant, instead of
// starting with the old session alive.
func TestPostgres_PreviousSessionOfAnotherRole(t *testing.T) {
	dsn := pgDSN(t)
	admin, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := u.Path[1:]
	suffix := db[len(db)-6:]
	old, holder := "rpmgr_old_"+suffix, "rpmgr_new_"+suffix
	for _, q := range []string{
		"CREATE ROLE " + old + " LOGIN PASSWORD 'low-entropy-1'",
		"CREATE ROLE " + holder + " LOGIN PASSWORD 'low-entropy-2'",
		"GRANT pg_read_all_stats TO " + holder, // sees the other's sessions, may not end them
		"GRANT CONNECT ON DATABASE " + db + " TO " + old + ", " + holder,
	} {
		if _, err := admin.Writer.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, r := range []string{old, holder} {
			_, _ = admin.Writer.Exec("DROP ROLE IF EXISTS " + r)
		}
	})
	as := func(role, pw string) string {
		c := *u
		c.User = url.UserPassword(role, pw)
		return c.String()
	}
	prev, err := storetest.OpenPostgres(t, as(old, "low-entropy-1"), store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prev.Close() }()
	if _, err := admin.Writer.Exec(`SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype = 'advisory' AND classid = 1919970663 AND objid = 2 AND granted
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`); err != nil {
		t.Fatal(err)
	}
	_, err = storetest.OpenPostgres(t, as(holder, "low-entropy-2"), store.PostgresOptions{Lock: true})
	if err == nil || !strings.Contains(err.Error(), "cannot end the sessions of the previous controller") {
		t.Errorf("a holder that may not end the previous sessions: %v", err)
	}
}

// TestPostgres_ReadOnlyTransactionsAfterClaim: the epoch check takes a row lock, which a read-only
// transaction cannot, so ReadTx (the snapshot compiler, the event stream, the audit sinks) skips it:
// after the claim reads work, and writes still check.
func TestPostgres_ReadOnlyTransactionsAfterClaim(t *testing.T) {
	dsn := migratedPG(t)
	a, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if err := store.ClaimFence(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err := store.ReadTx(storetest.SystemCtx(t), a, func(*ent.Tx, store.Revision) error { return nil }); err != nil {
		t.Errorf("ReadTx after the claim: %v", err)
	}
	if err := store.WriteTx(storetest.SystemCtx(t), a, func(*ent.Tx) error { return nil }); err != nil {
		t.Errorf("WriteTx after the claim: %v", err)
	}
}

// TestPostgres_AutocommitWritesAreFenced: a single Ent Create, Update or Delete, which Ent runs
// without a transaction of its own, goes through the epoch check as well: once another controller
// claimed the database it fails, and while the claim is ours it commits (also one that returns
// rows).
func TestPostgres_AutocommitWritesAreFenced(t *testing.T) {
	dsn := migratedPG(t)
	ctx := context.Background()
	sys := storetest.SystemCtx(t)
	a, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if err := store.ClaimFence(ctx, a); err != nil {
		t.Fatal(err)
	}
	admin, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	o, err := a.Client().Org.Create().SetName("auto").SetSlug("auto").Save(sys) // INSERT ... RETURNING
	if err != nil {
		t.Fatalf("an autocommit insert while the claim is ours: %v", err)
	}
	if n, err := admin.Client().Org.Query().Where(org.Slug("auto")).Count(sys); err != nil || n != 1 {
		t.Fatalf("the insert did not commit: %d %v", n, err)
	}
	if _, err := admin.Writer.Exec("UPDATE instance SET fence_epoch = fence_epoch + 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	for name, write := range map[string]func() error{
		"create": func() error { return a.Client().Org.Create().SetName("late").SetSlug("late").Exec(sys) },
		"create+ret": func() error {
			_, err := a.Client().Org.Create().SetName("late2").SetSlug("late2").Save(sys)
			return err
		},
		"update": func() error { return a.Client().Org.Update().Where(org.Slug("auto")).SetName("changed").Exec(sys) },
		"delete": func() error { return a.Client().Org.DeleteOneID(o.ID).Exec(sys) },
	} {
		if err := write(); !errors.Is(err, store.ErrLockLost) {
			t.Errorf("an autocommit %s after another controller claimed the database: %v, want ErrLockLost", name, err)
		}
	}
	slugs, err := admin.Client().Org.Query().Select(org.FieldSlug).Strings(sys)
	if err != nil || len(slugs) != 1 || slugs[0] != "auto" {
		t.Errorf("orgs: %v %v, want only the one written under our claim", slugs, err)
	}
	if n, _ := admin.Client().Org.Query().Where(org.Name("changed")).Count(sys); n != 0 {
		t.Error("the stale update committed")
	}
}

// TestPostgres_RetirementBumpsTheEpoch: migrate-db's retirement of a PostgreSQL source bumps the
// fence epoch in its own transaction, so a write transaction of a controller that queued before it
// and commits after it fails.
func TestPostgres_RetirementBumpsTheEpoch(t *testing.T) {
	dsn := migratedPG(t)
	ctx := context.Background()
	sys := storetest.SystemCtx(t)
	a, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if err := store.ClaimFence(ctx, a); err != nil {
		t.Fatal(err)
	}
	src, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	tx, err := store.BeginSource(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(sys, a, func(*ent.Tx) error { return nil }); !errors.Is(err, store.ErrLockLost) {
		t.Errorf("a write after the source's retirement transaction: %v, want ErrLockLost", err)
	}
}
