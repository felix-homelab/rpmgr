// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const retiredTo = "/srv/rpmgr/to.yaml"

// retire sets retired_at and retired_to as `rpmgr migrate-db` will, on any open database.
func retire(t *testing.T, db *store.DB) {
	t.Helper()
	if _, err := db.Writer.Exec("UPDATE instance SET retired_at = CURRENT_TIMESTAMP, retired_to = '" + retiredTo + "'"); err != nil {
		t.Fatal(err)
	}
}

func retiredHost(t *testing.T) host {
	t.Helper()
	h, _ := initHost(t)
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retire(t, db)
	_ = db.Close()
	return h
}

// TestRetired_RefusedByLockFreeCommands: every command that opens the database without the
// controller lock, and a controller that starts on it, refuses a retired database and names where
// it went.
func TestRetired_RefusedByLockFreeCommands(t *testing.T) {
	ctx := context.Background()
	h := retiredHost(t)
	calls := map[string]func() error{
		"ca status":       func() error { _, err := controller.CAStatus(ctx, h.cfg); return err },
		"restore confirm": func() error { _, err := controller.ConfirmRestore(ctx, h.cfg, ""); return err },
		"reset-password":  func() error { _, err := controller.ResetPasswordLink(ctx, h.cfg, "a@example.com"); return err },
		"release import": func() error {
			_, err := controller.ImportRelease(ctx, h.cfg, t.TempDir(), "1.4.2", nil, time.Now)
			return err
		},
		"run": func() error {
			var cfg config.Controller
			if err := config.Load(h.cfg, &cfg); err != nil {
				return err
			}
			cfg.Listen.HTTPS, cfg.Listen.Admin = freeAddr(t), freeAddr(t)
			none := ""
			cfg.Listen.HTTP = &none
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return controller.Run(c, controller.RunOptions{Config: cfg, Getenv: noEnv, Listening: func() { t.Error("Run started on a retired database") }})
		},
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, controller.ErrRetired) || !strings.Contains(err.Error(), retiredTo) {
			t.Errorf("%s on a retired database: %v", name, err)
		}
	}
}

// TestRetired_WriteAfterCheck: a lock-free writer that waits for the write lock while another
// process retires the database finds it retired, or fails; its write never lands in it.
func TestRetired_WriteAfterCheck(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	holder, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	conn, err := holder.Writer.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	other, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{BusyTimeout: 10 * time.Second, RefuseRetired: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	done := make(chan error, 1)
	go func() {
		done <- store.WriteTx(storetest.SystemCtx(t), other, func(tx *ent.Tx) error {
			return tx.Instance.Update().SetDbEpoch("LOST").Exec(storetest.SystemCtx(t))
		})
	}()
	time.Sleep(300 * time.Millisecond) // it now waits for the write lock
	if _, err := conn.ExecContext(ctx, "UPDATE instance SET retired_at = CURRENT_TIMESTAMP, retired_to = '"+retiredTo+"'"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-done; err == nil {
		t.Error("a write that waited for the retirement committed into the retired database")
	}
	var epoch string
	if err := holder.Reader.QueryRow("SELECT db_epoch FROM instance").Scan(&epoch); err != nil || epoch == "LOST" {
		t.Errorf("the epoch is %q (%v)", epoch, err)
	}
}

// TestRetired_Retired: not retired, retired, a schema from before the columns, and a database that
// cannot be read, which is an error and never "not retired".
func TestRetired_Retired(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, retired, err := db.Retired(ctx); retired || err != nil {
		t.Errorf("a fresh database: retired %v, %v", retired, err)
	}
	retire(t, db)
	if _, to, retired, err := db.Retired(ctx); !retired || err != nil || to != retiredTo {
		t.Errorf("a retired database: %q, %v, %v", to, retired, err)
	}
	_ = db.Close()
	if _, _, retired, err := db.Retired(ctx); retired || err == nil {
		t.Errorf("a closed database: retired %v, %v; want an error", retired, err)
	}
	older := host{db: h.dir + "/older.db"}
	olderDatabase(t, older.db)
	odb, err := store.OpenSQLite(ctx, older.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = odb.Close() }()
	if _, _, retired, err := odb.Retired(ctx); retired || err != nil {
		t.Errorf("a schema without the columns: retired %v, %v", retired, err)
	}
}

// TestRetired_Postgres: the guard reads inside the write transaction on PostgreSQL too.
func TestRetired_Postgres(t *testing.T) {
	ctx := context.Background()
	dsn := storetest.NewPostgresDatabase(t)
	setup, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = setup.Close() })
	dir, err := migrations.Dir(store.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Migrate(ctx, setup, dir); err != nil {
		t.Fatal(err)
	}
	storetest.Init(t, setup)
	guarded, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{RefuseRetired: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guarded.Close() })
	write := func() error {
		return store.WriteTx(storetest.SystemCtx(t), guarded, func(tx *ent.Tx) error {
			return tx.Instance.Update().SetDbEpoch("x").Exec(storetest.SystemCtx(t))
		})
	}
	if err := write(); err != nil {
		t.Fatalf("a write to a database that is not retired: %v", err)
	}
	if _, err := setup.Writer.Exec("UPDATE instance SET retired_at = now(), retired_to = '" + retiredTo + "'"); err != nil {
		t.Fatal(err)
	}
	if err := write(); !errors.Is(err, store.ErrRetired) || !strings.Contains(err.Error(), retiredTo) {
		t.Errorf("a write to a retired database: %v", err)
	}
}

// TestRetired_ConfigTx: a configuration transaction of a guarded connection checks too.
func TestRetired_ConfigTx(t *testing.T) {
	ctx := context.Background()
	h := retiredHost(t)
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{RefuseRetired: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ran := false
	_, err = store.ConfigTx(storetest.SystemCtx(t), db, func(*ent.Tx) ([]string, error) { ran = true; return nil, nil })
	if !errors.Is(err, store.ErrRetired) || ran {
		t.Errorf("a configuration transaction on a retired database: %v (ran %v)", err, ran)
	}
}

// TestRetired_PostgresShareLock: on PostgreSQL the check takes a share lock on the instance row, so
// a retirement waits for a write that has checked, and that write commits before the database is
// retired.
func TestRetired_PostgresShareLock(t *testing.T) {
	ctx := context.Background()
	dsn := storetest.NewPostgresDatabase(t)
	setup, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = setup.Close() })
	dir, err := migrations.Dir(store.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Migrate(ctx, setup, dir); err != nil {
		t.Fatal(err)
	}
	storetest.Init(t, setup)
	guarded, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{RefuseRetired: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guarded.Close() })

	inside, release, written := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		written <- store.WriteTx(storetest.SystemCtx(t), guarded, func(tx *ent.Tx) error {
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	retired := make(chan error, 1)
	go func() {
		_, err := setup.Writer.Exec("UPDATE instance SET retired_at = now(), retired_to = '" + retiredTo + "'")
		retired <- err
	}()
	select {
	case err := <-retired:
		t.Fatalf("the retirement did not wait for the write that had checked: %v", err)
	case <-time.After(700 * time.Millisecond):
	}
	close(release)
	if err := <-written; err != nil {
		t.Errorf("the write that had checked: %v", err)
	}
	if err := <-retired; err != nil {
		t.Errorf("the retirement: %v", err)
	}
}
