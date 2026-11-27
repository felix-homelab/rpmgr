// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// pgController is an initialised controller that runs on PostgreSQL: a SQLite host, copied into an
// empty PostgreSQL database, with the host's state directory as the PostgreSQL controller's.
type pgController struct {
	migrateHost
	boot, dsn string
	state     string
}

func newPGController(t *testing.T) pgController {
	t.Helper()
	src := newMigrateHost(t)
	boot, dsn := pgDatabase(t)
	if _, err := migrateDB(src.cfg, boot, true); err != nil {
		t.Fatal(err)
	}
	state := filepath.Dir(src.db)
	controller.SetStateDir(t, state)
	controller.SetLockSettle(t, 0)
	hostNodeID(t, state)
	// A revocation log and audit checkpoints, so that a test of what a restore leaves alone has
	// files to compare.
	writeLog(t, state, 2)
	if err := os.WriteFile(filepath.Join(state, "audit-checkpoints.log"), []byte("checkpoint-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return pgController{migrateHost: src, boot: boot, dsn: dsn, state: state}
}

// hostNodeID gives state a node ID if it has none: the file that makes a host the controller host,
// which a PostgreSQL backup needs.
func hostNodeID(t *testing.T, state string) {
	t.Helper()
	path := filepath.Join(state, "controller-node.id")
	if _, err := os.Stat(path); err != nil {
		if err := os.WriteFile(path, []byte(ids.New("ctn")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (c pgController) revlog() string { return filepath.Join(c.state, "revocations.log") }

func (c pgController) logs() []string { return []string{c.revlog()} }

func (c pgController) backup(t *testing.T, out string) (controller.BackupInfo, error) {
	t.Helper()
	return controller.Backup(context.Background(), c.boot, out, "2.0.0", time.Now)
}

// archiveDB opens the database of an archive.
func archiveDB(t *testing.T, files map[string][]byte) *store.DB {
	t.Helper()
	p := filepath.Join(t.TempDir(), "archive.db")
	if err := os.WriteFile(p, files[controller.BackupDatabase], 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLite(context.Background(), p, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func countRows(t *testing.T, db *store.DB, table, where string) int {
	t.Helper()
	var n int
	if err := db.Reader.QueryRowContext(context.Background(), "SELECT count(*) FROM "+table+" WHERE "+where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func tableCount(t *testing.T, boot string) int {
	t.Helper()
	var n int
	if err := openBoot(t, boot).Reader.QueryRowContext(context.Background(),
		"SELECT count(*) FROM pg_tables WHERE schemaname = current_schema()").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// stateDigest describes the files of a state directory other than the SQLite database, which a
// PostgreSQL controller has none of, by name and content hash.
func stateDigest(t *testing.T, dir string) string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range es {
		if e.IsDir() || strings.HasPrefix(e.Name(), "controller.db") {
			continue
		}
		fmt.Fprintf(&b, "%s:%x;", e.Name(), sha256.Sum256([]byte(fileBytes(t, filepath.Join(dir, e.Name())))))
	}
	return b.String()
}

// writeLog writes a revocation log of n entries to the state directory's file and returns it.
func writeLog(t *testing.T, state string, n int) string {
	t.Helper()
	path := filepath.Join(state, "revocations.log")
	rl, err := revlog.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := rl.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: fmt.Sprintf("ses_%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	return fileBytes(t, path)
}

func fileBytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}

// TestBackupPostgres: the archive of a PostgreSQL controller holds a SQLite copy with the same
// installation and the source's sealed values byte for byte, both logs without a line still being
// written, and backup.json naming PostgreSQL; the command leaves nothing behind, never overwrites
// and fails without an archive when the database cannot be read.
func TestBackupPostgres(t *testing.T) {
	c := newPGController(t)
	full := writeLog(t, c.state, 2)
	if err := os.WriteFile(filepath.Join(c.state, "revocations.log"), []byte(full+"{\"seq\":3, half"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "rpmgr.backup")
	info, err := c.backup(t, out)
	if err != nil {
		t.Fatal(err)
	}
	if info.SourceDialect != "postgres" || info.Format != 1 || info.DBEpoch == "" || info.TrustDomain == "" {
		t.Errorf("info %+v", info)
	}
	files := untar(t, out)
	if string(files[controller.BackupRevocations]) != full {
		t.Errorf("revocation log %q", files[controller.BackupRevocations])
	}
	if _, ok := files[controller.BackupCheckpoints]; !ok {
		t.Error("no audit checkpoints, even an empty file")
	}
	got := archiveDB(t, files)
	if got.Dialect != store.SQLite {
		t.Errorf("the archive's database is %s", got.Dialect)
	}
	want, have := sealedValues(t, openBoot(t, c.boot)), sealedValues(t, got)
	if len(want) == 0 || fmt.Sprint(want) != fmt.Sprint(have) {
		t.Errorf("sealed values differ:\nsource %v\narchive %v", want, have)
	}
	for _, v := range have {
		for _, s := range v {
			if strings.Contains(s, canary) {
				t.Error("the canary is in the archive in the clear")
			}
		}
	}
	if inst := got.Client().Instance.GetX(storetest.SystemCtx(t), 1); inst.DbEpoch != info.DBEpoch || inst.TrustDomain != info.TrustDomain {
		t.Errorf("the copy's installation %+v", inst)
	}
	if left, _ := filepath.Glob(filepath.Join(c.state, ".backup-*")); len(left) > 0 {
		t.Errorf("the backup left %v", left)
	}
	before := fileBytes(t, out)
	if _, err := c.backup(t, out); !errors.Is(err, os.ErrExist) {
		t.Errorf("an existing archive: %v", err)
	}
	if fileBytes(t, out) != before {
		t.Error("an existing archive was changed")
	}

	// A database that cannot be read leaves no archive and no work file.
	missing := filepath.Join(t.TempDir(), "boot.yaml")
	body := "version: 1\ndatabase:\n  driver: postgres\n  dsn: postgres://nobody@127.0.0.1:1/none?sslmode=disable\n"
	if err := os.WriteFile(missing, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := filepath.Join(t.TempDir(), "failed.backup")
	if _, err := controller.Backup(context.Background(), missing, failed, "2.0.0", time.Now); err == nil {
		t.Error("an unreachable database")
	}
	if _, err := os.Lstat(failed); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed backup left its archive: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(c.state, ".backup-*")); len(left) > 0 {
		t.Errorf("a failed backup left %v", left)
	}
}

// TestBackupPostgres_Retired: a database that migrate-db has retired is no controller's; no
// archive of it is written.
func TestBackupPostgres_Retired(t *testing.T) {
	src := newMigrateHost(t)
	boot, _ := pgDatabase(t)
	if _, err := migrateDB(src.cfg, boot, true); err != nil {
		t.Fatal(err)
	}
	// Retire the PostgreSQL database by moving it on to a SQLite file.
	if _, err := migrateDB(boot, sqliteBoot(t, filepath.Join(t.TempDir(), "back.db")), false); err != nil {
		t.Fatal(err)
	}
	controller.SetStateDir(t, filepath.Dir(src.db))
	hostNodeID(t, filepath.Dir(src.db))
	writeLog(t, filepath.Dir(src.db), 1)
	out := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := controller.Backup(context.Background(), boot, out, "2.0.0", time.Now); !errors.Is(err, controller.ErrRetired) {
		t.Errorf("a retired database: %v", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused backup left its archive: %v", err)
	}
}

// TestBackupPostgres_ConsistentUnderWrites: a writer commits pairs of rows of two tables in single transactions
// without pause while backups run. Every archive holds whole pairs only: one snapshot, one
// revision, though the copy takes many statements. The controller is not stopped and the writer
// is never refused.
func TestBackupPostgres_ConsistentUnderWrites(t *testing.T) {
	c := newPGController(t)
	pg := openBoot(t, c.boot)
	ctx, stop := context.WithCancel(context.Background())
	var pairs atomic.Int64
	done := make(chan error, 1)
	go func() {
		for i := 0; ctx.Err() == nil; i++ {
			tx, err := pg.Writer.BeginTx(ctx, nil)
			if err != nil {
				if ctx.Err() == nil {
					done <- err
					return
				}
				break
			}
			// Two tables, which the copier reads one after the other, so a copy without one snapshot
			// holds more of one than of the other.
			_, err = tx.ExecContext(ctx, "INSERT INTO instance_secrets (name, value_enc, updated_at) VALUES ($1, $2, now())",
				fmt.Sprintf("pair-%d", i), []byte{byte(i)})
			if err == nil {
				_, err = tx.ExecContext(ctx, "INSERT INTO instance_settings (value, version, updated_by, updated_at) VALUES ($1, $2, 'pair', now())",
					[]byte{byte(i)}, i)
			}
			if err != nil {
				_ = tx.Rollback()
			}
			if err == nil {
				err = tx.Commit()
			}
			if err != nil {
				if ctx.Err() == nil {
					done <- err
					return
				}
				break
			}
			pairs.Add(1)
		}
		done <- nil
	}()
	for pairs.Load() < 20 {
		time.Sleep(5 * time.Millisecond)
	}
	var sizes []int
	for i := range 8 {
		out := filepath.Join(t.TempDir(), "rpmgr.backup")
		if _, err := c.backup(t, out); err != nil {
			t.Fatal(err)
		}
		db := archiveDB(t, untar(t, out))
		a, b := countRows(t, db, "instance_secrets", "name LIKE 'pair-%'"), countRows(t, db, "instance_settings", "updated_by = 'pair'")
		if a != b {
			t.Errorf("backup %d holds %d secrets and %d settings of the pairs: not one snapshot", i, a, b)
		}
		sizes = append(sizes, a)
		start := pairs.Load()
		for pairs.Load() < start+5 { // the writer goes on between backups
			time.Sleep(5 * time.Millisecond)
		}
	}
	stop()
	if err := <-done; err != nil {
		t.Fatalf("the writer was refused: %v", err)
	}
	if sizes[0] == 0 || sizes[len(sizes)-1] <= sizes[0] {
		t.Errorf("rows per backup %v: the writer did not run alongside", sizes)
	}
}

// restoreInto restores archive into a new, empty PostgreSQL database and returns its boot file.
func restoreInto(t *testing.T, archive string, logs ...string) (string, controller.RestoreResult) {
	t.Helper()
	boot, _ := pgDatabase(t)
	res, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: archive, RevocationLogs: logs})
	if err != nil {
		t.Fatal(err)
	}
	return boot, res
}

// TestRestorePostgres: an archive, from either dialect, restores into an empty PostgreSQL database
// with a new db_epoch each time, the sealed values byte for byte, the restore's own audit entry,
// and the logs in place with the replaced ones kept.
func TestRestorePostgres(t *testing.T) {
	c := newPGController(t)
	logged := writeLog(t, c.state, 1)
	fromPG := filepath.Join(t.TempDir(), "pg.backup")
	info, err := c.backup(t, fromPG)
	if err != nil {
		t.Fatal(err)
	}
	fromSQLite := filepath.Join(t.TempDir(), "sqlite.backup")
	if _, err := controller.Backup(context.Background(), c.cfg, fromSQLite, "2.0.0", time.Now); err != nil {
		t.Fatal(err)
	}
	want := sealedValues(t, openBoot(t, c.boot))
	epochs := map[string]bool{info.DBEpoch: true}
	for name, archive := range map[string]string{"from postgres": fromPG, "from sqlite": fromSQLite, "again": fromPG} {
		t.Run(name, func(t *testing.T) {
			boot, res := restoreInto(t, archive, c.revlog())
			if res.NewEpoch == "" || epochs[res.NewEpoch] {
				t.Errorf("the epoch %q after the restore is one that was used: %v", res.NewEpoch, epochs)
			}
			epochs[res.NewEpoch] = true
			if res.Dialect != "postgres" {
				t.Errorf("the result's dialect %q", res.Dialect)
			}
			if res.OldEpoch != info.DBEpoch || res.TrustDomain != info.TrustDomain || res.Previous == "" {
				t.Errorf("result %+v", res)
			}
			db := openBoot(t, boot)
			inst := db.Client().Instance.GetX(storetest.SystemCtx(t), 1)
			if inst.DbEpoch != res.NewEpoch || inst.TrustDomain != info.TrustDomain {
				t.Errorf("the restored installation %+v", inst)
			}
			if have := sealedValues(t, db); fmt.Sprint(have) != fmt.Sprint(want) {
				t.Errorf("sealed values differ after the restore:\nwant %v\nhave %v", want, have)
			}
			if r := localReasons(t, db, "instance.restore"); len(r) != 1 || !strings.Contains(r[0], "epoch "+info.DBEpoch) {
				t.Errorf("the restore's audit entry: %q", r)
			}
			if fileBytes(t, filepath.Join(c.state, "revocations.log"+res.Previous)) != logged {
				t.Errorf("the replaced log was not kept")
			}
			if fileBytes(t, filepath.Join(c.state, "revocations.log")) != logged {
				t.Errorf("the restored log is not the archive's")
			}
			if db.Client().Instance.GetX(storetest.SystemCtx(t), 1).RestoreReviewSince != nil && len(res.Review) == 0 {
				t.Error("restore review without a reason")
			}
		})
	}
}

// TestRestorePostgres_Running: while a controller holds the target database's lock, shared as a
// replica or exclusive, the restore is refused and changes nothing; when it stops, it succeeds.
func TestRestorePostgres_Running(t *testing.T) {
	c := newPGController(t)
	archive := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := c.backup(t, archive); err != nil {
		t.Fatal(err)
	}
	before := stateDigest(t, c.state)
	boot, _ := pgDatabase(t)
	d, err := config.LoadDatabase(boot)
	if err != nil {
		t.Fatal(err)
	}
	for _, shared := range []bool{false, true} {
		running, err := store.OpenPostgres(context.Background(), d.DSN, store.PostgresOptions{PasswordFile: d.PasswordFile, Lock: true, Shared: shared})
		if err != nil {
			t.Fatal(err)
		}
		_, err = controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: archive, RevocationLogs: c.logs()})
		_ = running.Close()
		if !errors.Is(err, controller.ErrControllerRunning) {
			t.Errorf("with a controller running (shared %v): %v", shared, err)
		}
		if n := tableCount(t, boot); n != 0 {
			t.Errorf("a refused restore left %d tables", n)
		}
		if stateDigest(t, c.state) != before {
			t.Error("a refused restore changed the state directory")
		}
		if left, _ := filepath.Glob(filepath.Join(c.state, "*.before-restore-*")); len(left) > 0 {
			t.Errorf("a refused restore moved %v aside", left)
		}
	}
	if _, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: archive, RevocationLogs: c.logs()}); err != nil {
		t.Errorf("with the controller stopped: %v", err)
	}
}

// TestRestorePostgres_FailureChangesNothing: a restore that fails before, while or after the copy
// leaves the database without a row and the state directory as it was.
func TestRestorePostgres_FailureChangesNothing(t *testing.T) {
	c := newPGController(t)
	archive := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := c.backup(t, archive); err != nil {
		t.Fatal(err)
	}
	stateBefore := stateDigest(t, c.state)
	assertUnchanged := func(t *testing.T, boot string) {
		t.Helper()
		db := openBoot(t, boot)
		var rows int
		if err := db.Reader.QueryRowContext(context.Background(), "SELECT count(*) FROM instance").Scan(&rows); err != nil && !strings.Contains(err.Error(), "does not exist") {
			t.Fatal(err)
		}
		if rows != 0 {
			t.Errorf("the failed restore left %d installations", rows)
		}
		if now := stateDigest(t, c.state); now != stateBefore {
			t.Errorf("the state directory changed:\nbefore %s\nafter  %s", stateBefore, now)
		}
	}
	restore := func(boot, archive string) error {
		_, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: archive, RevocationLogs: c.logs()})
		return err
	}

	t.Run("not an archive", func(t *testing.T) {
		boot, _ := pgDatabase(t)
		bad := filepath.Join(t.TempDir(), "bad")
		if err := os.WriteFile(bad, []byte("neither a tar file\nnor a log\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := restore(boot, bad); err == nil || !strings.Contains(err.Error(), "not a backup archive") {
			t.Errorf("not an archive: %v", err)
		}
		assertUnchanged(t, boot)
	})
	t.Run("target holds a copy", func(t *testing.T) {
		boot, _ := pgDatabase(t)
		if _, err := migrateDB(c.cfg, boot, true); err != nil {
			t.Fatal(err)
		}
		if err := restore(boot, archive); !errors.Is(err, store.ErrTargetNotEmpty) {
			t.Errorf("a target with rows: %v", err)
		}
		if n := countRows(t, openBoot(t, boot), "instance", "true"); n != 1 {
			t.Errorf("the target's installation was touched: %d rows", n)
		}
		if got := localReasons(t, openBoot(t, boot), "instance.restore"); len(got) != 0 {
			t.Errorf("the refused restore left %v", got)
		}
		if left, _ := filepath.Glob(filepath.Join(c.state, "*.before-restore-*")); len(left) > 0 {
			t.Errorf("a refused restore moved %v aside", left)
		}
	})
	t.Run("copy fails midway", func(t *testing.T) {
		boot, _ := pgDatabase(t)
		pg := openBoot(t, boot)
		controller.OnRestoreStep(t, func(step string) {
			if step != "copying to postgres" {
				return
			}
			// The target is made to refuse a row of a table the copier fills late.
			for _, q := range []string{
				`CREATE FUNCTION refuse_rows() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$`,
				`CREATE TRIGGER refuse BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION refuse_rows()`} {
				if _, err := pg.Writer.Exec(q); err != nil {
					t.Error(err)
				}
			}
		})
		if err := restore(boot, archive); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("a copy that fails: %v", err)
		}
		for _, table := range []string{"instance", "users", "ca_keys", "audit_log"} {
			if n := countRows(t, pg, table, "true"); n != 0 {
				t.Errorf("the failed copy left %d rows in %s", n, table)
			}
		}
		assertUnchanged(t, boot)
	})
	t.Run("interrupted before the copy", func(t *testing.T) {
		boot, _ := pgDatabase(t)
		ctx, cancel := context.WithCancel(context.Background())
		controller.OnRestoreStep(t, func(step string) {
			if step == "copying to postgres" {
				cancel()
			}
		})
		_, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: boot, Archive: archive, RevocationLogs: c.logs()})
		if err == nil {
			t.Fatal("a cancelled restore succeeded")
		}
		assertUnchanged(t, boot)
	})
}

// TestRestorePostgres_RootMarker: the offline-root marker of the revocation log is applied again by
// a restore into PostgreSQL, as into SQLite: the archive's database still holds the root's key, the
// restored one does not.
func TestRestorePostgres_RootMarker(t *testing.T) {
	ctx := context.Background()
	c := newPGController(t)
	root := openBoot(t, c.boot).Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(storetest.SystemCtx(t))
	hash := pki.PublicKeyHash(root.PublicKey)
	rl, err := revlog.Open(filepath.Join(c.state, "revocations.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rl.Append(revlog.Entry{Kind: revlog.RootOffline, Subject: hash, Detail: "0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "mid-ceremony.backup")
	if _, err := c.backup(t, archive); err != nil {
		t.Fatal(err)
	}
	keyHeld := func(db *store.DB) bool {
		var held bool
		if err := db.Reader.QueryRowContext(ctx, "SELECT key_enc IS NOT NULL AND length(key_enc) > 0 FROM ca_keys WHERE kind = 'root'").Scan(&held); err != nil {
			t.Fatal(err)
		}
		return held
	}
	if !keyHeld(archiveDB(t, untar(t, archive))) {
		t.Fatal("the premise: the archive's database holds the key")
	}
	boot, res := restoreInto(t, archive, c.revlog())
	if len(res.RootKeysDropped) != 1 || res.RootKeysDropped[0] != hash {
		t.Errorf("result %+v", res)
	}
	if keyHeld(openBoot(t, boot)) {
		t.Error("the root is online after the restore")
	}
}

// TestRestorePostgres_Replaces: --replaces names the database the restore takes the place of. A
// controller running on it, shared or exclusive, makes the restore refuse and change nothing; the
// target is no valid --replaces; one that migrate-db retired is reported; a file that is no
// database is an error.
func TestRestorePostgres_Replaces(t *testing.T) {
	ctx := context.Background()
	c := newPGController(t)
	archive := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := c.backup(t, archive); err != nil {
		t.Fatal(err)
	}
	log := stateDigest(t, c.state)
	restore := func(boot, replaces string) (controller.RestoreResult, error) {
		return controller.Restore(ctx, controller.RestoreOptions{ConfigPath: boot, Archive: archive, RevocationLogs: c.logs(), Replaces: replaces})
	}
	d, err := config.LoadDatabase(c.boot)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := pgDatabase(t)
	for _, shared := range []bool{false, true} {
		running, err := store.OpenPostgres(ctx, d.DSN, store.PostgresOptions{PasswordFile: d.PasswordFile, Lock: true, Shared: shared})
		if err != nil {
			t.Fatal(err)
		}
		_, err = restore(target, c.boot)
		_ = running.Close()
		if !errors.Is(err, controller.ErrControllerRunning) || !strings.Contains(err.Error(), "--replaces") {
			t.Errorf("with a controller on the replaced database (shared %v): %v", shared, err)
		}
		if n := tableCount(t, target); n != 0 {
			t.Errorf("a refused restore left %d tables", n)
		}
	}
	if _, err := restore(target, target); !errors.Is(err, controller.ErrSameDatabase) {
		t.Errorf("the target as --replaces: %v", err)
	}
	if _, err := restore(target, filepath.Join(t.TempDir(), "none.yaml")); err == nil {
		t.Error("a missing boot file as --replaces")
	}
	if stateDigest(t, c.state) != log {
		t.Error("a refused restore changed the state directory")
	}
	res, err := restore(target, c.boot)
	if err != nil || res.ReplacesRetired != "" {
		t.Fatalf("the stopped, live database: %+v %v", res, err)
	}

	// A database that migrate-db moved on is reported, and the restore still goes ahead.
	other, _ := pgDatabase(t)
	if _, err := migrateDB(c.cfg, other, true); err != nil {
		t.Fatal(err)
	}
	moved := sqliteBoot(t, filepath.Join(t.TempDir(), "moved.db"))
	if _, err := migrateDB(other, moved, false); err != nil {
		t.Fatal(err)
	}
	fresh, _ := pgDatabase(t)
	res, err = restore(fresh, other)
	if err != nil || res.ReplacesRetired != moved {
		t.Errorf("a retired database: %q %v, want %q", res.ReplacesRetired, err, moved)
	}
}

// rewriteArchive writes a new archive of the files of an old one, changed by edit.
func rewriteArchive(t *testing.T, archive string, edit func(files map[string][]byte)) string {
	t.Helper()
	files := untar(t, archive)
	edit(files)
	out := filepath.Join(t.TempDir(), "edited.backup")
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(tw.Close(), f.Close()); err != nil {
		t.Fatal(err)
	}
	return out
}

// retiredArchive is archive with its database marked as retired by migrate-db.
func retiredArchive(t *testing.T, archive string) string {
	return rewriteArchive(t, archive, func(files map[string][]byte) {
		p := filepath.Join(t.TempDir(), "retired.db")
		if err := os.WriteFile(p, files[controller.BackupDatabase], 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := store.OpenSQLite(context.Background(), p, store.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Writer.Exec("UPDATE instance SET retired_at = ?, retired_to = ?", time.Now().UTC(), "/etc/rpmgr/elsewhere.yaml"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		files[controller.BackupDatabase] = []byte(fileBytes(t, p))
	})
}

// TestBackup_StagingIsPrivate: the backup stages its copy in a private directory of its own, not
// in the state directory, and reads and removes it through a handle on that directory by the names
// it made. When the directory is replaced by a link to another one meanwhile, the files of that
// one are neither read nor removed, for either dialect.
func TestBackup_StagingIsPrivate(t *testing.T) {
	c := newPGController(t)
	for name, boot := range map[string]string{"sqlite": c.cfg, "postgres": c.boot} {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.Mkdir(victim, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{"controller.db", "work.db", "keep.txt"} {
				if err := os.WriteFile(filepath.Join(victim, n), []byte("not the backup's: "+n), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var staged string
			controller.OnBackupStep(t, func(step, dir string) {
				if step != "snapshotted" {
					return
				}
				staged = dir
				if filepath.Dir(dir) != tmp {
					t.Errorf("the staging directory %s is not under the temporary directory %s", dir, tmp)
				}
				if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
					t.Errorf("the staging directory: %v %v", st, err)
				}
				if err := os.Rename(dir, dir+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, dir); err != nil {
					t.Fatal(err)
				}
			})
			out := filepath.Join(t.TempDir(), "rpmgr.backup")
			info, err := controller.Backup(context.Background(), boot, out, "2.0.0", time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if staged == "" {
				t.Fatal("the hook did not run")
			}
			db := archiveDB(t, untar(t, out))
			if inst := db.Client().Instance.GetX(storetest.SystemCtx(t), 1); inst.TrustDomain != info.TrustDomain {
				t.Errorf("the archive holds %+v, not the copy of the database", inst)
			}
			for _, n := range []string{"controller.db", "work.db", "keep.txt"} {
				if got := fileBytes(t, filepath.Join(victim, n)); got != "not the backup's: "+n {
					t.Errorf("%s of the other directory is now %q", n, got)
				}
			}
			if left, _ := filepath.Glob(filepath.Join(c.state, ".backup-*")); len(left) > 0 {
				t.Errorf("the state directory holds %v", left)
			}
			if es, _ := os.ReadDir(staged + ".moved"); len(es) > 0 {
				t.Errorf("the staging directory still holds %d files", len(es))
			}
		})
	}
}

// TestBackup_RetiredMeanwhile: a database that was retired after the first check but before the
// snapshot is refused as well, for either dialect, as is a retired SQLite database; no archive is
// written.
func TestBackup_RetiredMeanwhile(t *testing.T) {
	c := newPGController(t)
	out := filepath.Join(t.TempDir(), "rpmgr.backup")
	controller.OnBackupStep(t, func(step, _ string) {
		if step != "opened" {
			return
		}
		if _, err := openBoot(t, c.boot).Writer.Exec("UPDATE instance SET retired_at = now(), retired_to = '/etc/rpmgr/elsewhere.yaml'"); err != nil {
			t.Error(err)
		}
	})
	if _, err := c.backup(t, out); !errors.Is(err, controller.ErrRetired) {
		t.Errorf("a PostgreSQL database retired meanwhile: %v", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused backup left its archive: %v", err)
	}
	// A SQLite database that a migration retired.
	h := newMigrateHost(t)
	boot, _ := pgDatabase(t)
	if _, err := migrateDB(h.cfg, boot, false); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Backup(context.Background(), h.cfg, filepath.Join(t.TempDir(), "x.backup"), "2.0.0", time.Now); !errors.Is(err, controller.ErrRetired) {
		t.Errorf("a retired SQLite database: %v", err)
	}
}

// TestRestore_RetiredArchive: an archive of a retired database is refused with a clear message, into
// either dialect, and changes nothing.
func TestRestore_RetiredArchive(t *testing.T) {
	c := newPGController(t)
	archive := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := c.backup(t, archive); err != nil {
		t.Fatal(err)
	}
	bad := retiredArchive(t, archive)
	before := stateDigest(t, c.state)
	boot, _ := pgDatabase(t)
	_, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: bad, RevocationLogs: c.logs()})
	if !errors.Is(err, controller.ErrRetired) || !strings.Contains(err.Error(), "restore an archive of the controller that runs now") {
		t.Errorf("into PostgreSQL: %v", err)
	}
	if n := tableCount(t, boot); n != 0 {
		t.Errorf("a refused restore left %d tables", n)
	}
	if _, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: c.cfg, Archive: bad}); !errors.Is(err, controller.ErrRetired) {
		t.Errorf("into SQLite: %v", err)
	}
	if stateDigest(t, c.state) != before {
		t.Error("a refused restore changed the state directory")
	}
}

// TestRestorePostgres_FailureAfterTheCommit: when putting the logs in place fails after the database
// took the restore, the error says so and names what to place by hand, and nothing is deleted. A
// replaced log of the same name is never overwritten.
func TestRestorePostgres_FailureAfterTheCommit(t *testing.T) {
	c := newPGController(t)
	archive := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := c.backup(t, archive); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	taken := filepath.Join(c.state, "revocations.log.before-restore-20261127T100000Z")
	if err := os.WriteFile(taken, []byte("an earlier restore's"), 0o600); err != nil {
		t.Fatal(err)
	}
	live := fileBytes(t, c.revlog())
	boot, _ := pgDatabase(t)
	controller.OnRestoreStep(t, func(step string) {
		if step != "installing" {
			return
		}
		// The restored database has committed; a directory is where the log is to go.
		dir := c.revlog()
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "x"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	_, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: archive, RevocationLogs: c.logs(), Now: func() time.Time { return now }})
	if err == nil {
		t.Fatal("a restore whose logs could not be placed succeeded")
	}
	if !strings.Contains(err.Error(), "the PostgreSQL database holds the restore (epoch ") || !strings.Contains(err.Error(), ".restoring-revocations.log as revocations.log") {
		t.Errorf("the error: %v", err)
	}
	if n := countRows(t, openBoot(t, boot), "instance", "true"); n != 1 {
		t.Errorf("the database holds %d installations", n)
	}
	if got := fileBytes(t, taken); got != "an earlier restore's" {
		t.Errorf("an earlier replaced log was overwritten: %q", got)
	}
	if got := fileBytes(t, c.revlog()+".before-restore-20261127T100000Z-1"); got != live {
		t.Errorf("the replaced log is not kept under a new suffix: %q", got)
	}
	if fileBytes(t, filepath.Join(c.state, ".restoring-revocations.log")) == "" {
		t.Error("the restored log was removed")
	}
}

// TestRestorePostgres_Options: --replaces is for PostgreSQL only; a restore into PostgreSQL names
// its revocation log; a SQLite database named by --replaces is refused when it is a link, and a
// controller running on it makes the restore refuse; a boot file with a PostgreSQL section that is
// wrong says what is wrong with it.
func TestRestorePostgres_Options(t *testing.T) {
	ctx := context.Background()
	c := newPGController(t)
	archive := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := c.backup(t, archive); err != nil {
		t.Fatal(err)
	}
	before := stateDigest(t, c.state)
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: c.cfg, Archive: archive, Replaces: c.boot}); !errors.Is(err, controller.ErrReplacesNeedsPostgres) {
		t.Errorf("--replaces on SQLite: %v", err)
	}
	target, _ := pgDatabase(t)
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: target, Archive: archive}); !errors.Is(err, controller.ErrRevocationLogNeeded) {
		t.Errorf("without --revocation-log: %v", err)
	}
	if n := tableCount(t, target); n != 0 {
		t.Errorf("a refused restore left %d tables", n)
	}
	link := filepath.Join(t.TempDir(), "old.db")
	if err := os.Symlink(c.db, link); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: target, Archive: archive, RevocationLogs: c.logs(), Replaces: link}); !errors.Is(err, controller.ErrLinkedState) {
		t.Errorf("a link as --replaces: %v", err)
	}
	if _, err := os.Lstat(link + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a lock file was made through a link: %v", err)
	}
	running, err := store.OpenSQLite(ctx, c.db, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.Restore(ctx, controller.RestoreOptions{ConfigPath: target, Archive: archive, RevocationLogs: c.logs(), Replaces: c.db})
	_ = running.Close()
	if !errors.Is(err, controller.ErrControllerRunning) {
		t.Errorf("a controller on the replaced SQLite database: %v", err)
	}
	if n := tableCount(t, target); n != 0 {
		t.Errorf("a refused restore left %d tables", n)
	}
	if stateDigest(t, c.state) != before {
		t.Error("a refused restore changed the state directory")
	}
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: target, Archive: archive, RevocationLogs: c.logs(), Replaces: c.db}); err != nil {
		t.Errorf("a stopped SQLite database as --replaces: %v", err)
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	body := "version: 1\ndatabase:\n  driver: postgres\n  dsn: postgres://u@h/db\n  password_file: /etc/pw\n  password_credential: cred\n"
	if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Backup(ctx, bad, filepath.Join(t.TempDir(), "x"), "2.0.0", time.Now); err == nil || !strings.Contains(err.Error(), "password_file or password_credential") {
		t.Errorf("a boot file with both password settings: %v", err)
	}
}
