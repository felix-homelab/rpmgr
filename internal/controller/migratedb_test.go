// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// canary is a secret value the command must never print, log or audit. It is sealed under the KEK
// like every secret, so it can only appear if the command opened a sealed value.
const canary = "canary-secret-7f3a" //nolint:gosec // G101: a made-up test value

// migrateHost is an initialised SQLite controller host with a sealed canary in instance_secrets
// and its KEK file moved away: whatever the command does, it cannot read the KEK.
type migrateHost struct {
	host
	kek secret.KEK
}

func newMigrateHost(t *testing.T) migrateHost {
	t.Helper()
	h, _ := initHost(t)
	k, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := secret.NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sealed, err := sealer.Seal(context.Background(), secret.Context{Table: "instance_secrets", Column: "value_enc", RowID: "canary"}, secret.New(canary))
	if err != nil {
		t.Fatal(err)
	}
	db.Client().InstanceSecret.Create().SetID("canary").SetValueEnc(sealed).SetUpdatedAt(time.Now()).SaveX(storetest.SystemCtx(t))
	if err := os.Rename(h.kek, h.kek+".away"); err != nil {
		t.Fatal(err)
	}
	return migrateHost{h, k}
}

// giveKEKBack puts the KEK file where the boot file names it, for a test that starts a controller.
func (m migrateHost) giveKEKBack(t *testing.T) {
	t.Helper()
	if err := os.Rename(m.host.kek+".away", m.host.kek); err != nil {
		t.Fatal(err)
	}
}

// sqliteBoot writes a boot file for a SQLite database at path, with no kek section.
func sqliteBoot(t *testing.T, path string) string {
	t.Helper()
	boot := filepath.Join(t.TempDir(), "boot.yaml")
	if err := os.WriteFile(boot, []byte("version: 1\ndatabase: {driver: sqlite, dsn: "+path+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return boot
}

// pgDatabase makes an empty PostgreSQL database and returns a boot file for it, with the password
// in a file of its own, as the command wants it, and the database's DSN with the password.
func pgDatabase(t *testing.T) (boot, dsn string) {
	t.Helper()
	dsn = storetest.NewPostgresDatabase(t)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := u.User.Password()
	u.User = url.User(u.User.Username())
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	boot = filepath.Join(dir, "boot.yaml")
	body := fmt.Sprintf("version: 1\ndatabase:\n  driver: postgres\n  dsn: %s\n  password_file: %s\n", u.String(), pwFile)
	if err := os.WriteFile(boot, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return boot, dsn
}

func openBoot(t *testing.T, boot string) *store.DB {
	t.Helper()
	d, err := config.LoadDatabase(boot)
	if err != nil {
		t.Fatal(err)
	}
	var db *store.DB
	if d.Driver == "sqlite" {
		db, err = store.OpenSQLite(context.Background(), d.DSN, store.SQLiteOptions{})
	} else {
		db, err = store.OpenPostgres(context.Background(), d.DSN, store.PostgresOptions{PasswordFile: d.PasswordFile})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// sealedValues returns every sealed column of db, as "table.column" to its values in byte order.
func sealedValues(t *testing.T, db *store.DB) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, c := range controller.SealedColumns() {
		tbl, col, _ := strings.Cut(c, ".")
		//nolint:gosec // G202: the names are the fixed list of sealed columns
		rows, err := db.Reader.QueryContext(context.Background(), `SELECT "`+col+`" FROM "`+tbl+`" WHERE "`+col+`" IS NOT NULL`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				t.Fatal(err)
			}
			out[c] = append(out[c], string(b))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		_ = rows.Close()
		slices.Sort(out[c])
	}
	return out
}

func migrateDB(from, to string, noRetire bool) (controller.MigrateDBResult, error) {
	var tables []string
	r, err := controller.MigrateDB(context.Background(), controller.MigrateDBOptions{From: from, ToFile: to, NoRetire: noRetire,
		Getenv: noEnv, Now: func() time.Time { return time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC) },
		Progress: func(table string, _ int64) { tables = append(tables, table) }})
	if err == nil && len(tables) != r.Copy.Tables {
		err = fmt.Errorf("progress reported %d tables, the result %d", len(tables), r.Copy.Tables)
	}
	return r, err
}

func localReasons(t *testing.T, db *store.DB, action string) []string {
	t.Helper()
	var out []string
	for _, e := range db.Client().AuditEntry.Query().Where(auditentry.ActorID("local-cli"), auditentry.Action(action)).AllX(storetest.SystemCtx(t)) {
		if string(e.ActorType) != string(audit.ActorSystem) {
			t.Errorf("entry %s has actor type %s", e.Action, e.ActorType)
		}
		out = append(out, e.Reason)
	}
	return out
}

func retiredState(t *testing.T, boot string) (at sql.NullTime, to sql.NullString) {
	t.Helper()
	db := openBoot(t, boot)
	if err := db.Reader.QueryRowContext(context.Background(), "SELECT retired_at, retired_to FROM instance").Scan(&at, &to); err != nil {
		t.Fatal(err)
	}
	return at, to
}

func assertNotRetired(t *testing.T, boot string) {
	t.Helper()
	if at, to := retiredState(t, boot); at.Valid {
		t.Errorf("%s is retired (to %s)", boot, to.String)
	}
}

// TestMigrateDB_SecretsStaySealed (docs/12, slice 8.4): after a migration in each direction every
// sealed column of the target holds the source's bytes, the canary appears in no result or audit
// entry, the command had no KEK (its file is moved away and the boot files have no kek section) and
// the target opens only under the source's KEK.
func TestMigrateDB_SecretsStaySealed(t *testing.T) {
	src := newMigrateHost(t)
	want := sealedValues(t, openBoot(t, src.cfg))
	if len(want["ca_keys.key_enc"]) == 0 || len(want["instance_secrets.value_enc"]) == 0 {
		t.Fatalf("the source holds no sealed values: %v", want)
	}

	check := func(t *testing.T, name string, db *store.DB) {
		t.Helper()
		if got := sealedValues(t, db); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: the sealed columns differ from the source's", name)
		}
		sealer, err := secret.NewSealer(src.kek)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := castore.LoadCA(storetest.SystemCtx(t), db, sealer, time.Now); err != nil {
			t.Errorf("%s: the source's KEK does not open the target's CA: %v", name, err)
		}
		other := make([]byte, 32)
		other[0] = 1
		wrong, _ := secret.NewKEK(other)
		ws, _ := secret.NewSealer(wrong)
		if _, err := castore.LoadCA(storetest.SystemCtx(t), db, ws, time.Now); err == nil {
			t.Errorf("%s: another KEK opens the target's CA", name)
		}
		for _, r := range localReasons(t, db, "database.migrate") {
			if strings.Contains(r, canary) {
				t.Errorf("%s: the audit entry names the canary: %s", name, r)
			}
		}
	}

	t.Run("sqlite to sqlite", func(t *testing.T) {
		dst := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
		r, err := migrateDB(src.cfg, dst, true)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(fmt.Sprint(r), canary) {
			t.Error("the result names the canary")
		}
		check(t, "sqlite", openBoot(t, dst))
	})

	t.Run("both directions through postgresql", func(t *testing.T) {
		pgBoot, dsn := pgDatabase(t)
		r, err := migrateDB(src.cfg, pgBoot, true)
		if err != nil {
			t.Fatal(err)
		}
		pg := openBoot(t, pgBoot)
		check(t, "postgres", pg)
		if r.From != store.SQLite || r.To != store.Postgres || r.Copy.Tables == 0 {
			t.Errorf("result %+v", r)
		}
		_ = pg.Close()

		backBoot := sqliteBoot(t, filepath.Join(t.TempDir(), "back.db"))
		r2, err := migrateDB(pgBoot, backBoot, false)
		if err != nil {
			t.Fatal(err)
		}
		check(t, "sqlite again", openBoot(t, backBoot))
		// The target holds what the first command audited, so the way back copies more rows.
		if r2.From != store.Postgres || r2.To != store.SQLite || r2.Copy.Tables != r.Copy.Tables || r2.Copy.Rows <= r.Copy.Rows || !r2.Retired {
			t.Errorf("the way back: %+v, the way there: %+v", r2, r)
		}
		if s := fmt.Sprint(r, r2); strings.Contains(s, dsn) || strings.Contains(s, "rpmgr:rpmgr") {
			t.Error("a result carries the DSN or the password")
		}
	})

	t.Run("postgresql to postgresql", func(t *testing.T) {
		first, _ := pgDatabase(t)
		if _, err := migrateDB(src.cfg, first, true); err != nil {
			t.Fatal(err)
		}
		second, _ := pgDatabase(t)
		if _, err := migrateDB(first, second, true); err != nil {
			t.Fatal(err)
		}
		check(t, "postgres to postgres", openBoot(t, second))
	})
}

// TestMigrateDB_Arguments: a database address as an argument, whatever its form, is refused before
// anything opens, and so are a missing file, a file that is neither a SQLite database nor a boot
// file, a boot file with a bad database section, and one database as both source and target.
func TestMigrateDB_Arguments(t *testing.T) {
	src := newMigrateHost(t)
	good := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	for name, args := range map[string][2]string{
		"url as source":             {"postgres://rpmgr:rpmgr@127.0.0.1/db", good},
		"url as target":             {src.cfg, "postgresql://rpmgr@127.0.0.1/db?sslmode=verify-full"},
		"key value as source":       {"host=127.0.0.1 dbname=db password=pw", good},
		"key value as target":       {src.cfg, "user=rpmgr password=pw"},
		"empty source":              {"", good},
		"empty target":              {src.cfg, ""},
		"capitalised scheme":        {"POSTGRES://u@h/d", good},
		"password key without host": {src.cfg, "password=pw"},
	} {
		if _, err := migrateDB(args[0], args[1], true); !errors.Is(err, controller.ErrDSNArgument) {
			t.Errorf("%s: %v, want ErrDSNArgument", name, err)
		}
	}
	if _, err := migrateDB(filepath.Join(t.TempDir(), "missing.yaml"), good, true); err == nil {
		t.Error("a missing source was accepted")
	}
	if _, err := migrateDB(src.cfg, filepath.Join(t.TempDir(), "missing.yaml"), true); err == nil {
		t.Error("a missing target boot file was accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(junk, []byte("not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateDB(junk, good, true); err == nil {
		t.Error("a file that is no boot file was accepted")
	}
	for name, body := range map[string]string{
		"a password in a sqlite section": "database: {driver: sqlite, dsn: /srv/rpmgr/y.db, password_file: /srv/rpmgr/pw}\n",
		"an unknown key":                 "database: {driver: sqlite, dsn: /srv/rpmgr/y.db, password: pw}\n",
		"another driver":                 "database: {driver: mysql, dsn: root@db}\n",
		"postgres without a dsn":         "database: {driver: postgres}\n",
		"both password sources":          "database: {driver: postgres, dsn: 'postgres://u@h/d', password_file: /srv/a, password_credential: b}\n",
		"a relative sqlite path":         "database: {driver: sqlite, dsn: rpmgr.db}\n",
	} {
		p := filepath.Join(t.TempDir(), "boot.yaml")
		if err := os.WriteFile(p, []byte("version: 1\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := migrateDB(src.cfg, p, true); err == nil {
			t.Errorf("%s was accepted as a target", name)
		}
	}
	if _, err := migrateDB(src.cfg, src.cfg, true); !errors.Is(err, controller.ErrSameDatabase) {
		t.Errorf("one database twice: %v", err)
	}
	if _, err := migrateDB(src.db, sqliteBoot(t, src.db), true); !errors.Is(err, controller.ErrSameDatabase) {
		t.Errorf("one database, named by its file: %v", err)
	}
}

// TestMigrateDB_Locked: a controller on the source or on the target stops the command before it
// changes anything, on SQLite by the lock file and on PostgreSQL by the advisory lock, whether the
// holder is exclusive or one replica of a cluster.
func TestMigrateDB_Locked(t *testing.T) {
	src := newMigrateHost(t)
	dst := filepath.Join(t.TempDir(), "to.db")
	dstBoot := sqliteBoot(t, dst)

	unlock, err := store.HoldLock(src.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrateDB(src.cfg, dstBoot, false); !errors.Is(err, controller.ErrStopController) {
		t.Errorf("a controller on the source: %v", err)
	}
	_ = unlock()

	unlock, err = store.HoldLock(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrateDB(src.cfg, dstBoot, false); !errors.Is(err, controller.ErrStopController) {
		t.Errorf("a controller on the target: %v", err)
	}
	_ = unlock()
	assertNotRetired(t, src.cfg)

	t.Run("postgresql", func(t *testing.T) {
		pgBoot, dsn := pgDatabase(t)
		for name, shared := range map[string]bool{"exclusive": false, "replica": true} {
			holder, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true, Shared: shared})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := migrateDB(src.cfg, pgBoot, false); !errors.Is(err, controller.ErrStopController) {
				t.Errorf("%s controller on the target: %v", name, err)
			}
			_ = holder.Close()
		}
		assertNotRetired(t, src.cfg)
		// With the lock free the copy goes through; a holder on the source then stops the way back.
		if _, err := migrateDB(src.cfg, pgBoot, true); err != nil {
			t.Fatal(err)
		}
		holder, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = holder.Close() }()
		back := sqliteBoot(t, filepath.Join(t.TempDir(), "back.db"))
		if _, err := migrateDB(pgBoot, back, false); !errors.Is(err, controller.ErrStopController) {
			t.Errorf("a controller on the source: %v", err)
		}
	})
}

// TestMigrateDB_Refusals: a target with a row, a target with a table of something else, a target
// at another schema version, a source behind this binary and a source without an installation are
// refused, each with its own error, and retire nothing.
func TestMigrateDB_Refusals(t *testing.T) {
	src := newMigrateHost(t)

	t.Run("a target with rows", func(t *testing.T) {
		first := sqliteBoot(t, filepath.Join(t.TempDir(), "first.db"))
		if _, err := migrateDB(src.cfg, first, true); err != nil {
			t.Fatal(err)
		}
		before := sealedValues(t, openBoot(t, first))
		if _, err := migrateDB(src.cfg, first, false); !errors.Is(err, store.ErrTargetNotEmpty) {
			t.Fatalf("a target that holds a copy: %v", err)
		}
		if fmt.Sprint(sealedValues(t, openBoot(t, first))) != fmt.Sprint(before) {
			t.Error("a refused copy changed the target")
		}
		assertNotRetired(t, src.cfg)
	})

	t.Run("a table that is not rpmgr's", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "other.db")
		db, err := store.OpenSQLite(context.Background(), path, store.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Writer.Exec("CREATE TABLE notes (id integer)"); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if _, err := migrateDB(src.cfg, sqliteBoot(t, path), false); !errors.Is(err, store.ErrTargetNotEmpty) {
			t.Fatalf("%v", err)
		}
		assertNotRetired(t, src.cfg)
	})

	t.Run("a target at another schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "older.db")
		olderDatabase(t, path)
		if _, err := migrateDB(src.cfg, sqliteBoot(t, path), false); !errors.Is(err, store.ErrSchemaMismatch) {
			t.Fatalf("%v", err)
		}
		assertNotRetired(t, src.cfg)
	})

	t.Run("a source behind this binary", func(t *testing.T) {
		old := newMigrateHost(t)
		olderDatabase(t, old.db)
		_, err := migrateDB(old.db, sqliteBoot(t, filepath.Join(t.TempDir(), "to.db")), false)
		if !errors.Is(err, store.ErrSchemaMismatch) || !strings.Contains(err.Error(), "rpmgr migrate") {
			t.Fatalf("%v", err)
		}
	})

	t.Run("a source without an installation", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "empty.db")
		db, err := store.OpenSQLite(context.Background(), empty, store.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if _, err := migrateDB(empty, sqliteBoot(t, filepath.Join(t.TempDir(), "to.db")), false); err == nil {
			t.Fatal("an empty source was copied")
		}
	})
}

// TestMigrateDB_Audited: the migration is one audit entry of the actor local-cli in the target,
// naming the dialects, the counts and the hash, and the target's instance chain still verifies.
func TestMigrateDB_Audited(t *testing.T) {
	src := newMigrateHost(t)
	dst := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	r, err := migrateDB(src.cfg, dst, false)
	if err != nil {
		t.Fatal(err)
	}
	db := openBoot(t, dst)
	reasons := localReasons(t, db, "database.migrate")
	if len(reasons) != 1 || !strings.Contains(reasons[0], r.Copy.Hash) || !strings.Contains(reasons[0], "source retired") ||
		!strings.Contains(reasons[0], fmt.Sprintf("%d rows", r.Copy.Rows)) {
		t.Fatalf("entries %q for %+v", reasons, r)
	}
	if _, err := audit.Verify(storetest.SystemCtx(t), db, ""); err != nil {
		t.Errorf("the target's instance chain does not verify: %v", err)
	}

	kept := sqliteBoot(t, filepath.Join(t.TempDir(), "kept.db"))
	if _, err := migrateDB(src.cfg, kept, true); !errors.Is(err, controller.ErrRetired) {
		t.Fatalf("copying the retired source again: %v", err)
	}
}

// TestMigrateDB_Retire: the source carries retired_at and retired_to afterwards, a controller
// refuses to start on it, a second migration of it is refused, and --no-retire leaves it usable.
func TestMigrateDB_Retire(t *testing.T) {
	src := newMigrateHost(t)
	src.giveKEKBack(t) // so that Run fails on the retirement and on nothing else
	keep := sqliteBoot(t, filepath.Join(t.TempDir(), "copy.db"))
	if r, err := migrateDB(src.cfg, keep, true); err != nil || r.Retired {
		t.Fatalf("--no-retire: %+v, %v", r, err)
	}
	assertNotRetired(t, src.cfg)
	if reasons := localReasons(t, openBoot(t, keep), "database.migrate"); len(reasons) != 1 || !strings.Contains(reasons[0], "--no-retire") {
		t.Errorf("the entry of a copy that retires nothing: %q", reasons)
	}

	dst := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	r, err := migrateDB(src.cfg, dst, false)
	if err != nil || !r.Retired {
		t.Fatalf("%+v, %v", r, err)
	}
	at, to := retiredState(t, src.cfg)
	if !at.Valid || !at.Time.UTC().Equal(time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)) || to.String != dst {
		t.Errorf("retired_at %v, retired_to %q, want the target %q", at, to.String, dst)
	}
	if _, err := migrateDB(src.cfg, sqliteBoot(t, filepath.Join(t.TempDir(), "again.db")), false); !errors.Is(err, controller.ErrRetired) {
		t.Errorf("a retired source copied again: %v", err)
	}

	var cfg config.Controller
	if err := config.Load(src.cfg, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Listen.HTTPS, cfg.Listen.Admin = freeAddr(t), freeAddr(t)
	none := ""
	cfg.Listen.HTTP = &none
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = controller.Run(ctx, controller.RunOptions{Config: cfg, Getenv: noEnv, Listening: func() { t.Error("Run started on a retired database") }})
	if !errors.Is(err, controller.ErrRetired) || !strings.Contains(err.Error(), dst) {
		t.Errorf("a controller on the retired source: %v", err)
	}
}

// TestMigrateDB_PostgresTargets: a PostgreSQL target that holds a copy, and one that holds a table
// of its own and no migration, are refused and retire nothing.
func TestMigrateDB_PostgresTargets(t *testing.T) {
	src := newMigrateHost(t)
	pgBoot, _ := pgDatabase(t)
	if _, err := migrateDB(src.cfg, pgBoot, true); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateDB(src.cfg, pgBoot, false); !errors.Is(err, store.ErrTargetNotEmpty) {
		t.Fatalf("a PostgreSQL target that holds a copy: %v", err)
	}
	otherBoot, _ := pgDatabase(t)
	if _, err := openBoot(t, otherBoot).Writer.Exec("CREATE TABLE notes (id integer)"); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateDB(src.cfg, otherBoot, false); !errors.Is(err, store.ErrTargetNotEmpty) {
		t.Fatalf("a PostgreSQL database with a table of its own: %v", err)
	}
	assertNotRetired(t, src.cfg)
}

// TestMigrateDB_SourceHeldDuringCopy (S1): while the copy runs, a connection that takes no
// controller lock, as `ca rotate-intermediate` or `user reset-password` do, cannot write to the
// source, so nothing lands only in a database that is about to be retired.
func TestMigrateDB_SourceHeldDuringCopy(t *testing.T) {
	src := newMigrateHost(t)
	dst := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	var writeErr error
	tried := false
	_, err := controller.MigrateDB(context.Background(), controller.MigrateDBOptions{From: src.cfg, ToFile: dst, Getenv: noEnv,
		Progress: func(string, int64) {
			if tried {
				return
			}
			tried = true
			other, err := store.OpenSQLite(context.Background(), src.db, store.SQLiteOptions{BusyTimeout: 100 * time.Millisecond})
			if err != nil {
				writeErr = err
				return
			}
			defer func() { _ = other.Close() }()
			_, writeErr = other.Writer.Exec("UPDATE instance SET db_epoch = db_epoch || 'x'")
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !tried || writeErr == nil {
		t.Fatalf("a lock-free write to the source during the copy: tried %v, error %v", tried, writeErr)
	}
}

// TestMigrateDB_RetiredRefusedByLockFreeCommands (S1): every command that opens the database
// without the controller lock refuses a retired one, naming where it went.
func TestMigrateDB_RetiredRefusedByLockFreeCommands(t *testing.T) {
	ctx := context.Background()
	src := newMigrateHost(t)
	dst := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	if _, err := migrateDB(src.cfg, dst, false); err != nil {
		t.Fatal(err)
	}
	calls := map[string]func() error{
		"ca status":       func() error { _, err := controller.CAStatus(ctx, src.cfg); return err },
		"restore confirm": func() error { _, err := controller.ConfirmRestore(ctx, src.cfg, ""); return err },
		"reset-password":  func() error { _, err := controller.ResetPasswordLink(ctx, src.cfg, "a@example.com"); return err },
		"release import": func() error {
			_, err := controller.ImportRelease(ctx, src.cfg, t.TempDir(), "1.4.2", nil, time.Now)
			return err
		},
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, controller.ErrRetired) || !strings.Contains(err.Error(), "boot.yaml") {
			t.Errorf("%s on a retired database: %v", name, err)
		}
	}
}

// TestMigrateDB_OtherNamesOfTheSource (S2): a symbolic link to the source reaches the same lock as
// the path itself, and a hard link, whose lock would differ, is refused.
func TestMigrateDB_OtherNamesOfTheSource(t *testing.T) {
	src := newMigrateHost(t)
	dst := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))

	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(src.db, link); err != nil {
		t.Fatal(err)
	}
	unlock, err := store.HoldLock(src.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrateDB(link, dst, false); !errors.Is(err, controller.ErrStopController) {
		t.Errorf("a symbolic link to a database a controller holds: %v", err)
	}
	if _, err := store.HoldLock(link); !errors.Is(err, store.ErrLocked) {
		t.Errorf("HoldLock through the link: %v", err)
	}
	_ = unlock()
	assertNotRetired(t, src.cfg)

	hard := filepath.Join(t.TempDir(), "hard.db")
	if err := os.Link(src.db, hard); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	if _, err := migrateDB(hard, dst, false); !errors.Is(err, controller.ErrHardLinked) {
		t.Errorf("a hard-linked source: %v", err)
	}
	if _, err := migrateDB(src.db, dst, false); !errors.Is(err, controller.ErrHardLinked) {
		t.Errorf("the other name of a hard-linked source: %v", err)
	}
}

// TestMigrateDB_LockLost (S3): when the session that holds a PostgreSQL controller lock ends during
// the copy, the copy stops, the target is not committed and the source is not retired.
func TestMigrateDB_LockLost(t *testing.T) {
	src := newMigrateHost(t)
	pgBoot, dsn := pgDatabase(t)
	admin, err := sql.Open("pgx", os.Getenv("RPMGR_TEST_PG"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	killed := false
	_, err = controller.MigrateDB(context.Background(), controller.MigrateDBOptions{From: src.cfg, ToFile: pgBoot, Getenv: noEnv,
		Progress: func(string, int64) {
			if killed {
				return
			}
			killed = true
			u, _ := url.Parse(dsn)
			var n int
			// The lock's session is the only one of this database that holds an advisory lock.
			if err := admin.QueryRow(`SELECT count(pg_terminate_backend(l.pid)) FROM pg_locks l JOIN pg_database d ON d.oid = l.database
				WHERE l.locktype = 'advisory' AND d.datname = $1`, strings.TrimPrefix(u.Path, "/")).Scan(&n); err != nil || n == 0 {
				t.Errorf("ending the lock session: %d, %v", n, err)
			}
			time.Sleep(8 * time.Second) // longer than the interval at which the lock is checked
		}})
	if !killed || !errors.Is(err, controller.ErrLockLost) {
		t.Fatalf("a lost lock: killed %v, %v", killed, err)
	}
	assertNotRetired(t, src.cfg)
	var rows int
	if err := openBoot(t, pgBoot).Reader.QueryRow("SELECT count(*) FROM instance").Scan(&rows); err != nil || rows != 0 {
		t.Errorf("the target holds %d instance rows after a lost lock (%v)", rows, err)
	}
}

// TestMigrateDB_ReadOnlySource (S4): a source that cannot be written is refused before anything is
// copied and before a target file exists.
func TestMigrateDB_ReadOnlySource(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only file")
	}
	src := newMigrateHost(t)
	if err := os.Chmod(src.db, 0o400); err != nil { //nolint:gosec // G302: read-only on purpose
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "to.db")
	if _, err := migrateDB(src.cfg, sqliteBoot(t, target), false); err == nil {
		t.Fatal("a read-only source was accepted")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused migration left the target file: %v", err)
	}
}

// TestMigrateDB_TargetFile (S5): a SQLite target the command creates has mode 0600, as a restore
// makes it.
func TestMigrateDB_TargetFile(t *testing.T) {
	src := newMigrateHost(t)
	target := filepath.Join(t.TempDir(), "to.db")
	if _, err := migrateDB(src.cfg, sqliteBoot(t, target), true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{target, target + ".lock"} {
		fi, err := os.Stat(name)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want mode 0600", name, fi, err)
		}
	}
}

// TestMigrateDB_RefusalsLeaveNoTarget: a source that is retired or behind this binary is refused
// before the target is created.
func TestMigrateDB_RefusalsLeaveNoTarget(t *testing.T) {
	src := newMigrateHost(t)
	if _, err := migrateDB(src.cfg, sqliteBoot(t, filepath.Join(t.TempDir(), "first.db")), false); err != nil {
		t.Fatal(err)
	}
	old := newMigrateHost(t)
	olderDatabase(t, old.db)
	for name, from := range map[string]string{"retired": src.cfg, "behind": old.db} {
		target := filepath.Join(t.TempDir(), "to.db")
		if _, err := migrateDB(from, sqliteBoot(t, target), false); err == nil {
			t.Errorf("%s source was accepted", name)
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s source: the target file exists: %v", name, err)
		}
	}
}

// TestMigrateDB_PostgresToPostgres: the sealed values also survive a copy between two PostgreSQL
// databases, and a target that is the source under another host name is named as such.
func TestMigrateDB_PostgresToPostgres(t *testing.T) {
	src := newMigrateHost(t)
	want := sealedValues(t, openBoot(t, src.cfg))
	first, firstDSN := pgDatabase(t)
	if _, err := migrateDB(src.cfg, first, true); err != nil {
		t.Fatal(err)
	}
	second, _ := pgDatabase(t)
	if _, err := migrateDB(first, second, true); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sealedValues(t, openBoot(t, second))) != fmt.Sprint(want) {
		t.Error("the sealed columns changed on the way")
	}

	// The same database, spelled with another host name.
	body, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	// The loopback address and localhost name the same server, whichever RPMGR_TEST_PG uses.
	respelled := strings.ReplaceAll(string(body), "127.0.0.1", "localhost")
	if respelled == string(body) {
		respelled = strings.ReplaceAll(string(body), "localhost", "127.0.0.1")
	}
	if respelled == string(body) {
		t.Fatal("RPMGR_TEST_PG must name the server as 127.0.0.1 or localhost for this test")
	}
	spelled := filepath.Join(t.TempDir(), "respelled.yaml")
	if err := os.WriteFile(spelled, []byte(respelled), 0o600); err != nil { //nolint:gosec // G703: a path of this test
		t.Fatal(err)
	}
	_ = firstDSN
	_, err = migrateDB(first, spelled, true)
	if !errors.Is(err, controller.ErrStopController) || !strings.Contains(err.Error(), "under another name") {
		t.Errorf("one database under two names: %v", err)
	}
}

func killLockSession(t *testing.T, dsn string) {
	t.Helper()
	admin, err := sql.Open("pgx", os.Getenv("RPMGR_TEST_PG"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	u, _ := url.Parse(dsn)
	var n int
	// The lock's session is the only one of this database that holds an advisory lock.
	if err := admin.QueryRow(`SELECT count(pg_terminate_backend(l.pid)) FROM pg_locks l JOIN pg_database d ON d.oid = l.database
		WHERE l.locktype = 'advisory' AND d.datname = $1`, strings.TrimPrefix(u.Path, "/")).Scan(&n); err != nil || n == 0 {
		t.Fatalf("ending the lock session: %d, %v", n, err)
	}
	time.Sleep(8 * time.Second) // longer than the interval at which the lock is checked
}

// TestMigrateDB_LinkedSidecars (N1): a lock, journal or shared-memory name that is a link is
// refused on source and target, nothing is written through it, and no lock is taken through one.
func TestMigrateDB_LinkedSidecars(t *testing.T) {
	src := newMigrateHost(t)
	victim := filepath.Join(t.TempDir(), "victim")
	orig := []byte("VICTIM-CONTENT\n")
	check := func(what string) {
		t.Helper()
		if got, _ := os.ReadFile(victim); string(got) != string(orig) {
			t.Errorf("%s: the link's destination changed: %q", what, got)
		}
	}
	for _, suffix := range []string{".lock", "-wal", "-shm"} {
		if err := os.WriteFile(victim, orig, 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "to.db")
		if err := os.Symlink(victim, target+suffix); err != nil {
			t.Fatal(err)
		}
		if _, err := migrateDB(src.cfg, sqliteBoot(t, target), false); !errors.Is(err, controller.ErrLinkedState) {
			t.Errorf("target %s as a link: %v", suffix, err)
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("target %s as a link: the target file exists: %v", suffix, err)
		}
		check("target " + suffix)

		other := newMigrateHost(t)
		_ = os.Remove(other.db + suffix)
		if err := os.Symlink(victim, other.db+suffix); err != nil {
			t.Fatal(err)
		}
		if _, err := migrateDB(other.cfg, sqliteBoot(t, filepath.Join(t.TempDir(), "to.db")), false); !errors.Is(err, controller.ErrLinkedState) {
			t.Errorf("source %s as a link: %v", suffix, err)
		}
		check("source " + suffix)
	}
	// The lock files themselves are never opened through a link, by any command.
	path := filepath.Join(t.TempDir(), "x.db")
	if err := os.Symlink(victim, path+".lock"); err != nil {
		t.Fatal(err)
	}
	for name, hold := range map[string]func(string) (func() error, error){"HoldLock": store.HoldLock, "HoldLockNoFollow": store.HoldLockNoFollow} {
		if unlock, err := hold(path); err == nil || errors.Is(err, store.ErrLocked) {
			_ = unlock
			t.Errorf("%s through a link: %v", name, err)
		}
	}
	check("lock")
}

// TestMigrateDB_LockFreeWriteAfterCheck (N2): a lock-free writer that checked before the retirement
// and waits for the write lock while the copy holds it finds the source retired, or fails; its
// write never lands in the retired source.
func TestMigrateDB_LockFreeWriteAfterCheck(t *testing.T) {
	src := newMigrateHost(t)
	dst := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	done := make(chan error, 1)
	started := false
	_, err := controller.MigrateDB(context.Background(), controller.MigrateDBOptions{From: src.cfg, ToFile: dst, Getenv: noEnv,
		Progress: func(string, int64) {
			if started {
				return
			}
			started = true
			other, err := store.OpenSQLite(context.Background(), src.db, store.SQLiteOptions{BusyTimeout: 10 * time.Second, RefuseRetired: true})
			if err != nil {
				t.Error(err)
				done <- err
				return
			}
			go func() {
				defer func() { _ = other.Close() }()
				done <- store.WriteTx(storetest.SystemCtx(t), other, func(tx *ent.Tx) error {
					return tx.Instance.Update().SetDbEpoch("LOST").Exec(storetest.SystemCtx(t))
				})
			}()
			time.Sleep(300 * time.Millisecond) // it now waits for the write lock
		}})
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-done; werr == nil {
		t.Error("a write that waited for the copy committed into the retired source")
	}
	var epoch string
	if err := openBoot(t, src.cfg).Reader.QueryRow("SELECT db_epoch FROM instance").Scan(&epoch); err != nil || epoch == "LOST" {
		t.Errorf("the source's epoch is %q (%v)", epoch, err)
	}
}

// TestMigrateDB_InterruptedAfterCommit (N3): a context cancelled after the target committed does
// not leave both databases live: the source is retired all the same, on SQLite and on PostgreSQL.
func TestMigrateDB_InterruptedAfterCommit(t *testing.T) {
	src := newMigrateHost(t)
	run := func(t *testing.T, from, to string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		controller.SetMigrateHook(t, func(stage string) {
			if stage == "after copy" {
				cancel()
			}
		})
		r, err := controller.MigrateDB(ctx, controller.MigrateDBOptions{From: from, ToFile: to, Getenv: noEnv})
		if err != nil || !r.Retired {
			t.Fatalf("%+v, %v", r, err)
		}
		if at, _ := retiredState(t, from); !at.Valid {
			t.Error("the source is not retired")
		}
	}
	t.Run("sqlite", func(t *testing.T) {
		run(t, src.cfg, sqliteBoot(t, filepath.Join(t.TempDir(), "to.db")))
	})
	t.Run("postgresql", func(t *testing.T) {
		pg, _ := pgDatabase(t)
		if _, err := migrateDB(newMigrateHost(t).cfg, pg, true); err != nil {
			t.Fatal(err)
		}
		run(t, pg, sqliteBoot(t, filepath.Join(t.TempDir(), "to.db")))
	})
}

// TestMigrateDB_FailedCopyRemovesOnlyItsOwnFiles (N6): a target this command created is removed
// when the copy fails, and a file of the target's name that existed before stays.
func TestMigrateDB_FailedCopyRemovesOnlyItsOwnFiles(t *testing.T) {
	src := newMigrateHost(t)
	target := filepath.Join(t.TempDir(), "to.db")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := controller.MigrateDB(ctx, controller.MigrateDBOptions{From: src.cfg, ToFile: sqliteBoot(t, target), Getenv: noEnv,
		Progress: func(string, int64) { cancel() }})
	if err == nil {
		t.Fatal("a cancelled copy succeeded")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the failed copy left the target: %v", err)
	}
	assertNotRetired(t, src.cfg)

	// What existed before is not removed, whatever else the cleanup removes.
	other := filepath.Join(t.TempDir(), "other.db")
	if err := os.WriteFile(other+"-wal", []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	remove, err := controller.PlanTarget(other)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{other, other + ".lock"} { // made by the command, the lock too
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	remove()
	if _, err := os.Stat(other + ".lock"); err != nil {
		t.Errorf("the lock file, which a controller may hold, was removed: %v", err)
	}
	if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a file the command made was not removed: %v", err)
	}
	if b, err := os.ReadFile(other + "-wal"); err != nil || string(b) != "mine" {
		t.Errorf("a file that existed before: %q, %v", b, err)
	}
}

// TestMigrateDB_LockLostBeforeRetire (N7): a PostgreSQL lock lost after the copy committed, before
// the retirement, stops the command without retiring the source.
func TestMigrateDB_LockLostBeforeRetire(t *testing.T) {
	src := newMigrateHost(t)
	pgBoot, dsn := pgDatabase(t)
	controller.SetMigrateHook(t, func(stage string) {
		if stage == "after copy" {
			killLockSession(t, dsn)
		}
	})
	_, err := migrateDB(src.cfg, pgBoot, false)
	if !errors.Is(err, controller.ErrLockLost) {
		t.Fatalf("a lock lost after the copy: %v", err)
	}
	assertNotRetired(t, src.cfg)
}

// TestMigrateDB_SnapshotOfTheSource (N7): the copy reads the source inside the transaction that
// holds it, so a write committed to a PostgreSQL source after that moment is not in the target.
func TestMigrateDB_SnapshotOfTheSource(t *testing.T) {
	src := newMigrateHost(t)
	pg, dsn := pgDatabase(t)
	if _, err := migrateDB(src.cfg, pg, true); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := openBoot(t, pg).Reader.QueryRow("SELECT seq FROM config_seq").Scan(&before); err != nil {
		t.Fatal(err)
	}
	controller.SetMigrateHook(t, func(stage string) {
		if stage != "before copy" {
			return
		}
		other, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = other.Close() }()
		if _, err := other.Writer.Exec("UPDATE config_seq SET seq = seq + 1000"); err != nil {
			t.Error(err)
		}
	})
	to := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	if _, err := migrateDB(pg, to, true); err != nil {
		t.Fatal(err)
	}
	var after int64
	if err := openBoot(t, to).Reader.QueryRow("SELECT seq FROM config_seq").Scan(&after); err != nil || after != before {
		t.Errorf("config_seq in the target %d (%v), want the %d of the source's snapshot", after, err, before)
	}
}

// TestMigrateDB_OtherUser: migrate-db refuses to run as a user other than the owner of the
// directory of the source or of the target, so that nothing it creates crosses users.
func TestMigrateDB_OtherUser(t *testing.T) {
	src := newMigrateHost(t)
	target := filepath.Join(t.TempDir(), "to.db")
	pg, _ := pgDatabase(t)
	if _, err := migrateDB(src.cfg, pg, true); err != nil {
		t.Fatal(err)
	}
	controller.SetEffectiveUID(t, os.Geteuid()+1)
	if _, err := migrateDB(src.cfg, sqliteBoot(t, target), false); !errors.Is(err, controller.ErrOtherUser) || !strings.Contains(err.Error(), "sudo -u") {
		t.Errorf("another user, a SQLite source: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the target file exists: %v", err)
	}
	if _, err := migrateDB(pg, sqliteBoot(t, target), false); !errors.Is(err, controller.ErrOtherUser) {
		t.Errorf("another user, a SQLite target only: %v", err)
	}
	assertNotRetired(t, src.cfg)
}

// TestMigrateDB_LinkedTargetName (B1): a target whose own name is a dangling link, a link to a
// file, a hard-linked file or a directory is refused, and nothing is created or changed behind it.
func TestMigrateDB_LinkedTargetName(t *testing.T) {
	src := newMigrateHost(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("VICTIM"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, plant := range map[string]func(target string) error{
		"dangling link":    func(target string) error { return os.Symlink(filepath.Join(filepath.Dir(target), "nowhere"), target) },
		"link to a file":   func(target string) error { return os.Symlink(victim, target) },
		"hard link":        func(target string) error { return os.Link(victim, target) },
		"directory":        func(target string) error { return os.Mkdir(target, 0o700) },
		"hard-linked lock": func(target string) error { return os.Link(victim, target+".lock") },
	} {
		target := filepath.Join(t.TempDir(), "to.db")
		if err := plant(target); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := migrateDB(src.cfg, sqliteBoot(t, target), false); !errors.Is(err, controller.ErrLinkedState) {
			t.Errorf("%s: %v", name, err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "VICTIM" {
			t.Errorf("%s: the destination changed: %q", name, b)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(target), "nowhere")); err == nil {
			t.Errorf("%s: a file was created behind the link", name)
		}
	}
	assertNotRetired(t, src.cfg)
}

// TestOpenSQLite_CreateNeverFollowsLinks (B1): Create makes the file exclusively and refuses
// anything that exists but a regular file, whatever the migrate-db checks before it say.
func TestOpenSQLite_CreateNeverFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	dangling := filepath.Join(dir, "dangling.db")
	behind := filepath.Join(dir, "behind.db")
	if err := os.Symlink(behind, dangling); err != nil {
		t.Fatal(err)
	}
	if db, err := store.OpenSQLite(context.Background(), dangling, store.SQLiteOptions{Create: true}); err == nil {
		_ = db.Close()
		t.Error("a dangling link was accepted")
	}
	if _, err := os.Lstat(behind); err == nil {
		t.Error("the file behind the dangling link was created")
	}
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("VICTIM"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(existing, link); err != nil {
		t.Fatal(err)
	}
	if db, err := store.OpenSQLite(context.Background(), link, store.SQLiteOptions{Create: true}); err == nil {
		_ = db.Close()
		t.Error("a link to a file was accepted")
	}
	if b, _ := os.ReadFile(existing); string(b) != "VICTIM" {
		t.Errorf("the destination changed: %q", b)
	}
	fresh := filepath.Join(dir, "fresh.db")
	db, err := store.OpenSQLite(context.Background(), fresh, store.SQLiteOptions{Create: true})
	if err != nil || !db.Created {
		t.Fatalf("a new file: %v", err)
	}
	_ = db.Close()
	if db, err = store.OpenSQLite(context.Background(), fresh, store.SQLiteOptions{Create: true}); err != nil || db.Created {
		t.Errorf("an existing regular file: created %v, %v", db != nil && db.Created, err)
	}
	if db != nil {
		_ = db.Close()
	}
}

// TestMigrateDB_LockedTargetKeepsItsFiles (N6): a target another process holds, and has just
// created, is refused and none of its files is removed.
func TestMigrateDB_LockedTargetKeepsItsFiles(t *testing.T) {
	src := newMigrateHost(t)
	target := filepath.Join(t.TempDir(), "to.db")
	var holder *store.DB
	controller.SetMigrateHook(t, func(stage string) {
		if stage != "before target" {
			return
		}
		var err error
		if holder, err = store.OpenSQLite(context.Background(), target, store.SQLiteOptions{Lock: true, Create: true}); err != nil {
			t.Error(err)
		}
	})
	_, err := migrateDB(src.cfg, sqliteBoot(t, target), false)
	if holder == nil {
		t.Fatal("no holder")
	}
	defer func() { _ = holder.Close() }()
	if !errors.Is(err, controller.ErrStopController) {
		t.Fatalf("a target another process holds: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the holder's database was removed: %v", err)
	}
	if _, err := store.HoldLock(target); !errors.Is(err, store.ErrLocked) {
		t.Errorf("the holder's lock is gone: %v", err)
	}
}

// TestMigrateDB_PostgresWriterBeforeCopy (S1): a writer that holds the share lock of the retired
// check, writes and commits, is in the copy, or the copy waits for it; it is never lost.
func TestMigrateDB_PostgresWriterBeforeCopy(t *testing.T) {
	src := newMigrateHost(t)
	pg, dsn := pgDatabase(t)
	if _, err := migrateDB(src.cfg, pg, true); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := openBoot(t, pg).Reader.QueryRow("SELECT seq FROM config_seq").Scan(&before); err != nil {
		t.Fatal(err)
	}
	guarded, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{RefuseRetired: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guarded.Close() }()
	inside, release, written := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		written <- store.WriteTx(storetest.SystemCtx(t), guarded, func(tx *ent.Tx) error {
			close(inside)
			<-release
			_, err := tx.ExecContext(context.Background(), "UPDATE config_seq SET seq = seq + 1000")
			return err
		})
	}()
	<-inside
	to := sqliteBoot(t, filepath.Join(t.TempDir(), "to.db"))
	migrated := make(chan error, 1)
	go func() { _, err := migrateDB(pg, to, true); migrated <- err }()
	time.Sleep(700 * time.Millisecond) // the copy waits for the writer, or has copied without it
	close(release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := <-migrated; err != nil {
		t.Fatal(err)
	}
	var after int64
	if err := openBoot(t, to).Reader.QueryRow("SELECT seq FROM config_seq").Scan(&after); err != nil || after != before+1000 {
		t.Errorf("config_seq in the target %d (%v), want %d: the writer's commit is lost", after, err, before+1000)
	}
}
