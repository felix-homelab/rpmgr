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
	sealed, err := sealer.Seal(secret.Context{Table: "instance_secrets", Column: "value_enc", RowID: "canary"}, secret.New(canary))
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
