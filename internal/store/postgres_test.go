// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// noPGEnv keeps the developer's PostgreSQL environment out of a test: pgx reads PGPASSWORD,
// PGSSLMODE and a .pgpass file for what a DSN leaves out.
func noPGEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PGPASSWORD", "PGSSLMODE", "PGHOST", "PGSERVICE", "PGSSLROOTCERT"} {
		t.Setenv(k, "")
	}
	t.Setenv("PGPASSFILE", filepath.Join(t.TempDir(), "none"))
}

func TestPostgres_RequiresVerifiedTLS(t *testing.T) {
	noPGEnv(t)
	refused := []string{
		"postgres://rpmgr@db.example:5432/rpmgr?sslmode=disable",
		"postgres://rpmgr@db.example/rpmgr?sslmode=allow",
		"postgres://rpmgr@db.example/rpmgr?sslmode=prefer",
		"postgres://rpmgr@db.example/rpmgr?sslmode=require",
		"postgres://rpmgr@db.example/rpmgr?sslmode=verify-ca",
		"postgres://rpmgr@db.example/rpmgr", // pgx's default is prefer
		"postgres://rpmgr@10.0.0.5/rpmgr?sslmode=require",
		"host=db.example user=rpmgr dbname=rpmgr sslmode=require",
		"host=db.example user=rpmgr sslmode=verify-full sslmode=disable", // the last one wins
		"host=db.example user=rpmgr user=rpmgr sslmode='require'",
		// a second host without verified TLS, behind a loopback one
		"postgres://rpmgr@127.0.0.1,db.example/rpmgr?sslmode=prefer",
	}
	for _, dsn := range refused {
		err := store.PostgresConfigErr(dsn, store.PostgresOptions{})
		if err == nil || !strings.Contains(err.Error(), "verify-full") {
			t.Errorf("%s: err = %v, want a refusal that asks for verify-full", dsn, err)
		}
	}
	accepted := []string{
		"postgres://rpmgr@db.example/rpmgr?sslmode=verify-full",
		"host=db.example user=rpmgr dbname=rpmgr sslmode=verify-full",
		"postgres://rpmgr@db1.example,db2.example/rpmgr?sslmode=verify-full",
		"host=db.example user=rpmgr sslmode=disable sslmode='verify-full'",
		"postgres://rpmgr@127.0.0.1:5432/rpmgr?sslmode=disable",
		"postgres://rpmgr@[::1]:5432/rpmgr?sslmode=disable",
		"postgres://rpmgr@localhost/rpmgr?sslmode=disable",
		"host=/run/postgresql user=rpmgr dbname=rpmgr sslmode=disable",
	}
	for _, dsn := range accepted {
		if err := store.PostgresConfigErr(dsn, store.PostgresOptions{}); err != nil {
			t.Errorf("%s: %v", dsn, err)
		}
	}
}

func TestPostgres_TLSModeFromEnvironment(t *testing.T) {
	noPGEnv(t)
	t.Setenv("PGSSLMODE", "verify-full")
	if err := store.PostgresConfigErr("postgres://rpmgr@db.example/rpmgr", store.PostgresOptions{}); err != nil {
		t.Fatalf("PGSSLMODE=verify-full: %v", err)
	}
	t.Setenv("PGSSLMODE", "require")
	if err := store.PostgresConfigErr("postgres://rpmgr@db.example/rpmgr", store.PostgresOptions{}); err == nil {
		t.Fatal("PGSSLMODE=require was accepted")
	}
}

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // not narrowed by the umask
		t.Fatal(err)
	}
	return p
}

func TestPostgres_PasswordOnlyFromFileOrCredential(t *testing.T) {
	noPGEnv(t)
	const pw = "s3cr3t-Passw0rd-value"
	const local = "postgres://rpmgr@127.0.0.1/rpmgr?sslmode=disable"
	mustRefuse := func(t *testing.T, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want one with %q", err, want)
		}
		if strings.Contains(err.Error(), pw) {
			t.Fatalf("the error names the password: %v", err)
		}
	}
	t.Run("in the DSN", func(t *testing.T) {
		mustRefuse(t, store.PostgresConfigErr("postgres://rpmgr:"+pw+"@127.0.0.1/rpmgr?sslmode=disable", store.PostgresOptions{}), "password_file")
		mustRefuse(t, store.PostgresConfigErr("host=127.0.0.1 user=rpmgr password="+pw+" sslmode=disable", store.PostgresOptions{}), "password_file")
	})
	t.Run("unparsable DSN", func(t *testing.T) {
		mustRefuse(t, store.PostgresConfigErr("postgres://rpmgr:"+pw+"@127.0.0.1:notaport/rpmgr", store.PostgresOptions{}), "cannot be parsed")
	})
	t.Run("PGPASSWORD", func(t *testing.T) {
		t.Setenv("PGPASSWORD", pw)
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{}), "PGPASSWORD")
	})
	t.Run(".pgpass", func(t *testing.T) {
		t.Setenv("PGPASSFILE", writeFile(t, "127.0.0.1:5432:rpmgr:rpmgr:"+pw+"\n", 0o600))
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{}), ".pgpass")
	})
	t.Run("file others may read", func(t *testing.T) {
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: writeFile(t, pw, 0o644)}), "mode 0644")
	})
	t.Run("empty or several lines", func(t *testing.T) {
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: writeFile(t, "\n", 0o600)}), "one non-empty line")
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: writeFile(t, pw+"\n"+pw+"\n", 0o600)}), "one non-empty line")
	})
	t.Run("too large", func(t *testing.T) {
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: writeFile(t, strings.Repeat(pw, 400), 0o600)}), "larger than")
	})
	t.Run("missing file", func(t *testing.T) {
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: filepath.Join(t.TempDir(), "nope")}), "database password file")
	})
	t.Run("file and credential", func(t *testing.T) {
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: writeFile(t, pw, 0o600), PasswordCredential: "pg"}), "not both")
	})
	t.Run("credential without CREDENTIALS_DIRECTORY", func(t *testing.T) {
		getenv := func(string) string { return "" }
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordCredential: "pg", Getenv: getenv}), "CREDENTIALS_DIRECTORY")
	})
	t.Run("credential name with a path", func(t *testing.T) {
		getenv := func(string) string { return t.TempDir() }
		mustRefuse(t, store.PostgresConfigErr(local, store.PostgresOptions{PasswordCredential: "../pg", Getenv: getenv}), "invalid name")
	})
	t.Run("file and credential accepted", func(t *testing.T) {
		if err := store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: writeFile(t, pw+"\n", 0o400)}); err != nil {
			t.Fatal(err)
		}
		f := writeFile(t, pw, 0o600)
		getenv := func(k string) string {
			if k == "CREDENTIALS_DIRECTORY" {
				return filepath.Dir(f)
			}
			return ""
		}
		if err := store.PostgresConfigErr(local, store.PostgresOptions{PasswordCredential: filepath.Base(f), Getenv: getenv}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPostgres_RefusesOldServer(t *testing.T) {
	for num, ok := range map[int]bool{140013: false, 90624: false, 150000: true, 150014: true, 180001: true} {
		err := store.CheckServerVersion(num)
		if (err == nil) != ok {
			t.Errorf("%d: err = %v, want ok=%v", num, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "needs 15 or later") {
			t.Errorf("%d: %v", num, err)
		}
	}
}

// pgDSN returns the DSN of a new, empty PostgreSQL database.
func pgDSN(t *testing.T) string {
	t.Helper()
	return storetest.NewPostgresDatabase(t)
}

func TestPostgres_WrongPasswordNotInError(t *testing.T) {
	dsn := pgDSN(t)
	const wrong = "wr0ng-Passw0rd-value"
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.User(u.User.Username())
	_, err = store.OpenPostgres(context.Background(), u.String(), store.PostgresOptions{PasswordFile: writeFile(t, wrong, 0o600)})
	if err == nil {
		t.Skip("the test server accepts any password")
	}
	if strings.Contains(err.Error(), wrong) {
		t.Fatalf("the error names the password: %v", err)
	}
}

func TestPostgres_ControllerLock(t *testing.T) {
	store.SetLockCheckInterval(t.Cleanup, 50*time.Millisecond)
	dsn := pgDSN(t)
	first, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	// Controllers are replicas: a second one runs next to the first.
	replica, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatalf("a second controller replica: %v", err)
	}
	// restore and migrate-db need the database to themselves.
	if _, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true, Exclusive: true}); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("exclusive next to controllers: err = %v, want ErrLocked", err)
	}
	admin, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatalf("an administration command next to the controller: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if admin.LockLost() != nil {
		t.Fatal("LockLost without the lock must be nil")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := replica.Close(); err != nil {
		t.Fatal(err)
	}
	excl, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true, Exclusive: true})
	if err != nil {
		t.Fatalf("exclusive with no controller: %v", err)
	}
	if _, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true}); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("a controller while an exclusive holder runs: err = %v, want ErrLocked", err)
	}
	if err := excl.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatalf("after the exclusive holder stopped: %v", err)
	}
	defer func() { _ = second.Close() }()

	// The session that holds the lock ends: the controller is told, and another one can start.
	if _, err := admin.Writer.Exec(`SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype = 'advisory' AND classid = 1919970663 AND objid = 2 AND granted`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.LockLost():
	case <-time.After(10 * time.Second):
		t.Fatal("LockLost was not closed after the lock's session ended")
	}
	third, err := storetest.OpenPostgres(t, dsn, store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatalf("after the lock was lost: %v", err)
	}
	_ = third.Close()
}

func TestMigrate_TwoMigratorsOneRuns(t *testing.T) {
	dsn := pgDSN(t)
	dir, err := migrations.Dir(store.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	files, err := dir.Files()
	if err != nil {
		t.Fatal(err)
	}
	var dbs [2]*store.DB
	for i := range dbs {
		if dbs[i], err = storetest.OpenPostgres(t, dsn, store.PostgresOptions{}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dbs[i].Close() })
	}
	var wg sync.WaitGroup
	var applied [2]int
	var errs [2]error
	for i := range dbs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applied[i], errs[i] = store.Migrate(context.Background(), dbs[i], dir)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if applied[0]+applied[1] != len(files) || (applied[0] != 0 && applied[1] != 0) {
		t.Fatalf("applied %v of %d files, want all by one migrator", applied, len(files))
	}
	var n int
	if err := dbs[0].Reader.QueryRow("SELECT count(*) FROM " + store.RevisionTable).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(files) {
		t.Fatalf("%d revisions, want %d", n, len(files))
	}
}
