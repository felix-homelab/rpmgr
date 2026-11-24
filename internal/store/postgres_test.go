// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// noPGEnv keeps the developer's PostgreSQL environment and home directory out of a test: pgx reads
// PGPASSWORD, PGSSLMODE, a service file, a .pgpass file and ~/.postgresql for what a DSN leaves out.
func noPGEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PGPASSWORD", "PGSSLMODE", "PGHOST", "PGSERVICE", "PGSERVICEFILE",
		"PGSSLNEGOTIATION", "PGSSLCERT", "PGSSLKEY", "PGSSLROOTCERT", "PGSSLPASSWORD"} {
		t.Setenv(k, "")
	}
	t.Setenv("PGSSLCERTMODE", "allow") // set explicitly empty, pgx refuses it
	if err := os.Unsetenv("PGSSLCERTMODE"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PGPASSFILE", filepath.Join(home, "none"))
}

func isLocalHost(h string) bool {
	return strings.HasPrefix(h, "/") || h == "127.0.0.1" || h == "::1" || h == "localhost"
}

// assertVerified fails unless every remote host of the configuration, and of each fallback, has a
// TLS configuration that verifies the server's name against explicit authorities. It reports
// whether the DSN was refused.
func assertVerified(t *testing.T, dsn string, o store.PostgresOptions) (refused bool) {
	t.Helper()
	cfg, err := store.PostgresConfig(dsn, o)
	if err != nil {
		return true
	}
	check := func(host string, tc *tls.Config) {
		if isLocalHost(host) {
			return
		}
		if tc == nil || tc.ServerName != host || tc.RootCAs == nil || tc.MinVersion < tls.VersionTLS12 {
			t.Errorf("%s: host %s is reachable without verified TLS: %+v", dsn, host, tc)
		}
	}
	check(cfg.Host, cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		check(fb.Host, fb.TLSConfig)
	}
	return false
}

func TestPostgres_RequiresVerifiedTLS(t *testing.T) {
	noPGEnv(t)
	refused := []string{
		"postgres://rpmgr@db.example:5432/rpmgr?sslmode=disable",
		"postgres://rpmgr@db.example/rpmgr?sslmode=allow",
		"postgres://rpmgr@db.example/rpmgr?sslmode=prefer",
		"postgres://rpmgr@db.example/rpmgr", // pgx's default is prefer
		"postgres://rpmgr@10.0.0.5/rpmgr?sslmode=prefer",
		"host=db.example user=rpmgr dbname=rpmgr sslmode=disable",
		// a second host without TLS, behind a loopback one
		"postgres://rpmgr@127.0.0.1,db.example/rpmgr?sslmode=prefer",
		"postgres://rpmgr@127.0.0.1,db.example/rpmgr?sslmode=disable",
		"host=db.example user=rpmgr sslmode=verify-full sslmode=disable", // the last one wins
	}
	for _, dsn := range refused {
		if err := store.PostgresConfigErr(dsn, store.PostgresOptions{}); err == nil || !strings.Contains(err.Error(), "verify-full") {
			t.Errorf("%s: err = %v, want a refusal that asks for verify-full", dsn, err)
		}
	}
	// Whatever the spelling, a remote host ends up with verified TLS or the DSN is refused. These
	// are the ways in which a reading of the mode other than pgx's own differs from pgx's.
	service := writeFile(t, "[evil]\nhost=db.example.com\nsslmode=require\n", 0o600)
	cases := []struct {
		dsn string
		env map[string]string
	}{
		{dsn: "postgres://rpmgr@db.example.com/rpmgr?sslmode=verify-full&sslmode=require"},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr?sslmode=require&sslmode=verify-full"},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr?sslmode=verify-full&ssl=true"},
		{dsn: `sslmode=require application_name=x\ sslmode=verify-full host=db.example.com`},
		{dsn: "postgres://rpmgr@db1.example.com:5432,db2.example.com/rpmgr?sslmode=require", env: map[string]string{"PGSSLMODE": "verify-full"}},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr?sslmode=&sslnegotiation=direct"},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr", env: map[string]string{"PGSSLNEGOTIATION": "direct"}},
		{dsn: "service=evil user=rpmgr", env: map[string]string{"PGSSLMODE": "verify-full", "PGSERVICEFILE": service}},
		{dsn: "user=rpmgr", env: map[string]string{"PGSSLMODE": "verify-full", "PGSERVICEFILE": service, "PGSERVICE": "evil"}},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr?sslmode=require"},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr?sslmode=verify-ca"},
		{dsn: "host=db.example user=rpmgr dbname=rpmgr sslmode=require"},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr?sslmode=verify-full", env: map[string]string{"PGSSLMODE": "disable"}},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr", env: map[string]string{"PGSSLMODE": "require"}},
		{dsn: "postgres://rpmgr@db.example.com/rpmgr", env: map[string]string{"PGHOST": "db.example.com", "PGSSLMODE": "prefer"}},
	}
	for _, c := range cases {
		t.Run(c.dsn, func(t *testing.T) {
			noPGEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			assertVerified(t, c.dsn, store.PostgresOptions{})
		})
	}
	accepted := []string{
		"postgres://rpmgr@db.example/rpmgr?sslmode=verify-full",
		"host=db.example user=rpmgr dbname=rpmgr sslmode=verify-full",
		"postgres://rpmgr@db1.example,db2.example/rpmgr?sslmode=verify-full",
		"postgres://rpmgr@[2001:db8::1]:5432,[2001:db8::2]:5432/rpmgr?sslmode=verify-full",
		"postgres://rpmgr@db.example/rpmgr?sslmode=require&sslrootcert=system",
		"postgres://rpmgr@127.0.0.1:5432/rpmgr?sslmode=disable",
		"postgres://rpmgr@[::1]:5432/rpmgr?sslmode=disable",
		"postgres://rpmgr@localhost/rpmgr?sslmode=disable",
		"host=/run/postgresql user=rpmgr dbname=rpmgr sslmode=disable",
	}
	for _, dsn := range accepted {
		if assertVerified(t, dsn, store.PostgresOptions{}) {
			t.Errorf("%s: refused: %v", dsn, store.PostgresConfigErr(dsn, store.PostgresOptions{}))
		}
	}
}

func TestPostgres_RefusesClientKeyPassphrase(t *testing.T) {
	noPGEnv(t)
	const local = "postgres://rpmgr@127.0.0.1/rpmgr?sslmode=disable"
	if err := store.PostgresConfigErr(local+"&sslpassword=x", store.PostgresOptions{}); err == nil {
		t.Error("sslpassword in the DSN was accepted")
	}
	t.Setenv("PGSSLPASSWORD", "x")
	if err := store.PostgresConfigErr(local, store.PostgresOptions{}); err == nil {
		t.Error("PGSSLPASSWORD was accepted")
	}
}

func TestPostgres_IgnoresRootCertInHomeDirectory(t *testing.T) {
	noPGEnv(t)
	home := os.Getenv("HOME")
	if err := os.MkdirAll(filepath.Join(home, ".postgresql"), 0o700); err != nil { //nolint:gosec // G703: a test directory
		t.Fatal(err)
	}
	ca := newTestCA(t)
	if err := os.WriteFile(filepath.Join(home, ".postgresql", "root.crt"), ca.pem, 0o600); err != nil { //nolint:gosec // G703: a test directory
		t.Fatal(err)
	}
	cfg, err := store.PostgresConfig("postgres://rpmgr@db.example/rpmgr?sslmode=verify-full", store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sys, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLSConfig.RootCAs.Equal(sys) {
		t.Fatal("the root certificate in the home directory is trusted")
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

// stripPassword returns dsn without its password.
func stripPassword(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.User(u.User.Username())
	return u.String()
}

func TestPostgres_WrongPasswordNotInError(t *testing.T) {
	dsn := pgDSN(t)
	const wrong = "wr0ng-Passw0rd-value"
	_, err := store.OpenPostgres(context.Background(), stripPassword(t, dsn), store.PostgresOptions{PasswordFile: writeFile(t, wrong, 0o600)})
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
	open := func(o store.PostgresOptions) (*store.DB, error) { return storetest.OpenPostgres(t, dsn, o) }
	first, err := open(store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	// A single controller holds the lock exclusively: a second controller, a replica and a tool
	// that needs the database to itself all get ErrLocked.
	for name, o := range map[string]store.PostgresOptions{
		"second controller": {Lock: true},
		"replica":           {Lock: true, Shared: true},
	} {
		if _, err := open(o); !errors.Is(err, store.ErrLocked) {
			t.Fatalf("%s next to a controller: err = %v, want ErrLocked", name, err)
		}
	}
	admin, err := open(store.PostgresOptions{})
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
	if err := first.Close(); err != nil { // closing twice must not panic
		t.Fatalf("second Close: %v", err)
	}
	// Replicas share the lock; nothing exclusive gets it meanwhile.
	r1, err := open(store.PostgresOptions{Lock: true, Shared: true})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := open(store.PostgresOptions{Lock: true, Shared: true})
	if err != nil {
		t.Fatalf("a second replica: %v", err)
	}
	if _, err := open(store.PostgresOptions{Lock: true}); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("exclusive next to replicas: err = %v, want ErrLocked", err)
	}
	_ = r1.Close()
	_ = r2.Close()
	second, err := open(store.PostgresOptions{Lock: true})
	if err != nil {
		t.Fatalf("after the replicas stopped: %v", err)
	}
	defer func() { _ = second.Close() }()
	if _, err := open(store.PostgresOptions{Lock: true, Shared: true}); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("a replica next to an exclusive holder: err = %v, want ErrLocked", err)
	}

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
