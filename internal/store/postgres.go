// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"ariga.io/atlas/sql/migrate"
	atlaspostgres "ariga.io/atlas/sql/postgres"
	atlasschema "ariga.io/atlas/sql/schema"
	atlassqlite "ariga.io/atlas/sql/sqlite"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// MinPostgresMajor is the oldest PostgreSQL major version the controller runs on: every major
// version the PostgreSQL project still supports when an rpmgr release is made
// (docs/06-data-model.md, "Database engines").
const MinPostgresMajor = 15

// Advisory locks on PostgreSQL take the two-key form pg_advisory_lock(namespace, lock), so they
// cannot collide with a single-key lock of another application in the same database.
const (
	advisoryNamespace  = 0x72706d67 // "rpmg"
	advisoryMigrations = 1          // held while migrations run; a second migrator waits
	advisoryController = 2          // shared by every running controller; exclusive for restore and migrate-db
)

// lockCheckInterval is how often the connection that holds the controller lock is checked.
var lockCheckInterval = 5 * time.Second

// maxPasswordFile bounds the database password file.
const maxPasswordFile = 4096

// PostgresOptions are the settings of OpenPostgres that the DSN does not carry.
type PostgresOptions struct {
	// PasswordFile is the file with the database password (database.password_file): mode 0600 or
	// 0400, one line. The DSN itself must not carry a password.
	PasswordFile string
	// PasswordCredential is the name of a systemd credential with the password, as an alternative
	// to PasswordFile.
	PasswordCredential string
	// Getenv reads $CREDENTIALS_DIRECTORY for PasswordCredential; default os.Getenv.
	Getenv func(string) string
	// Lock takes the controller lock, a session advisory lock, for as long as the database is
	// open. Controllers take it shared, so replicas run side by side; it fails with ErrLocked while
	// an exclusive holder has it. Commands that may run next to a controller leave it off.
	Lock bool
	// Exclusive makes Lock exclusive, for restore and migrate-db: it fails with ErrLocked while any
	// controller runs, and no controller starts while it is held.
	Exclusive bool
}

// OpenPostgres opens a PostgreSQL database. A server that is not on the loopback interface or a
// Unix socket must be reached with sslmode=verify-full; the password comes only from a file or a
// systemd credential, never from the DSN, PGPASSWORD or a .pgpass file; and the server must run
// MinPostgresMajor or later (docs/06-data-model.md, "Database engines"). No error names the
// password.
func OpenPostgres(ctx context.Context, dsn string, o PostgresOptions) (*DB, error) {
	cfg, err := postgresConfig(dsn, o)
	if err != nil {
		return nil, err
	}
	pool := stdlib.OpenDB(*cfg)
	db := &DB{Dialect: Postgres, Writer: pool, Reader: pool, unlock: func() error { return nil }}
	if err := checkPostgres(ctx, pool); err != nil {
		_ = db.Close()
		return nil, err
	}
	if o.Lock {
		unlock, lost, err := holdControllerLock(ctx, cfg, o.Exclusive)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		db.unlock, db.lockLost = unlock, lost
	}
	db.client = NewClient(Postgres, pool)
	db.readClient = db.client
	return db, nil
}

// postgresConfig parses dsn, refuses a password from anywhere but o, and checks TLS.
func postgresConfig(dsn string, o PostgresOptions) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("store: PostgreSQL DSN: cannot be parsed") // pgx's message quotes it
	}
	if cfg.Password != "" {
		return nil, errors.New("store: PostgreSQL: the DSN, PGPASSWORD or a .pgpass file sets a password; " +
			"give it in database.password_file or a systemd credential instead")
	}
	if err := checkTLS(dsn, &cfg.Config); err != nil {
		return nil, err
	}
	pw, err := readPassword(o)
	if err != nil {
		return nil, err
	}
	cfg.Password = pw
	return cfg, nil
}

// checkTLS requires sslmode=verify-full for every host that is not loopback or a Unix socket:
// TLS with the certificate chain and the host name verified, and no plain-text fallback. pgx does
// not keep the mode it parsed, and the settings of its tls.Config that tell the modes apart are
// banned names (docs/03), so the mode is read from the DSN and the environment here and checked
// against the TLS configuration pgx built from it.
func checkTLS(dsn string, c *pgconn.Config) error {
	hosts := []string{c.Host}
	tlsOn := []bool{c.TLSConfig != nil}
	for _, fb := range c.Fallbacks {
		hosts = append(hosts, fb.Host)
		tlsOn = append(tlsOn, fb.TLSConfig != nil)
	}
	mode := sslMode(dsn)
	for i, h := range hosts {
		if !localHost(h) && (mode != "verify-full" || !tlsOn[i]) {
			return fmt.Errorf("store: PostgreSQL at %s: use sslmode=verify-full (with sslrootcert); "+
				"only the loopback interface or a Unix socket may go without verified TLS", h)
		}
	}
	return nil
}

// sslMode returns the sslmode of a PostgreSQL DSN in URL or key/value form, else $PGSSLMODE, else
// "prefer". The last of repeated keys wins, as in pgx. A DSN it cannot read gives "".
func sslMode(dsn string) string {
	mode := ""
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		if u, err := url.Parse(dsn); err == nil {
			mode = u.Query().Get("sslmode")
		}
	} else {
		mode = keywordValue(dsn, "sslmode")
	}
	if mode == "" {
		mode = os.Getenv("PGSSLMODE")
	}
	if mode == "" {
		mode = "prefer"
	}
	return mode
}

// keywordValue returns the value of key in a "key=value key2='quoted value'" connection string.
func keywordValue(dsn, key string) string {
	val := ""
	for rest := strings.TrimSpace(dsn); rest != ""; rest = strings.TrimSpace(rest) {
		k, r, ok := strings.Cut(rest, "=")
		if !ok {
			return ""
		}
		k, r = strings.TrimSpace(k), strings.TrimLeft(r, " \t\r\n")
		var v strings.Builder
		if strings.HasPrefix(r, "'") {
			i := 1
			for ; i < len(r) && r[i] != '\''; i++ {
				if r[i] == '\\' && i+1 < len(r) {
					i++
				}
				v.WriteByte(r[i])
			}
			if i >= len(r) {
				return ""
			}
			rest = r[i+1:]
		} else {
			end := strings.IndexAny(r, " \t\r\n")
			if end < 0 {
				end = len(r)
			}
			v.WriteString(r[:end])
			rest = r[end:]
		}
		if k == key {
			val = v.String()
		}
	}
	return val
}

// localHost reports whether host is a Unix socket directory or a loopback address.
func localHost(host string) bool {
	if strings.HasPrefix(host, "/") || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// readPassword reads the password from o's file or credential; without either there is none,
// for a server that authenticates by peer or certificate.
func readPassword(o PostgresOptions) (string, error) {
	path, what := o.PasswordFile, "database password file"
	switch {
	case o.PasswordFile != "" && o.PasswordCredential != "":
		return "", errors.New("store: PostgreSQL: give a password file or a credential, not both")
	case o.PasswordCredential != "":
		getenv := o.Getenv
		if getenv == nil {
			getenv = os.Getenv
		}
		p, err := secret.CredentialPath(o.PasswordCredential, getenv)
		if err != nil {
			return "", fmt.Errorf("store: database password credential: %w", err)
		}
		path, what = p, "database password credential"
	case o.PasswordFile == "":
		return "", nil
	}
	data, err := secret.ReadFile(path, what, o.PasswordCredential != "", maxPasswordFile)
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if pw == "" || strings.ContainsAny(pw, "\x00\r\n") {
		return "", fmt.Errorf("store: %s %s: must hold one non-empty line", what, path)
	}
	return pw, nil
}

// checkPostgres connects and refuses a server older than MinPostgresMajor.
func checkPostgres(ctx context.Context, pool *sql.DB) error {
	var num int
	if err := pool.QueryRowContext(ctx, "SHOW server_version_num").Scan(&num); err != nil {
		return fmt.Errorf("store: open PostgreSQL: %w", err)
	}
	return checkServerVersion(num)
}

// checkServerVersion checks a server_version_num, such as 180001 for 18.1.
func checkServerVersion(num int) error {
	if major := num / 10000; major < MinPostgresMajor {
		return fmt.Errorf("store: PostgreSQL %d is not supported; rpmgr needs %d or later", major, MinPostgresMajor)
	}
	return nil
}

// holdControllerLock takes the controller's advisory lock, shared or exclusive, on a connection of its own, outside the
// pool, and checks that connection every lockCheckInterval: the lock ends with the session, so a
// lost connection closes the returned channel and the controller must stop.
func holdControllerLock(ctx context.Context, cfg *pgx.ConnConfig, exclusive bool) (func() error, <-chan struct{}, error) {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("store: controller lock: %w", err)
	}
	fn := "pg_try_advisory_lock_shared"
	if exclusive {
		fn = "pg_try_advisory_lock"
	}
	var got bool
	if err := conn.QueryRow(ctx, "SELECT "+fn+"($1, $2)", advisoryNamespace, advisoryController).Scan(&got); err != nil {
		_ = conn.Close(ctx)
		return nil, nil, fmt.Errorf("store: controller lock: %w", err)
	}
	if !got {
		_ = conn.Close(ctx)
		return nil, nil, ErrLocked // the lock is held shared by a controller or exclusively by a tool
	}
	lost, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(lockCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lockCheckInterval)
				err := conn.Ping(pctx)
				cancel()
				if err != nil {
					close(lost)
					return
				}
			}
		}
	}()
	unlock := func() error {
		close(stop)
		<-done
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return conn.Close(cctx) // ending the session releases the lock
	}
	return unlock, lost, nil
}

// lockMigrations takes the migration lock on PostgreSQL, waiting while another process migrates;
// on SQLite the single writer connection already serialises migrations.
func lockMigrations(ctx context.Context, db *DB) (func(), error) {
	if db.Dialect != Postgres {
		return func() {}, nil
	}
	conn, err := db.Writer.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1, $2)", advisoryNamespace, advisoryMigrations); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("store: migration lock: %w", err)
	}
	return func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1, $2)", advisoryNamespace, advisoryMigrations)
		_ = conn.Close()
	}, nil
}

// atlasDriver opens Atlas's migration driver for d on conn.
func atlasDriver(d string, conn atlasschema.ExecQuerier) (migrate.Driver, error) {
	switch d {
	case SQLite:
		return atlassqlite.Open(conn)
	case Postgres:
		return atlaspostgres.Open(conn)
	}
	return nil, fmt.Errorf("store: unsupported dialect %q", d)
}
