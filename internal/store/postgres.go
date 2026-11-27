// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"ariga.io/atlas/sql/migrate"
	atlaspostgres "ariga.io/atlas/sql/postgres"
	atlasschema "ariga.io/atlas/sql/schema"
	atlassqlite "ariga.io/atlas/sql/sqlite"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"

	entsql "entgo.io/ent/dialect/sql"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// MinPostgresMajor is the oldest PostgreSQL major version the controller runs on: every major
// version the PostgreSQL project still supports when an rpmgr release is made
// (docs/06-data-model.md, "Database engines").
const MinPostgresMajor = 15

// MaxTestedPostgresMajor is the newest PostgreSQL major version the tests run on; a newer server is
// used, with a warning in the log.
const MaxTestedPostgresMajor = 19

// Advisory locks on PostgreSQL take the two-key form pg_advisory_lock(namespace, lock), so they
// cannot collide with a single-key lock of another application in the same database.
const (
	advisoryNamespace  = 0x72706d67 // "rpmg"
	advisoryMigrations = 1          // held while migrations run; a second migrator waits
	advisoryController = 2          // exclusive for a single controller, restore and migrate-db; shared for replicas
)

// lockCheckInterval is how often the connection that holds the controller lock is checked.
var lockCheckInterval = 5 * time.Second

// LockStopBound is the longest a controller can go on after it lost the controller lock before it
// knows: an interval until the next check and the check itself (docs/03-connections.md, "Timeouts,
// keepalive and backoff"). A controller that takes the lock waits this long, plus a margin, before
// its first write, so that the one that lost it has stopped writing: its database fences every
// write from the moment the loss is seen.
func LockStopBound() time.Duration { return 2 * lockCheckInterval }

// migrationLockWait is how long a migrator waits for the migration lock, which another migrator
// holds for the length of its migrations (docs/03-connections.md).
var migrationLockWait = 2 * time.Minute

// lockKeepAlive is the TCP keepalive of the connection that holds the controller lock, so that
// a middlebox does not drop it for being idle.
const lockKeepAlive = 15 * time.Second

// connectTimeout bounds opening a PostgreSQL database: the first connection, the version check and
// the controller lock (docs/03-connections.md, "Timeouts, keepalive and backoff"). A server that
// does not answer stops the controller at start with an error instead of a hang.
var connectTimeout = 10 * time.Second

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
	// open. It is exclusive unless Shared is set, so a missing flag fails safe: a second controller,
	// restore or migrate-db gets ErrLocked while another holder has it. Commands that may run next to
	// a controller leave Lock off.
	Lock bool
	// Shared makes Lock shared, for the replicas of a controller cluster (listen.internal) and for
	// `rpmgr migrate`: any number of shared holders, none while an exclusive one has the lock.
	Shared bool
	// RefuseRetired makes every write transaction check that `rpmgr migrate-db` has not retired the
	// database, for commands that take no controller lock.
	RefuseRetired bool
}

// OpenPostgres opens a PostgreSQL database. A server that is not on the loopback interface or a
// Unix socket must be reached with sslmode=verify-full; the password comes only from a file or a
// systemd credential, never from the DSN, PGPASSWORD or a .pgpass file; and the server must run
// MinPostgresMajor or later (docs/06-data-model.md, "Database engines"). No error or log line names
// the password.
func OpenPostgres(ctx context.Context, dsn string, o PostgresOptions) (*DB, error) {
	cfg, err := postgresConfig(dsn, o)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	// Every connection of a controller carries its own name, so that the next exclusive holder can
	// end the sessions of the controller before it (endPreviousSessions).
	name := ""
	if o.Lock {
		name = controllerApp + randomHex()
		if cfg.RuntimeParams == nil {
			cfg.RuntimeParams = map[string]string{}
		}
		cfg.RuntimeParams["application_name"] = name
	}
	pool := stdlib.OpenDB(*cfg)
	db := &DB{Dialect: Postgres, Writer: pool, Reader: pool, unlock: func() error { return nil }, refuseRetired: o.RefuseRetired}
	if err := checkPostgres(ctx, pool); err != nil {
		_ = db.Close()
		return nil, unreachable(ctx, err)
	}
	if o.Lock {
		unlock, lost, err := holdControllerLock(ctx, cfg, o.Shared, name)
		if err != nil {
			_ = db.Close()
			return nil, unreachable(ctx, err)
		}
		db.unlock, db.lockLost = unlock, lost
		db.fence.exclusive = !o.Shared
	}
	db.fence.lost = db.lockLost
	db.client = ent.NewClient(ent.Driver(fencedDriver{Driver: entsql.OpenDB(Postgres, pool), fence: &db.fence}))
	db.readClient = db.client
	return db, nil
}

// unreachable names the timeout when ctx ended while opening, so that a server that does not
// answer is not reported as "context deadline exceeded" alone.
func unreachable(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && !errors.Is(err, ErrLocked) {
		return fmt.Errorf("store: PostgreSQL did not answer within %s: %w", connectTimeout, err)
	}
	return err
}

// dsnKeys are the parameters a DSN may set. Others, such as service and sslpassword, are refused:
// they would read settings from places rpmgr does not control.
var dsnKeys = []string{
	"host", "port", "user", "password", "dbname", "database", "sslmode", "ssl", "sslrootcert",
	"sslcert", "sslkey", "connect_timeout", "application_name", "target_session_attrs",
}

// postgresConfig parses dsn, refuses a password or a client key passphrase from anywhere but o, and
// makes the TLS configuration of every remote host verified.
func postgresConfig(dsn string, o PostgresOptions) (*pgx.ConnConfig, error) {
	if os.Getenv("PGSSLPASSWORD") != "" {
		return nil, errors.New("store: PostgreSQL: a client key passphrase (PGSSLPASSWORD, sslpassword) is not supported")
	}
	// A service file would set parameters, such as sslrootcert, that the DSN does not show.
	if os.Getenv("PGSERVICE") != "" || os.Getenv("PGSERVICEFILE") != "" {
		return nil, errors.New("store: PostgreSQL: PGSERVICE and PGSERVICEFILE are not supported")
	}
	cfg, err := pgx.ParseConfigWithOptions(dsn, pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: dsnKeys},
	})
	if err != nil {
		// pgx's message may quote the DSN
		return nil, errors.New("store: PostgreSQL DSN: cannot be parsed, or sets a parameter that is not supported (such as service or sslpassword)")
	}
	if cfg.Password != "" {
		return nil, errors.New("store: PostgreSQL: the DSN, PGPASSWORD or a .pgpass file sets a password; " +
			"give it in database.password_file or a systemd credential instead")
	}
	if err := verifyTLS(dsn, &cfg.Config); err != nil {
		return nil, err
	}
	pw, err := readPassword(o)
	if err != nil {
		return nil, err
	}
	cfg.Password = pw
	return cfg, nil
}

// verifyTLS makes the connection to every host that is not loopback or a Unix socket use TLS 1.2 or
// later with the certificate chain and the host name verified, and refuses a host that may be
// reached without TLS (sslmode disable, allow or prefer). It does not ask which sslmode the DSN, the
// environment or a service file set, because every reading of that other than pgx's own can differ
// from pgx's: it replaces the TLS configuration pgx built for the host with one made here, keeping
// only pgx's client certificates and protocol. Weaker modes that use TLS (require, verify-ca) thus
// become verify-full.
func verifyTLS(dsn string, c *pgconn.Config) error {
	roots, err := rootPool(dsn)
	if err != nil {
		return err
	}
	fix := func(host string, tc *tls.Config) (*tls.Config, error) {
		if localHost(host) {
			return tc, nil
		}
		if tc == nil {
			return nil, fmt.Errorf("store: PostgreSQL at %s: use sslmode=verify-full; "+
				"only the loopback interface or a Unix socket may go without TLS", host)
		}
		return &tls.Config{
			ServerName:   host,
			RootCAs:      roots,
			Certificates: tc.Certificates,
			NextProtos:   tc.NextProtos,
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
	if c.TLSConfig, err = fix(c.Host, c.TLSConfig); err != nil {
		return err
	}
	for _, fb := range c.Fallbacks {
		if fb.TLSConfig, err = fix(fb.Host, fb.TLSConfig); err != nil {
			return err
		}
	}
	return nil
}

// rootPool returns the certificate authorities that verify a server: the file of sslrootcert, if
// the DSN or PGSSLROOTCERT names one ("system" is the system's), else the system's. It reads the
// file itself rather than taking pgx's pool, which also covers a Unix-socket first host (it has no
// TLS configuration) and never takes $HOME/.postgresql/root.crt, which pgx would.
func rootPool(dsn string) (*x509.CertPool, error) {
	file := dsnParam(dsn, "sslrootcert")
	if file == "" {
		file = os.Getenv("PGSSLROOTCERT")
	}
	if file == "" || file == "system" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("store: PostgreSQL: the system certificate pool: %w", err)
		}
		return pool, nil
	}
	data, err := os.ReadFile(file) //nolint:gosec // G304: the path is the operator's boot configuration
	if err != nil {
		return nil, fmt.Errorf("store: PostgreSQL: sslrootcert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("store: PostgreSQL: sslrootcert " + file + " holds no certificate")
	}
	return pool, nil
}

// dsnParam returns the last value of key in a URL or key/value DSN, or "". It is used only to find
// out which certificate file the operator named, never to decide whether TLS is verified.
func dsnParam(dsn, key string) string {
	val := ""
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		_, q, ok := strings.Cut(dsn, "?")
		if !ok {
			return ""
		}
		q, _, _ = strings.Cut(q, "#")
		for _, kv := range strings.Split(q, "&") {
			k, v, _ := strings.Cut(kv, "=")
			if k, err := url.QueryUnescape(k); err == nil && k == key {
				if u, err := url.QueryUnescape(v); err == nil {
					val = u
				}
			}
		}
		return val
	}
	return keywordValue(dsn, key)
}

// keywordValue returns the last value of key in a "key=value key2='quoted value'" connection string.
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
			end := 0
			for end < len(r) && !strings.ContainsRune(" \t\r\n", rune(r[end])) {
				if r[end] == '\\' && end+1 < len(r) {
					end++
				}
				v.WriteByte(r[end])
				end++
			}
			rest = r[end:]
		}
		if k == key {
			val = v.String()
		}
	}
	return val
}

// localHost reports whether host is a Unix socket directory, an IP loopback address, or the name
// localhost with only loopback addresses. The name is resolved here and again when pgx connects,
// which leaves a theoretical gap between check and use; it is accepted, because localhost comes
// from the hosts file and an attacker who can change that already controls the host.
func localHost(host string) bool {
	if strings.HasPrefix(host, "/") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	if host != "localhost" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !a.IP.IsLoopback() {
			return false
		}
	}
	return true
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
	if err := checkServerVersion(num); err != nil {
		return err
	}
	if major := num / 10000; major > MaxTestedPostgresMajor {
		slog.Warn("PostgreSQL is newer than the versions rpmgr is tested on", "major", major, "tested_up_to", MaxTestedPostgresMajor)
	}
	return nil
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
func holdControllerLock(ctx context.Context, cfg *pgx.ConnConfig, shared bool, name string) (func() error, <-chan struct{}, error) {
	// The lock ends with its session, so the server must not end that for being idle, and a
	// middlebox must see traffic: docs/06-data-model.md, "Connecting to PostgreSQL".
	lc := cfg.Copy()
	if lc.RuntimeParams == nil {
		lc.RuntimeParams = map[string]string{}
	}
	lc.RuntimeParams["idle_session_timeout"] = "0"
	lc.DialFunc = (&net.Dialer{KeepAlive: lockKeepAlive}).DialContext
	conn, err := pgx.ConnectConfig(ctx, lc)
	if err != nil {
		return nil, nil, fmt.Errorf("store: controller lock: %w", err)
	}
	fn := "pg_try_advisory_lock"
	if shared {
		fn = "pg_try_advisory_lock_shared"
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
	if !shared {
		if err := endPreviousSessions(ctx, conn, name); err != nil {
			_ = conn.Close(ctx)
			return nil, nil, err
		}
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
				var held bool
				err := conn.QueryRow(pctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = pg_backend_pid()
  AND locktype = 'advisory' AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 2 AND granted)`,
					advisoryNamespace, advisoryController).Scan(&held)
				cancel()
				if err != nil || !held {
					close(lost)
					return
				}
			}
		}
	}()
	var once sync.Once
	var closeErr error
	unlock := func() error {
		once.Do(func() {
			close(stop)
			<-done
			cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			closeErr = conn.Close(cctx) // ending the session releases the lock
		})
		return closeErr
	}
	return unlock, lost, nil
}

// controllerApp is the start of the application_name of every connection of a controller that
// holds the lock; the rest is random per opened database.
const controllerApp = "rpmgr-controller:"

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// endPreviousSessions ends every other session of a controller in this database, as the new
// exclusive holder of the lock: a transaction of the controller before it that is still on the
// wire, held back by a stalled socket or a frozen process, then fails instead of committing after
// the new holder has started to write. Only sessions of the same role are visible and may be
// ended, unless the role is a member of pg_signal_backend and pg_read_all_stats; a refusal stops
// the start.
func endPreviousSessions(ctx context.Context, conn *pgx.Conn, own string) error {
	var n int
	err := conn.QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
 WHERE datname = current_database() AND application_name LIKE $1 AND application_name <> $2`,
		controllerApp+"%", own).Scan(&n)
	if err != nil {
		return fmt.Errorf("store: cannot end the sessions of the previous controller (the role needs pg_signal_backend and pg_read_all_stats for sessions of another role): %w", err)
	}
	return nil
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
	wctx, cancel := context.WithTimeout(ctx, migrationLockWait)
	defer cancel()
	if _, err := conn.ExecContext(wctx, "SELECT pg_advisory_lock($1, $2)", advisoryNamespace, advisoryMigrations); err != nil {
		// The statement may still be waiting on the server: never return this connection to the pool.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
		if errors.Is(wctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, fmt.Errorf("store: migration lock: another process has held it for more than %s: %w", migrationLockWait, err)
		}
		return nil, fmt.Errorf("store: migration lock: %w", err)
	}
	return func() {
		uctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(uctx, "SELECT pg_advisory_unlock($1, $2)", advisoryNamespace, advisoryMigrations); err != nil {
			// still holding the lock: never return this connection to the pool
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
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
