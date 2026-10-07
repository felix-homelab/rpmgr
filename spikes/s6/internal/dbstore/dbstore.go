// SPDX-License-Identifier: Apache-2.0

// Package dbstore is a certmagic.Storage backed by a SQL database, as the controller would run
// it: an acme_storage table for the data and a leases table for the locks, with an expiry and a
// fencing token per lease (docs/06-data-model.md, "PKI and ACME" and "System"). The spike uses
// SQLite through modernc.org/sqlite; values are stored in plaintext here, while the product
// envelope-encrypts them under the KEK.
package dbstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"modernc.org/sqlite" // also registers the "sqlite" driver
)

// Storage implements certmagic.Storage, certmagic.TryLocker and certmagic.LockLeaseRenewer.
type Storage struct {
	db     *sql.DB
	holder string // unique per Storage instance, i.e. per controller replica

	// LeaseTTL is how long a lock lives without renewal; held locks are renewed every
	// LeaseTTL/3 by a background goroutine, so only a dead or stalled holder loses them.
	LeaseTTL time.Duration
	// PollInterval is how often Lock retries while another holder has the lease.
	PollInterval time.Duration
	// Now is the clock; tests replace it.
	Now func() time.Time

	mu    sync.Mutex
	held  map[string]heldLease // lease name → keep-alive state
	owned sync.WaitGroup

	// Waits counts Lock calls that found the lease held by another holder and had to wait.
	Waits atomic.Int64
}

type heldLease struct {
	token int64
	stop  chan struct{}
}

// ErrNotHeld is returned by Unlock and RenewLockLease for a lease this instance does not hold.
var ErrNotHeld = errors.New("dbstore: lease not held by this instance")

// Open opens (and if needed creates) the SQLite database at path. Several Storage values may open
// the same file; each one is a separate lock holder, like controller replicas sharing a database.
func Open(path string) (*Storage, error) {
	// busy_timeout must come first: pragmas run in order when a connection opens, and setting
	// journal_mode without a busy handler fails with SQLITE_BUSY while another process writes
	// (seen in the rehearsal with two replica processes).
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer connection per process, as in 06-data-model.md
	// When two processes create the same new database at once, SQLite can report SQLITE_BUSY
	// while the other one switches the file to WAL, without consulting the busy handler (seen in
	// the rehearsal). Initialisation is idempotent, so it is retried for a bounded time.
	deadline := time.Now().Add(10 * time.Second)
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS acme_storage (
			key TEXT PRIMARY KEY, value BLOB NOT NULL, modified_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS leases (
			name TEXT PRIMARY KEY, holder TEXT NOT NULL, fencing_token INTEGER NOT NULL,
			expires_at INTEGER NOT NULL)`,
	} {
		for {
			_, err := db.Exec(stmt)
			if err == nil {
				break
			}
			if !isBusy(err) || time.Now().After(deadline) {
				db.Close()
				return nil, fmt.Errorf("dbstore: initialising %s: %w", path, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		db.Close()
		return nil, err
	}
	return &Storage{
		db:           db,
		holder:       hex.EncodeToString(id),
		LeaseTTL:     30 * time.Second,
		PollInterval: 200 * time.Millisecond,
		Now:          time.Now,
		held:         map[string]heldLease{},
	}, nil
}

// Close stops the keep-alives and closes the database. Held leases are not released, so they
// expire like those of a crashed replica.
func (s *Storage) Close() error {
	s.mu.Lock()
	for name, h := range s.held {
		close(h.stop)
		delete(s.held, name)
	}
	s.mu.Unlock()
	s.owned.Wait()
	return s.db.Close()
}

// Holder returns this instance's lease-holder ID.
func (s *Storage) Holder() string { return s.holder }

func (s *Storage) now() int64 { return s.Now().UnixMilli() }

// Store implements certmagic.Storage.
func (s *Storage) Store(ctx context.Context, key string, value []byte) error {
	if key == "" {
		return errors.New("dbstore: empty key")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO acme_storage (key, value, modified_at)
		VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value,
		modified_at = excluded.modified_at`, key, value, s.now())
	return err
}

// Load implements certmagic.Storage; a missing key yields an error wrapping fs.ErrNotExist,
// which certmagic requires.
func (s *Storage) Load(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM acme_storage WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("dbstore: %q: %w", key, fs.ErrNotExist)
	}
	return v, err
}

// Delete implements certmagic.Storage: the key and every key below it ("directory" semantics).
func (s *Storage) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM acme_storage WHERE key = ? OR key LIKE ? ESCAPE '\'`,
		key, likePrefix(key))
	return err
}

// Exists implements certmagic.Storage: true for a key or a "directory" (prefix of keys).
func (s *Storage) Exists(ctx context.Context, key string) bool {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM acme_storage
		WHERE key = ? OR key LIKE ? ESCAPE '\'`, key, likePrefix(key)).Scan(&n)
	return err == nil && n > 0
}

// List implements certmagic.Storage. Non-recursive listing returns the direct children of path,
// including "directories"; recursive listing returns every key below path.
func (s *Storage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	prefix := strings.TrimSuffix(path, "/")
	pattern := likePrefix(prefix)
	if prefix == "" {
		pattern = "%"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM acme_storage WHERE key LIKE ? ESCAPE '\'`,
		pattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		if !recursive {
			base := prefix + "/"
			if prefix == "" {
				base = ""
			}
			rest := strings.TrimPrefix(k, base)
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				k = base + rest[:i]
			}
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dbstore: %q: %w", path, fs.ErrNotExist)
	}
	sort.Strings(out)
	return out, nil
}

// Stat implements certmagic.Storage.
func (s *Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	var size, mod int64
	err := s.db.QueryRowContext(ctx, `SELECT length(value), modified_at FROM acme_storage
		WHERE key = ?`, key).Scan(&size, &mod)
	if err == nil {
		return certmagic.KeyInfo{Key: key, Modified: time.UnixMilli(mod), Size: size,
			IsTerminal: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return certmagic.KeyInfo{}, err
	}
	if s.Exists(ctx, key) {
		return certmagic.KeyInfo{Key: key, IsTerminal: false}, nil
	}
	return certmagic.KeyInfo{}, fmt.Errorf("dbstore: %q: %w", key, fs.ErrNotExist)
}

// TryLock implements certmagic.TryLocker: it takes the lease if it is free or expired, and raises
// its fencing token.
func (s *Storage) TryLock(ctx context.Context, name string) (bool, error) {
	now := s.now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO leases (name, holder, fencing_token, expires_at)
		VALUES (?, ?, 1, ?) ON CONFLICT (name) DO UPDATE SET holder = excluded.holder,
		fencing_token = leases.fencing_token + 1, expires_at = excluded.expires_at
		WHERE leases.expires_at <= ?`, name, s.holder, now+s.LeaseTTL.Milliseconds(), now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	token, err := s.FencingToken(ctx, name)
	if err != nil {
		return false, err
	}
	s.startKeepAlive(name, token)
	return true, nil
}

// Lock implements certmagic.Locker: it waits until the lease is free or expired.
func (s *Storage) Lock(ctx context.Context, name string) error {
	for waited := false; ; waited = true {
		ok, err := s.TryLock(ctx, name)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !waited {
			s.Waits.Add(1)
		}
		jitter, _ := rand.Int(rand.Reader, big.NewInt(int64(s.PollInterval/2)+1))
		t := time.NewTimer(s.PollInterval + time.Duration(jitter.Int64()))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Unlock implements certmagic.Locker. Releasing a lease this instance does not hold (any more)
// is an error: another replica has taken it over.
func (s *Storage) Unlock(ctx context.Context, name string) error {
	s.stopKeepAlive(name)
	res, err := s.db.ExecContext(ctx, `UPDATE leases SET holder = '', expires_at = 0
		WHERE name = ? AND holder = ?`, name, s.holder)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %q", ErrNotHeld, name)
	}
	return nil
}

// RenewLockLease implements certmagic.LockLeaseRenewer.
func (s *Storage) RenewLockLease(ctx context.Context, name string, d time.Duration) error {
	if d < s.LeaseTTL {
		d = s.LeaseTTL
	}
	res, err := s.db.ExecContext(ctx, `UPDATE leases SET expires_at = ?
		WHERE name = ? AND holder = ? AND expires_at > ?`, s.now()+d.Milliseconds(), name,
		s.holder, s.now())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %q", ErrNotHeld, name)
	}
	return nil
}

// FencingToken returns the current fencing token of a lease; it rises on every takeover, so a
// holder that lost its lease can detect it before committing work.
func (s *Storage) FencingToken(ctx context.Context, name string) (int64, error) {
	var t int64
	err := s.db.QueryRowContext(ctx, `SELECT fencing_token FROM leases WHERE name = ?`, name).Scan(&t)
	return t, err
}

// LeaseHolder returns the holder of a lease and whether it is unexpired.
func (s *Storage) LeaseHolder(ctx context.Context, name string) (string, bool, error) {
	var h string
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT holder, expires_at FROM leases WHERE name = ?`,
		name).Scan(&h, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return h, exp > s.now(), err
}

func (s *Storage) startKeepAlive(name string, token int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.held[name]; ok {
		close(old.stop)
	}
	h := heldLease{token: token, stop: make(chan struct{})}
	s.held[name] = h
	s.owned.Add(1)
	go func() {
		defer s.owned.Done()
		tick := time.NewTicker(s.LeaseTTL / 3)
		defer tick.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-tick.C:
				// The token guard makes a renewal fail once another holder took over.
				_, _ = s.db.Exec(`UPDATE leases SET expires_at = ? WHERE name = ? AND holder = ?
					AND fencing_token = ? AND expires_at > ?`, s.now()+s.LeaseTTL.Milliseconds(),
					name, s.holder, h.token, s.now())
			}
		}
	}()
}

func (s *Storage) stopKeepAlive(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.held[name]; ok {
		close(h.stop)
		delete(s.held, name)
	}
}

// isBusy reports SQLITE_BUSY, including its extended codes (e.g. SQLITE_BUSY_RECOVERY).
func isBusy(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == 5
}

// likePrefix returns a LIKE pattern matching every key below key, with LIKE wildcards escaped.
func likePrefix(key string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(strings.TrimSuffix(key, "/")) + "/%"
}

// Interface guards.
var (
	_ certmagic.Storage          = (*Storage)(nil)
	_ certmagic.TryLocker        = (*Storage)(nil)
	_ certmagic.LockLeaseRenewer = (*Storage)(nil)
)
