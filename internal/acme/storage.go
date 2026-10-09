// SPDX-License-Identifier: Apache-2.0

// Package acme runs ACME on the controller with certmagic (docs/04-security.md, "Controller
// certificates"; D17; spike S6): certmagic's storage in the database under the KEK, its locks on
// the controller's leases, challenges pushed to gateways, and issuance and renewal of route
// certificates.
package acme

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/caddyserver/certmagic"

	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/acmestorage"
	"github.com/felix-homelab/rpmgr/internal/store/ent/predicate"
)

// lockPrefix names certmagic's locks among the controller's leases.
const lockPrefix = "acme:"

// lockPoll is how often Lock tries again while another replica holds a lock; a variable for
// tests.
var lockPoll = time.Second

// Storage is certmagic's storage in the acme_storage table, each value sealed under the KEK with
// its key as the row, and its locks as leases, kept alive while held: replicas never order the
// same certificate twice, and a crashed replica's locks expire (spike S6).
type Storage struct {
	db     *store.DB
	sys    context.Context // the system scope
	sealer *secret.Sealer
	leases *lease.Leases
	now    func() time.Time

	mu   sync.Mutex
	held map[string]*heldLock
}

type heldLock struct {
	lease lease.Lease
	stop  chan struct{}
	done  chan struct{}
}

// NewStorage returns the storage; sys must carry the system scope, granted and audited by the
// caller.
func NewStorage(db *store.DB, sys context.Context, sealer *secret.Sealer, leases *lease.Leases, now func() time.Time) *Storage {
	if now == nil {
		now = time.Now
	}
	return &Storage{db: db, sys: sys, sealer: sealer, leases: leases, now: now, held: map[string]*heldLock{}}
}

func valueContext(key string) secret.Context {
	return secret.Context{Table: "acme_storage", Column: "value_enc", RowID: key}
}

// Store implements certmagic.Storage.
func (s *Storage) Store(_ context.Context, key string, value []byte) error {
	if key == "" {
		return errors.New("acme: an empty storage key")
	}
	write := func(tx *ent.Tx) error {
		sealed, err := store.Seal(s.sys, tx, s.sealer, valueContext(key), secret.FromBytes(value))
		if err != nil {
			return err
		}
		n, err := tx.ACMEStorage.Update().Where(acmestorage.ID(key)).SetValueEnc(sealed).SetSize(len(value)).
			SetModifiedAt(s.now()).Save(s.sys)
		if err != nil || n > 0 {
			return err
		}
		return tx.ACMEStorage.Create().SetID(key).SetValueEnc(sealed).SetSize(len(value)).SetModifiedAt(s.now()).Exec(s.sys)
	}
	err := store.WriteTx(s.sys, s.db, write)
	if store.IsUniqueViolation(err) { // another replica created the key at the same moment
		err = store.WriteTx(s.sys, s.db, write)
	}
	return err
}

// under matches key and every key under it, certmagic's "directory" key.
func under(key string) predicate.ACMEStorage {
	prefix := strings.TrimSuffix(key, "/") + "/"
	return acmestorage.Or(acmestorage.ID(key), prefixed(prefix))
}

// prefixed matches the keys that start with prefix; LIKE's wildcards in it match only themselves.
func prefixed(prefix string) predicate.ACMEStorage {
	return predicate.ACMEStorage(func(s *sql.Selector) { s.Where(sql.HasPrefix(s.C(acmestorage.FieldID), prefix)) })
}

// Load implements certmagic.Storage; a missing key wraps fs.ErrNotExist, as certmagic requires.
func (s *Storage) Load(_ context.Context, key string) ([]byte, error) {
	var out []byte
	err := store.ReadTx(s.sys, s.db, func(tx *ent.Tx, _ store.Revision) error {
		row, err := tx.ACMEStorage.Get(s.sys, key)
		if ent.IsNotFound(err) {
			return fmt.Errorf("acme: %q: %w", key, fs.ErrNotExist)
		}
		if err != nil {
			return err
		}
		v, err := s.sealer.Open(valueContext(key), row.ValueEnc)
		if err != nil {
			return err
		}
		out = []byte(v.Reveal())
		return nil
	})
	return out, err
}

// Delete implements certmagic.Storage: the key and every key under it.
func (s *Storage) Delete(_ context.Context, key string) error {
	return store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		_, err := tx.ACMEStorage.Delete().Where(under(key)).Exec(s.sys)
		return err
	})
}

// Exists implements certmagic.Storage: true for a key or a "directory" of keys.
func (s *Storage) Exists(_ context.Context, key string) bool {
	found := false
	err := store.ReadTx(s.sys, s.db, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		found, err = tx.ACMEStorage.Query().Where(under(key)).Exist(s.sys)
		return err
	})
	return err == nil && found
}

// List implements certmagic.Storage: the direct children of path, "directories" included, or with
// recursive every key under it.
func (s *Storage) List(_ context.Context, path string, recursive bool) ([]string, error) {
	base := strings.TrimSuffix(path, "/")
	if base != "" {
		base += "/"
	}
	var keys []string
	err := store.ReadTx(s.sys, s.db, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		keys, err = tx.ACMEStorage.Query().Where(prefixed(base)).IDs(s.sys)
		return err
	})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range keys {
		if !recursive {
			if i := strings.IndexByte(k[len(base):], '/'); i >= 0 {
				k = k[:len(base)+i]
			}
		}
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("acme: %q: %w", path, fs.ErrNotExist)
	}
	slices.Sort(out)
	return out, nil
}

// Stat implements certmagic.Storage.
func (s *Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	var info certmagic.KeyInfo
	err := store.ReadTx(s.sys, s.db, func(tx *ent.Tx, _ store.Revision) error {
		row, err := tx.ACMEStorage.Get(s.sys, key)
		if err == nil {
			info = certmagic.KeyInfo{Key: key, Modified: row.ModifiedAt, Size: int64(row.Size), IsTerminal: true}
		}
		if ent.IsNotFound(err) {
			return nil
		}
		return err
	})
	switch {
	case err != nil:
		return certmagic.KeyInfo{}, err
	case info.Key != "":
		return info, nil
	case s.Exists(ctx, key):
		return certmagic.KeyInfo{Key: key}, nil
	}
	return certmagic.KeyInfo{}, fmt.Errorf("acme: %q: %w", key, fs.ErrNotExist)
}

// TryLock implements certmagic.TryLocker: it takes the lease of the lock if it is free or expired
// and keeps it alive until Unlock.
func (s *Storage) TryLock(ctx context.Context, name string) (bool, error) {
	l, ok, err := s.leases.TryAcquire(ctx, lockPrefix+name)
	if err != nil || !ok {
		return false, err
	}
	h := &heldLock{lease: l, stop: make(chan struct{}), done: make(chan struct{})}
	s.mu.Lock()
	if old := s.held[name]; old != nil {
		close(old.stop)
	}
	s.held[name] = h
	s.mu.Unlock()
	go s.keepAlive(h)
	return true, nil
}

func (s *Storage) keepAlive(h *heldLock) {
	defer close(h.done)
	t := time.NewTicker(lease.RenewEvery)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			if err := s.leases.Renew(s.sys, h.lease); err != nil {
				return // lost: another replica has it now
			}
		}
	}
}

// Lock implements certmagic.Locker: it waits until the lease of the lock is free or expired.
func (s *Storage) Lock(ctx context.Context, name string) error {
	for {
		ok, err := s.TryLock(ctx, name)
		if err != nil || ok {
			return err
		}
		jitter, _ := rand.Int(rand.Reader, big.NewInt(int64(lockPoll/2)+1))
		t := time.NewTimer(lockPoll + time.Duration(jitter.Int64()))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Unlock implements certmagic.Locker; a lock this replica does not hold any more is an error.
func (s *Storage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	h := s.held[name]
	delete(s.held, name)
	s.mu.Unlock()
	if h == nil {
		return fmt.Errorf("acme: lock %q is not held here", name)
	}
	close(h.stop)
	<-h.done
	return s.leases.Release(ctx, h.lease)
}

// RenewLockLease implements certmagic.LockLeaseRenewer; held locks are kept alive anyway, so this
// only reports a lock that was lost.
func (s *Storage) RenewLockLease(ctx context.Context, name string, _ time.Duration) error {
	s.mu.Lock()
	h := s.held[name]
	s.mu.Unlock()
	if h == nil {
		return fmt.Errorf("acme: lock %q is not held here", name)
	}
	return s.leases.Renew(ctx, h.lease)
}

// Close stops keeping the held locks alive; they expire like those of a crashed replica.
func (s *Storage) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, h := range s.held {
		close(h.stop)
		<-h.done
		delete(s.held, name)
	}
}

// Interface guards.
var (
	_ certmagic.Storage          = (*Storage)(nil)
	_ certmagic.TryLocker        = (*Storage)(nil)
	_ certmagic.LockLeaseRenewer = (*Storage)(nil)
)
