// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// clock is a test clock that can jump.
type clock struct{ offset atomic.Int64 }

func (c *clock) now() time.Time       { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *clock) jump(d time.Duration) { c.offset.Add(int64(d)) }

func sealer(t *testing.T) *secret.Sealer {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	k, err := secret.NewKEK(b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := secret.NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// replica is the storage of one controller replica on db.
func replica(t *testing.T, db *store.DB, s *secret.Sealer, c *clock, holder string) *acme.Storage {
	t.Helper()
	st := acme.NewStorage(db, storetest.SystemCtx(t), s, lease.New(db, holder, c.now), c.now)
	t.Cleanup(st.Close)
	return st
}

// TestStorage_Semantics: certmagic's storage contract: overwrite, "directories", listing, Stat,
// deletion below a key, LIKE wildcards in keys taken literally, and fs.ErrNotExist for missing
// keys; values are sealed, never stored in plain.
func TestStorage_Semantics(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		ctx := context.Background()
		s := replica(t, db, sealer(t), &clock{}, "ctn_a")
		if _, err := s.Load(ctx, "missing"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Load(missing): %v", err)
		}
		if _, err := s.Stat(ctx, "missing"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat(missing): %v", err)
		}
		if err := s.Store(ctx, "", []byte("x")); err == nil {
			t.Fatal("an empty key was stored")
		}
		for k, v := range map[string]string{
			"certificates/ca/a.test/a.test.crt": "A", "certificates/ca/a.test/a.test.key": "secret key",
			"certificates/ca/b.test/b.test.crt": "B", "acme/ca/users/x/x.json": "U",
			"certificates/ca/c_%.test/c.crt": "special characters in a key",
		} {
			if err := s.Store(ctx, k, []byte(v)); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Store(ctx, "certificates/ca/a.test/a.test.crt", []byte("A2")); err != nil {
			t.Fatal(err)
		}
		if v, err := s.Load(ctx, "certificates/ca/a.test/a.test.crt"); err != nil || string(v) != "A2" {
			t.Fatalf("overwrite: %q %v", v, err)
		}
		raw := db.Client().ACMEStorage.GetX(storetest.SystemCtx(t), "certificates/ca/a.test/a.test.key")
		if bytes.Contains(raw.ValueEnc, []byte("secret key")) || raw.Size != len("secret key") {
			t.Fatal("a value is stored in plain")
		}
		if !s.Exists(ctx, "certificates/ca") || !s.Exists(ctx, "certificates/ca/a.test/a.test.key") {
			t.Fatal("Exists is false for a directory or a key")
		}
		if s.Exists(ctx, "certificates/c") {
			t.Fatal("Exists matched part of a path segment")
		}
		got, err := s.List(ctx, "certificates/ca", false)
		if want := []string{"certificates/ca/a.test", "certificates/ca/b.test", "certificates/ca/c_%.test"}; err != nil || !slices.Equal(got, want) {
			t.Fatalf("List: %v %v, want %v", got, err, want)
		}
		if got, _ := s.List(ctx, "certificates/ca/", true); len(got) != 4 {
			t.Fatalf("List recursive: %v", got)
		}
		if root, _ := s.List(ctx, "", false); !slices.Equal(root, []string{"acme", "certificates"}) {
			t.Fatalf("List of the root: %v", root)
		}
		if _, err := s.List(ctx, "nothing", false); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("List(nothing): %v", err)
		}
		if ki, err := s.Stat(ctx, "certificates/ca/b.test/b.test.crt"); err != nil || !ki.IsTerminal || ki.Size != 1 {
			t.Fatalf("Stat of a key: %+v %v", ki, err)
		}
		if ki, err := s.Stat(ctx, "certificates/ca/b.test"); err != nil || ki.IsTerminal {
			t.Fatalf("Stat of a directory: %+v %v", ki, err)
		}
		if err := s.Delete(ctx, "certificates/ca/c_%.test"); err != nil {
			t.Fatal(err)
		}
		if !s.Exists(ctx, "certificates/ca/a.test") || s.Exists(ctx, "certificates/ca/c_%.test") {
			t.Fatal("a key with LIKE wildcards deleted the wrong keys")
		}
		if err := s.Delete(ctx, "certificates/ca/a.test"); err != nil {
			t.Fatal(err)
		}
		if s.Exists(ctx, "certificates/ca/a.test/a.test.key") {
			t.Fatal("deleting a directory left a key under it")
		}
		if err := s.Delete(ctx, "certificates/ca/a.test"); err != nil {
			t.Fatalf("deleting a missing key: %v", err)
		}
		// Another KEK cannot read a value.
		other := replica(t, db, sealer(t), &clock{}, "ctn_b")
		if _, err := other.Load(ctx, "acme/ca/users/x/x.json"); err == nil {
			t.Fatal("a value opened under another KEK")
		}
	})
}

// TestStorage_Locks: a lock is held by one replica at a time and kept alive while held; another
// replica's Lock waits until Unlock or its context ends; a lock not held cannot be unlocked; a
// stalled holder's lock expires and is taken over, and the former holder can no longer use it.
func TestStorage_Locks(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		ctx := context.Background()
		s, c := sealer(t), &clock{}
		a, b := replica(t, db, s, c, "ctn_a"), replica(t, db, s, c, "ctn_b")
		if err := a.Lock(ctx, "issue_cert_x"); err != nil {
			t.Fatal(err)
		}
		if ok, err := b.TryLock(ctx, "issue_cert_x"); ok || err != nil {
			t.Fatalf("a second replica got the lock: %v %v", ok, err)
		}
		if err := b.Unlock(ctx, "issue_cert_x"); err == nil {
			t.Fatal("a replica unlocked a lock it does not hold")
		}
		tctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		if err := b.Lock(tctx, "issue_cert_x"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Lock while held: %v", err)
		}
		acme.SetLockPoll(t, 50*time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- b.Lock(ctx, "issue_cert_x") }()
		time.Sleep(200 * time.Millisecond)
		if err := a.Unlock(ctx, "issue_cert_x"); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a waiting Lock did not get the lock after Unlock")
		}
		if err := b.RenewLockLease(ctx, "issue_cert_x", time.Minute); err != nil {
			t.Fatalf("renewing a held lock: %v", err)
		}

		// b stalls: its keep-alive stops and its lease runs out.
		b.Close()
		c.jump(lease.TTL + time.Second)
		if ok, err := a.TryLock(ctx, "issue_cert_x"); !ok || err != nil {
			t.Fatalf("an expired lock was not taken over: %v %v", ok, err)
		}
		if err := b.Unlock(ctx, "issue_cert_x"); err == nil {
			t.Fatal("the former holder unlocked the lock")
		}
		if err := b.RenewLockLease(ctx, "issue_cert_x", time.Minute); err == nil {
			t.Fatal("the former holder renewed the lock")
		}
		if err := a.Unlock(ctx, "issue_cert_x"); err != nil {
			t.Fatal(err)
		}
	})
}

// TestStorage_LockContention: twelve workers on three replicas never hold one lock at once.
func TestStorage_LockContention(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		acme.SetLockPoll(t, 20*time.Millisecond)
		ctx := context.Background()
		s, c := sealer(t), &clock{}
		replicas := []*acme.Storage{replica(t, db, s, c, "ctn_1"), replica(t, db, s, c, "ctn_2"), replica(t, db, s, c, "ctn_3")}
		var (
			mu                      sync.Mutex
			inside, most, completed int
			wg                      sync.WaitGroup
		)
		for i := range 12 {
			wg.Go(func() {
				st := replicas[i%len(replicas)]
				if err := st.Lock(ctx, "counter"); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				inside++
				most = max(most, inside)
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
				mu.Lock()
				inside--
				completed++
				mu.Unlock()
				if err := st.Unlock(ctx, "counter"); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if most != 1 || completed != 12 {
			t.Fatalf("%d holders at once, %d completed; want 1 and 12", most, completed)
		}
	})
}
