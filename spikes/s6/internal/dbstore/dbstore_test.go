// SPDX-License-Identifier: Apache-2.0

package dbstore

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func open(t *testing.T, path string) *Storage {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStorageSemantics(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "c.db"))

	if _, err := s.Load(ctx, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load(missing) = %v, want fs.ErrNotExist", err)
	}
	if _, err := s.Stat(ctx, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(missing) = %v, want fs.ErrNotExist", err)
	}
	if err := s.Store(ctx, "", []byte("x")); err == nil {
		t.Fatal("Store with empty key succeeded")
	}
	for k, v := range map[string]string{
		"certificates/ca/a.test/a.test.crt": "A", "certificates/ca/a.test/a.test.key": "K",
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
		t.Fatalf("overwrite: got %q, %v", v, err)
	}
	if !s.Exists(ctx, "certificates/ca") || !s.Exists(ctx, "certificates/ca/a.test/a.test.key") {
		t.Fatal("Exists is false for a directory or a key")
	}
	if s.Exists(ctx, "certificates/c") {
		t.Fatal("Exists matched a partial path segment")
	}
	got, err := s.List(ctx, "certificates/ca", false)
	want := []string{"certificates/ca/a.test", "certificates/ca/b.test", "certificates/ca/c_%.test"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("List non-recursive = %v, %v; want %v", got, err, want)
	}
	got, _ = s.List(ctx, "certificates/ca/", true)
	if len(got) != 4 {
		t.Fatalf("List recursive = %v, want 4 keys", got)
	}
	root, _ := s.List(ctx, "", false)
	if !reflect.DeepEqual(root, []string{"acme", "certificates"}) {
		t.Fatalf("List root = %v", root)
	}
	if _, err := s.List(ctx, "nothing", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("List(nothing) = %v, want fs.ErrNotExist", err)
	}
	ki, err := s.Stat(ctx, "certificates/ca/b.test/b.test.crt")
	if err != nil || !ki.IsTerminal || ki.Size != 1 {
		t.Fatalf("Stat(key) = %+v, %v", ki, err)
	}
	ki, err = s.Stat(ctx, "certificates/ca/b.test")
	if err != nil || ki.IsTerminal {
		t.Fatalf("Stat(dir) = %+v, %v", ki, err)
	}
	// "_" and "%" in a key are not LIKE wildcards: deleting "c_%.test" must not touch others.
	if err := s.Delete(ctx, "certificates/ca/c_%.test"); err != nil {
		t.Fatal(err)
	}
	if !s.Exists(ctx, "certificates/ca/a.test") || s.Exists(ctx, "certificates/ca/c_%.test") {
		t.Fatal("Delete with special characters deleted the wrong keys")
	}
	if err := s.Delete(ctx, "certificates/ca/a.test"); err != nil {
		t.Fatal(err)
	}
	if s.Exists(ctx, "certificates/ca/a.test/a.test.key") {
		t.Fatal("Delete(dir) left a key below it")
	}
	if err := s.Delete(ctx, "certificates/ca/a.test"); err != nil {
		t.Fatalf("Delete of a missing key = %v, want nil", err)
	}
}

func TestLockExclusiveAcrossInstances(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "c.db")
	a, b := open(t, path), open(t, path)
	a.LeaseTTL, b.LeaseTTL = 3*time.Second, 3*time.Second

	if err := a.Lock(ctx, "issue_cert_x"); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.TryLock(ctx, "issue_cert_x"); ok || err != nil {
		t.Fatalf("second holder got the lock: %v, %v", ok, err)
	}
	if err := b.Unlock(ctx, "issue_cert_x"); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("Unlock by non-holder = %v, want ErrNotHeld", err)
	}
	// The keep-alive keeps the lease past its TTL while the holder lives.
	time.Sleep(4 * time.Second)
	if ok, _ := b.TryLock(ctx, "issue_cert_x"); ok {
		t.Fatal("lease expired although its holder renews it")
	}
	tctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if err := b.Lock(tctx, "issue_cert_x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Lock while held = %v, want context.DeadlineExceeded", err)
	}
	done := make(chan error, 1)
	go func() { done <- b.Lock(ctx, "issue_cert_x") }()
	time.Sleep(300 * time.Millisecond)
	if err := a.Unlock(ctx, "issue_cert_x"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting Lock did not acquire after Unlock")
	}
	if err := b.Unlock(ctx, "issue_cert_x"); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseExpiresWhenHolderDies(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "c.db")
	a, b := open(t, path), open(t, path)
	a.LeaseTTL = 1 * time.Second

	if ok, err := a.TryLock(ctx, "issue_cert_y"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	t1, _ := a.FencingToken(ctx, "issue_cert_y")
	a.stopKeepAlive("issue_cert_y") // the holder stalls: no more renewals
	time.Sleep(1200 * time.Millisecond)
	if ok, err := b.TryLock(ctx, "issue_cert_y"); !ok || err != nil {
		t.Fatalf("expired lease not taken over: %v, %v", ok, err)
	}
	t2, _ := b.FencingToken(ctx, "issue_cert_y")
	if t2 <= t1 {
		t.Fatalf("fencing token did not rise on takeover: %d → %d", t1, t2)
	}
	if h, live, _ := b.LeaseHolder(ctx, "issue_cert_y"); h != b.Holder() || !live {
		t.Fatalf("holder after takeover = %q (live %v)", h, live)
	}
	// The stalled former holder can neither renew nor release the lease any more.
	if err := a.RenewLockLease(ctx, "issue_cert_y", time.Minute); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("RenewLockLease by former holder = %v, want ErrNotHeld", err)
	}
	if err := a.Unlock(ctx, "issue_cert_y"); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("Unlock by former holder = %v, want ErrNotHeld", err)
	}
}

func TestLockMutualExclusionUnderContention(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "c.db")
	stores := []*Storage{open(t, path), open(t, path), open(t, path)}
	var inside, maxInside, total int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := stores[i%len(stores)]
			if err := s.Lock(ctx, "counter"); err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			maxInside = max(maxInside, inside)
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			inside--
			total++
			mu.Unlock()
			if err := s.Unlock(ctx, "counter"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if maxInside != 1 || total != 12 {
		t.Fatalf("max holders at once = %d, completed = %d; want 1 and 12", maxInside, total)
	}
}
