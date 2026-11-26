// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package controller_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// withDB runs f on the host's database, opened beside the command under test.
func withDB(t *testing.T, h host, f func(db *store.DB)) {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	f(db)
}

// TestOfflineRoot_PlanGoesStale: the root's sealed key changes between the plan of `ca offline-root`
// and its transaction (a KEK rotation re-wrapped it). The ceremony fails and says what happened,
// writes no file and leaves the root online.
func TestOfflineRoot_PlanGoesStale(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { controller.CeremonyFault = nil })
	h, _ := initHost(t)
	kek, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	s, err := secret.NewSealer(kek)
	if err != nil {
		t.Fatal(err)
	}
	controller.CeremonyFault = func(stage, _ string) error {
		if stage != "planned" {
			return nil
		}
		withDB(t, h, func(db *store.DB) {
			sys := storetest.SystemCtx(t)
			r := db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(sys)
			sc := secret.Context{Table: "ca_keys", Column: "key_enc", RowID: r.ID}
			v, err := s.Open(ctx, sc, *r.KeyEnc)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := s.Seal(ctx, sc, v)
			if err != nil {
				t.Fatal(err)
			}
			db.Client().CAKey.UpdateOneID(r.ID).SetKeyEnc(sealed).ExecX(sys)
		})
		return nil
	}
	out := filepath.Join(t.TempDir(), "root.age")
	_, err = controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: h.cfg, Out: out, Passphrase: suppliedPass, Getenv: noEnv})
	if !errors.Is(err, castore.ErrRotated) || !strings.Contains(err.Error(), "root's key changed") || strings.Contains(err.Error(), "intermediate") {
		t.Fatalf("err = %v, want ErrRotated saying that the root's key changed", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a stale ceremony left a file: %v", err)
	}
	if off, _, _ := rootRowOf(t, h); off {
		t.Error("a stale ceremony took the root offline")
	}
	if len(auditOf(t, h, castore.RootActionOffline)) != 0 {
		t.Error("a stale ceremony was recorded")
	}
}

// offlineHost is a host whose root is offline.
func offlineHost(t *testing.T) host {
	t.Helper()
	h, _ := initHost(t)
	root := filepath.Join(t.TempDir(), "root.age")
	if _, err := controller.OfflineRoot(context.Background(), controller.OfflineRootOptions{ConfigPath: h.cfg, Out: root, Passphrase: suppliedPass, Getenv: noEnv}); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestRequestIntermediate_ConcurrentRequest: another request commits between the plan of
// `rotate-intermediate --csr-out` and its transaction. The command plans again and returns the
// request that waits, with the same hash; one request waits.
func TestRequestIntermediate_ConcurrentRequest(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { controller.CeremonyFault = nil })
	h := offlineHost(t)
	dir := t.TempDir()
	var first string
	var calls int
	controller.CeremonyFault = func(stage, _ string) error {
		if stage != "planned" {
			return nil
		}
		calls++
		if calls == 1 {
			var err error
			if first, err = controller.RequestIntermediate(ctx, h.cfg, filepath.Join(dir, "first.csr"), noEnv, time.Now); err != nil {
				t.Errorf("the request that came first: %v", err)
			}
		}
		return nil
	}
	hash, err := controller.RequestIntermediate(ctx, h.cfg, filepath.Join(dir, "second.csr"), noEnv, time.Now)
	if err != nil {
		t.Fatalf("the request that lost the race: %v", err)
	}
	if first == "" || hash != first {
		t.Errorf("hash %q, the first request's %q", hash, first)
	}
	a, _ := os.ReadFile(filepath.Join(dir, "first.csr"))
	b, _ := os.ReadFile(filepath.Join(dir, "second.csr"))
	if len(a) == 0 || !bytes.Equal(a, b) {
		t.Error("the two files do not hold the same request")
	}
	if calls < 2 {
		t.Errorf("planned %d times, want a second plan after the first went stale", calls)
	}
	if n := nextIntermediates(t, h); n != 1 {
		t.Errorf("%d next intermediates, want 1", n)
	}
}

// TestRequestIntermediate_GivesUp: when the keys change between every plan and its transaction, the
// command stops after three attempts, says what happened and writes no file.
func TestRequestIntermediate_GivesUp(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { controller.CeremonyFault = nil })
	h := offlineHost(t)
	var calls int
	controller.CeremonyFault = func(stage, _ string) error {
		if stage != "planned" {
			return nil
		}
		calls++
		key, csr, err := pki.NewIntermediateRequest()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		withDB(t, h, func(db *store.DB) {
			sys := storetest.SystemCtx(t)
			r := db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(sys)
			db.Client().CAKey.Create().SetID(ids.New("cak")).SetKind(cakey.KindIntermediate).SetAlgorithm(r.Algorithm).
				SetKeyEnc([]byte("not opened by a request")).SetStatus(cakey.StatusNext).SetPublicKey(pub).SetCsr(csr).
				SetNotBefore(r.NotBefore).SetNotAfter(r.NotAfter).ExecX(sys)
		})
		return nil
	}
	out := filepath.Join(t.TempDir(), "next.csr")
	hash, err := controller.RequestIntermediate(ctx, h.cfg, out, noEnv, time.Now)
	if !errors.Is(err, castore.ErrRotated) || !strings.Contains(err.Error(), "three attempts") || strings.Contains(err.Error(), "the intermediate was rotated") {
		t.Fatalf("err = %v, want ErrRotated saying that the keys kept changing", err)
	}
	if hash != "" {
		t.Errorf("hash %q returned with an error", hash)
	}
	if calls != 3 {
		t.Errorf("planned %d times, want 3", calls)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed request left a file: %v", err)
	}
}
