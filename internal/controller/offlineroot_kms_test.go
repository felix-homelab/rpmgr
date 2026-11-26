// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// nextIntermediates counts the next intermediates in the host's database.
func nextIntermediates(t *testing.T, h host) int {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	return db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusNext)).CountX(storetest.SystemCtx(t))
}

// TestKMS_OfflineRootCeremony: `ca offline-root` and `ca rotate-intermediate --csr-out` open and
// seal the CA's keys through Transit when the KEK is a Transit key. With Transit down they fail with
// its error and change nothing.
func TestKMS_OfflineRootCeremony(t *testing.T) {
	ctx := context.Background()
	h, srv := kmsHost(t)
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.age")
	opts := controller.OfflineRootOptions{ConfigPath: h.cfg, Out: rootFile, Passphrase: suppliedPass, Getenv: noEnv}

	srv.FailWith(500, false)
	if _, err := controller.OfflineRoot(ctx, opts); err == nil {
		t.Fatal("offline-root with Transit down succeeded")
	} else if strings.Contains(err.Error(), "neither") {
		t.Errorf("offline-root with Transit down blames the KEK: %v", err)
	}
	if _, err := os.Lstat(rootFile); !os.IsNotExist(err) {
		t.Errorf("a failed ceremony left a file: %v", err)
	}
	if off, _, _ := rootRowOf(t, h); off {
		t.Fatal("a failed ceremony took the root offline")
	}
	srv.FailWith(0, false)

	res, err := controller.OfflineRoot(ctx, opts)
	if err != nil {
		t.Fatalf("offline-root with a Transit KEK: %v", err)
	}
	if res.FileSHA256 == "" || res.KEK == "" {
		t.Errorf("result %+v", res)
	}
	if off, _, _ := rootRowOf(t, h); !off {
		t.Error("the root is still online")
	}

	csr := filepath.Join(dir, "next.csr")
	srv.FailWith(500, false)
	if _, err := controller.RequestIntermediate(ctx, h.cfg, csr, noEnv, time.Now); err == nil {
		t.Fatal("a request with Transit down succeeded")
	}
	if _, err := os.Lstat(csr); !os.IsNotExist(err) {
		t.Errorf("a failed request left a file: %v", err)
	}
	if n := nextIntermediates(t, h); n != 0 {
		t.Errorf("a failed request left %d next intermediates", n)
	}
	srv.FailWith(0, false)

	hash, err := controller.RequestIntermediate(ctx, h.cfg, csr, noEnv, time.Now)
	if err != nil || hash == "" {
		t.Fatalf("a request with a Transit KEK: %q %v", hash, err)
	}
	if n := nextIntermediates(t, h); n != 1 {
		t.Errorf("%d next intermediates after a request", n)
	}
	// The ceremony's sealed key opens with Transit: sign and import the way an operator does.
	cert := filepath.Join(dir, "next.crt")
	if _, err := controller.SignIntermediate(controller.SignOptions{RootFile: rootFile, CSR: csr, Out: cert, Passphrase: suppliedPass}); err != nil {
		t.Fatal(err)
	}
	if got, err := controller.ImportIntermediate(ctx, h.cfg, cert, time.Now); err != nil || got.KeyHash != hash {
		t.Fatalf("import: %+v %v", got, err)
	}
}
