// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// untar reads every file of an archive.
func untar(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string][]byte{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Mode != 0o600 {
			t.Errorf("%s: mode %o", h.Name, h.Mode)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = b
	}
}

// TestBackup: a backup of an initialised controller holds a copy of its database that opens with
// the same installation, both logs without a line still being written, and backup.json; the
// archive is the owner's only and is never overwritten.
func TestBackup(t *testing.T) {
	h := newHost(t)
	h.writeBoot(t, h.fileKEK())
	r, err := controller.Init(context.Background(), h.opts())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Dir(h.db)
	revocations := "{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3, half written"
	if err := os.WriteFile(filepath.Join(state, "revocations.log"), []byte(revocations), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "rpmgr.backup")
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	info, err := controller.Backup(context.Background(), h.cfg, out, "1.4.2", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if info.TrustDomain != r.TrustDomain || info.DBEpoch == "" || info.Version != "1.4.2" {
		t.Errorf("info %+v", info)
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("archive mode: %v %v", st, err)
	}
	files := untar(t, out)
	var meta controller.BackupInfo
	if err := json.Unmarshal(files[controller.BackupMeta], &meta); err != nil || meta != info || meta.Format != 1 {
		t.Errorf("backup.json: %s %v", files[controller.BackupMeta], err)
	}
	if string(files[controller.BackupRevocations]) != "{\"seq\":1}\n{\"seq\":2}\n" {
		t.Errorf("revocation log %q", files[controller.BackupRevocations])
	}
	if _, ok := files[controller.BackupCheckpoints]; !ok {
		t.Error("no audit checkpoints, even an empty file")
	}
	copyDB := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(copyDB, files[controller.BackupDatabase], 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLite(context.Background(), copyDB, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if inst, err := db.Client().Instance.Get(storetest.SystemCtx(t), 1); err != nil || inst.TrustDomain != r.TrustDomain || inst.DbEpoch != info.DBEpoch {
		t.Errorf("the copy's installation: %v %v", inst, err)
	}

	before, _ := os.ReadFile(out)
	if _, err := controller.Backup(context.Background(), h.cfg, out, "1.4.2", time.Now); !errors.Is(err, os.ErrExist) {
		t.Errorf("an existing archive: %v", err)
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Error("an existing archive was changed")
	}
	if _, err := controller.Backup(context.Background(), filepath.Join(t.TempDir(), "none.yaml"), filepath.Join(t.TempDir(), "x"), "1.4.2", time.Now); err == nil {
		t.Error("a missing boot file")
	}
	empty := newHost(t)
	empty.writeBoot(t, empty.fileKEK())
	if err := os.MkdirAll(filepath.Dir(empty.db), 0o750); err != nil {
		t.Fatal(err)
	}
	failed := filepath.Join(t.TempDir(), "failed.backup")
	if _, err := controller.Backup(context.Background(), empty.cfg, failed, "1.4.2", time.Now); err == nil {
		t.Error("a database without an installation")
	}
	if _, err := os.Stat(failed); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed backup left %s: %v", failed, err)
	}
}
