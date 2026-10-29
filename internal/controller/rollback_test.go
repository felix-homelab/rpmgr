// SPDX-License-Identifier: Apache-2.0

//go:build linux

package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// TestRollbackRoundTrip is what the root updater's rollback does with the real code (D158): a backup
// of a SQLite controller, a migration this binary does not know (a newer release's), the check of
// the previous binary (`rpmgr migrate`) that reports it as store.ErrUnknownMigration and no other
// failure, and the restore that makes the check pass again.
func TestRollbackRoundTrip(t *testing.T) {
	ctx := context.Background()
	h := newHost(t)
	h.writeBoot(t, h.fileKEK())
	if _, err := controller.Init(ctx, h.opts()); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC) }
	archive := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := controller.Backup(ctx, h.cfg, archive, "1.5.0", now); err != nil {
		t.Fatal(err)
	}
	// Up to date: the check applies nothing and succeeds.
	if res, err := controller.Migrate(ctx, h.cfg, now); err != nil || len(res.Applied) != 0 {
		t.Fatalf("Migrate of an up-to-date database = %+v, %v", res, err)
	}

	// The new release migrates the database.
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.ExecContext(ctx, `INSERT INTO `+store.RevisionTable+` (version, description, type, applied, total, executed_at,
  execution_time, error, error_stmt, hash, partial_hashes, operator_version) VALUES ('29991231235959', 'newer', 2, 1, 1, '2099-01-01T00:00:00Z',
  0, '', '', 'h', '[]', 'rpmgr')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Migrate(ctx, h.cfg, now); !errors.Is(err, store.ErrUnknownMigration) {
		t.Fatalf("Migrate of a newer schema = %v; want ErrUnknownMigration", err)
	}

	// The restore puts the backup back, and the check passes.
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: archive, Now: now}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := controller.Migrate(ctx, h.cfg, now); err != nil {
		t.Errorf("Migrate after the restore = %v", err)
	}
}

// TestRestoreRefusesLinks: the state directory belongs to the service user, and root's restore and
// backup must not follow a link planted there: a link at a live or journal name is refused with
// ErrUnsafeStateFile, one at a staged name is replaced and not followed, and the link's target is
// left untouched.
func TestRestoreRefusesLinks(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"controller.db.restoring", "controller.db-wal", "controller.db-shm", "revocations.log.restoring",
		"audit-checkpoints.log", "controller.db.restoring-wal"} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t)
			h.writeBoot(t, h.fileKEK())
			if _, err := controller.Init(ctx, h.opts()); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "rpmgr.backup")
			if _, err := controller.Backup(ctx, h.cfg, archive, "1.5.0", time.Now); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(target, []byte("precious"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(filepath.Dir(h.db), name)
			_ = os.Remove(link)
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			_, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: archive})
			if strings.Contains(name, ".restoring") {
				// A staged name is removed and created again inside the root, never followed.
				if err != nil {
					t.Fatalf("Restore with a link at the staged name %s = %v", name, err)
				}
				if b, _ := os.ReadFile(target); string(b) != "precious" { //nolint:gosec // G304: under t.TempDir
					t.Errorf("the link's target was changed: %q", b)
				}
				return
			}
			if !errors.Is(err, controller.ErrUnsafeStateFile) {
				t.Fatalf("Restore with a link at %s = %v; want ErrUnsafeStateFile", name, err)
			}
			if b, _ := os.ReadFile(target); string(b) != "precious" { //nolint:gosec // G304: under t.TempDir
				t.Errorf("the link's target was changed: %q", b)
			}
			if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("the link was replaced: %v, %v", fi, err)
			}
			if name == "controller.db-wal" || name == "controller.db-shm" {
				out := filepath.Join(t.TempDir(), "again.backup")
				if _, err := controller.Backup(ctx, h.cfg, out, "1.5.0", time.Now); !errors.Is(err, controller.ErrUnsafeStateFile) {
					t.Errorf("Backup with a link at %s = %v; want ErrUnsafeStateFile", name, err)
				}
			}
		})
	}
}
