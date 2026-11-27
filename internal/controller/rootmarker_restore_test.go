// SPDX-License-Identifier: Apache-2.0

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
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// backupOf takes a backup of the host into a new file.
func backupOf(t *testing.T, h host) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := controller.Backup(context.Background(), h.cfg, out, "0.1.0", time.Now); err != nil {
		t.Fatal(err)
	}
	return out
}

// stateSnapshot is what a refused restore must leave alone: the database file and the log, and no
// file of a replaced one.
func stateSnapshot(t *testing.T, h host) (db, log []byte, others int) {
	t.Helper()
	dir := filepath.Dir(h.db)
	var err error
	if db, err = os.ReadFile(h.db); err != nil {
		t.Fatal(err)
	}
	if log, err = os.ReadFile(filepath.Join(dir, "revocations.log")); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ".before-restore-") || strings.HasPrefix(e.Name(), ".restoring-") {
			others++
		}
	}
	return db, log, others
}

// A restore replaces the database with the archive's, so one from before the switch of issuing would make
// the old root issue again and one from before the drop would put it back into a bundle that agents have
// dropped it from. The markers of the revocation log make the restore refuse both and change nothing; an
// archive taken after the drop restores.
func TestRestore_RefusesAnArchiveOlderThanARootChange(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	now := time.Now()
	before := backupOf(t, h)
	if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	duringOverlap := backupOf(t, h)
	if _, err := controller.DropRoot(ctx, h.cfg, false, false, func() time.Time { return now.Add(38 * rotationDay) }); err != nil {
		t.Fatal(err)
	}
	after := backupOf(t, h)

	marks := rootMarkers(t, filepath.Join(filepath.Dir(h.db), "revocations.log"))
	if len(marks) != 2 || marks[0].Kind != revlog.RootSwitched || marks[1].Kind != revlog.RootDropped || marks[0].Subject != marks[1].Subject ||
		marks[0].Detail == "" || marks[0].Actor != "local-cli" {
		t.Fatalf("markers: %+v", marks)
	}
	db0, log0, _ := stateSnapshot(t, h)
	for name, archive := range map[string]string{"before the switch": before, "before the drop": duringOverlap} {
		_, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: archive})
		if !errors.Is(err, controller.ErrOlderThanRootChange) || !strings.Contains(err.Error(), marks[0].Subject) {
			t.Fatalf("a restore of an archive from %s = %v, want ErrOlderThanRootChange naming the root", name, err)
		}
		db1, log1, others := stateSnapshot(t, h)
		if string(db1) != string(db0) || string(log1) != string(log0) || others != 0 {
			t.Fatalf("the refused restore from %s changed the state (%d moved files)", name, others)
		}
	}
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: after}); err != nil {
		t.Fatalf("a restore of an archive taken after the drop: %v", err)
	}
}

// The marker may be only in the archive's own log: a backup's database can precede the commit of the
// change while its copy of the log, taken after, holds the marker. It refuses all the same, and for each
// kind of marker, and a marker that names another root, or one of a root the archive no longer
// holds as before, does not.
func TestRestore_RefusesOnAMarkerInTheArchivesOwnLog(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	root := db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(storetest.SystemCtx(t))
	_ = db.Close()
	hash := pki.PublicKeyHash(root.PublicKey)
	rl, err := revlog.Open(filepath.Join(filepath.Dir(h.db), "revocations.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A marker of a root this database never held does not stand in the way.
	if _, err := rl.Append(revlog.Entry{Kind: revlog.RootCompromised, Subject: strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: backupOf(t, h)}); err != nil {
		t.Fatalf("a marker of another root refused a restore: %v", err)
	}
	for _, kind := range []revlog.Kind{revlog.RootSwitched, revlog.RootDropped, revlog.RootCompromised} {
		if _, err := rl.Append(revlog.Entry{Kind: kind, Subject: hash, Detail: strings.Repeat("cd", 32)}); err != nil {
			t.Fatal(err)
		}
		_, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: backupOf(t, h)})
		if !errors.Is(err, controller.ErrOlderThanRootChange) {
			t.Fatalf("with a %s marker in the archive's log the restore = %v", kind, err)
		}
		// Each kind alone: the log is the state directory's, so start the next kind from a fresh host.
		h, _ = initHost(t)
		db, err = store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		hash = pki.PublicKeyHash(db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(storetest.SystemCtx(t)).PublicKey)
		_ = db.Close()
		if rl, err = revlog.Open(filepath.Join(filepath.Dir(h.db), "revocations.log"), nil); err != nil {
			t.Fatal(err)
		}
	}
}
