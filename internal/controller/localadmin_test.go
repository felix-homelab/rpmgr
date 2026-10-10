// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ariga.io/atlas/sql/migrate"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	entmigrate "github.com/felix-homelab/rpmgr/internal/store/ent/migrate"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func noEnv(string) string { return "" }

// initHost is an initialised controller host with a file KEK, its database not open.
func initHost(t *testing.T) (host, controller.InitResult) {
	t.Helper()
	h := newHost(t)
	h.writeBoot(t, h.fileKEK())
	r, err := controller.Init(context.Background(), h.opts())
	if err != nil {
		t.Fatal(err)
	}
	return h, r
}

// writeKEK writes a new KEK file at path, as `rpmgr controller init` does, and returns the KEK.
func writeKEK(t *testing.T, path string, mode os.FileMode) secret.KEK {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	k, err := secret.NewKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// localActions returns the actions local-cli recorded in the instance's audit log.
func localActions(t *testing.T, h host) []string {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var out []string
	for _, e := range db.Client().AuditEntry.Query().Where(auditentry.ActorID("local-cli")).Order(auditentry.BySeq()).AllX(storetest.SystemCtx(t)) {
		out = append(out, e.Action+" "+e.Reason)
	}
	return out
}

// TestCA_StatusAndRotate: `ca status` shows the CA's keys and the root pin without the KEK; `ca
// rotate-intermediate` makes a new active intermediate and retires the old one, beside a running
// controller; both are audited as local-cli. A KEK that does not open the root, a systemd
// credential that is not loaded, a missing boot file and a missing database are refused.
func TestCA_StatusAndRotate(t *testing.T) {
	ctx := context.Background()
	h, r := initHost(t)
	st, err := controller.CAStatus(ctx, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.GetTrustDomain() != r.TrustDomain || st.GetRootPin() != r.RootPin {
		t.Errorf("status %v, init reported %s %s", st, r.TrustDomain, r.RootPin)
	}
	active := func(st *rpmgrv1.GetPkiStatusResponse, kind rpmgrv1.CAKeyKind) []*rpmgrv1.CAKey {
		var out []*rpmgrv1.CAKey
		for _, k := range st.GetKeys() {
			if k.GetKind() == kind && k.GetState() == rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE {
				out = append(out, k)
			}
		}
		return out
	}
	before := active(st, rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE)
	if len(before) != 1 || len(active(st, rpmgrv1.CAKeyKind_CA_KEY_KIND_ROOT)) != 1 {
		t.Fatalf("keys %v", st.GetKeys())
	}

	// A controller runs meanwhile: the rotation needs no lock.
	running, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = running.Close() }()
	k, err := controller.RotateIntermediate(ctx, h.cfg, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	st, err = controller.CAStatus(ctx, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	after := active(st, rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE)
	if len(after) != 1 || !after[0].GetNotBefore().AsTime().Equal(k.GetNotBefore().AsTime()) ||
		!after[0].GetNotBefore().AsTime().After(before[0].GetNotBefore().AsTime().Add(-time.Second)) {
		t.Errorf("the active intermediate after the rotation: %v, returned %v", after, k)
	}
	retired := 0
	for _, k := range st.GetKeys() {
		if k.GetKind() == rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE && k.GetState() == rpmgrv1.CAKeyState_CA_KEY_STATE_RETIRED {
			retired++
		}
	}
	if retired != 1 {
		t.Errorf("%d retired intermediates", retired)
	}
	got := strings.Join(localActions(t, h), "\n")
	for _, want := range []string{"system_scope.grant rpmgr ca status", "system_scope.grant rpmgr ca rotate-intermediate", "ca.rotate_intermediate "} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in the audit log:\n%s", want, got)
		}
	}

	// Refusals.
	writeKEK(t, h.kek, 0o600) // another KEK than the one the CA was sealed with
	if _, err := controller.RotateIntermediate(ctx, h.cfg, noEnv); !errors.Is(err, secret.ErrOpen) {
		t.Errorf("a KEK that does not open the root: %v", err)
	}
	cred := newHost(t)
	cred.writeBoot(t, "kek: {source: systemd-credential, name: rpmgr-kek}\n")
	if err := os.WriteFile(cred.db, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.RotateIntermediate(ctx, cred.cfg, noEnv); err == nil || !strings.Contains(err.Error(), "systemd-run") {
		t.Errorf("a credential that is not loaded: %v", err)
	}
	if _, err := controller.CAStatus(ctx, filepath.Join(t.TempDir(), "none.yaml")); err == nil {
		t.Error("a missing boot file")
	}
	empty := newHost(t)
	empty.writeBoot(t, empty.fileKEK())
	if _, err := controller.CAStatus(ctx, empty.cfg); err == nil || !strings.Contains(err.Error(), "controller init") {
		t.Errorf("a missing database: %v", err)
	}
	if _, err := os.Stat(empty.db); !errors.Is(err, os.ErrNotExist) {
		t.Error("ca status created a database")
	}
}

// TestKEK_StatusAndRotate: `kek status` counts the secrets by KEK version and lists those under
// another KEK than the boot file's, flagging a boot file whose KEK wraps none; `kek rotate`
// re-wraps every one under the new KEK, with every controller stopped, in one transaction, and
// is audited. A previous KEK that opens nothing, a loose previous KEK file and a running
// controller change nothing.
func TestKEK_StatusAndRotate(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	k1, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	st, err := controller.StatusKEK(ctx, h.cfg, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	sealed := st.Versions[k1.Version()]
	if st.Current != k1.Version() || sealed < 4 || len(st.Old) != 0 || st.Mismatch() {
		t.Fatalf("status after init: %+v", st)
	}

	// The operator provisions a new KEK and keeps the old one in a file.
	prev := filepath.Join(t.TempDir(), "old-kek")
	if err := os.Rename(h.kek, prev); err != nil {
		t.Fatal(err)
	}
	k2 := writeKEK(t, h.kek, 0o600)
	st, err = controller.StatusKEK(ctx, h.cfg, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current != k2.Version() || st.Versions[k1.Version()] != sealed || len(st.Old) != sealed || !st.Mismatch() {
		t.Fatalf("status with the new KEK: %+v", st)
	}
	if st.Old[0].KEKVersion != k1.Version() || !strings.HasPrefix(st.Old[0].String(), "ca_keys.key_enc cak_") {
		t.Errorf("old %v", st.Old)
	}

	if _, _, err := controller.RotateKEK(ctx, h.cfg, filepath.Join(t.TempDir(), "missing"), noEnv); err == nil {
		t.Error("a previous KEK file that does not exist")
	}
	wrong := filepath.Join(t.TempDir(), "wrong")
	writeKEK(t, wrong, 0o600)
	if _, _, err := controller.RotateKEK(ctx, h.cfg, wrong, noEnv); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Errorf("a previous KEK that opens nothing: %v", err)
	}
	loose := filepath.Join(t.TempDir(), "loose")
	writeKEK(t, loose, 0o644)
	if _, _, err := controller.RotateKEK(ctx, h.cfg, loose, noEnv); err == nil {
		t.Error("a previous KEK file other users can read")
	}
	running, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.RotateKEK(ctx, h.cfg, prev, noEnv); !errors.Is(err, controller.ErrStopController) {
		t.Errorf("with a controller running: %v", err)
	}
	_ = running.Close()
	if st, _ := controller.StatusKEK(ctx, h.cfg, noEnv); len(st.Old) != sealed {
		t.Fatalf("a refused rotation changed secrets: %+v", st)
	}

	n, v, err := controller.RotateKEK(ctx, h.cfg, prev, noEnv)
	if err != nil || n != sealed || v != k2.Version() {
		t.Fatalf("rotate: %d %s %v; want %d secrets under %s", n, v, err, sealed, k2.Version())
	}
	st, err = controller.StatusKEK(ctx, h.cfg, noEnv)
	if err != nil || st.Versions[k2.Version()] != sealed || st.Versions[k1.Version()] != 0 || len(st.Old) != 0 || st.Mismatch() {
		t.Fatalf("status after the rotation: %+v %v", st, err)
	}
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]secret.KEK{"the new KEK": k2, "the old KEK": k1} {
		s, _ := secret.NewSealer(k)
		_, err := pki.LoadCA(storetest.SystemCtx(t), db, s, time.Now)
		if (err == nil) != (k.Version() == k2.Version()) {
			t.Errorf("the CA with %s: %v", name, err)
		}
	}
	_ = db.Close()
	if n, _, err := controller.RotateKEK(ctx, h.cfg, prev, noEnv); err != nil || n != 0 {
		t.Errorf("rotating again: %d %v", n, err)
	}
	if got := strings.Join(localActions(t, h), "\n"); !strings.Contains(got, "kek.rotate ") || !strings.Contains(got, "system_scope.grant rpmgr kek status") {
		t.Errorf("audit log:\n%s", got)
	}
}

// TestKEK_StatusWithoutKEK: `kek status` still counts the secrets when the KEK does not load, and
// says why.
func TestKEK_StatusWithoutKEK(t *testing.T) {
	h, _ := initHost(t)
	if err := os.Remove(h.kek); err != nil {
		t.Fatal(err)
	}
	st, err := controller.StatusKEK(context.Background(), h.cfg, noEnv)
	if err != nil || st.Current != "" || st.CurrentErr == nil || len(st.Old) < 4 || st.Mismatch() {
		t.Errorf("%+v %v", st, err)
	}
}

// TestSealedColumnsCovered: the columns `kek rotate` re-wraps are exactly those of the schema that
// hold sealed values, named *_enc.
func TestSealedColumnsCovered(t *testing.T) {
	var sealed []string
	for _, tbl := range entmigrate.Tables {
		for _, c := range tbl.Columns {
			if strings.HasSuffix(c.Name, "_enc") {
				sealed = append(sealed, tbl.Name+"."+c.Name)
			}
		}
	}
	known := controller.SealedColumns()
	slices.Sort(sealed)
	slices.Sort(known)
	if !slices.Equal(sealed, known) {
		t.Errorf("sealed columns %v, kek rotate re-wraps %v", sealed, known)
	}
}

// TestMigrate: `rpmgr migrate` applies what is pending after a copy of the database, and nothing
// on an up-to-date one; it refuses while a controller runs and without a database.
// olderDatabase replaces the SQLite database at path with one that has every embedded migration
// but the newest applied, and returns the newest's file name. With one migration, the database is
// empty.
func olderDatabase(t *testing.T, path string) string {
	t.Helper()
	ctx := context.Background()
	dir, err := migrations.Dir(store.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	files, err := dir.Files()
	if err != nil || len(files) == 0 {
		t.Fatalf("embedded migrations: %d, %v", len(files), err)
	}
	older := &migrate.MemDir{}
	for _, f := range files[:len(files)-1] {
		if err := older.WriteFile(f.Name(), f.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := older.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.WriteSumFile(older, sum); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	db, err := store.OpenSQLite(ctx, path, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := store.Migrate(ctx, db, older); err != nil {
		t.Fatal(err)
	}
	return files[len(files)-1].Name()
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	now := func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }
	h, _ := initHost(t)
	if res, err := controller.Migrate(ctx, h.cfg, now); err != nil || len(res.Applied) != 0 || res.Copy != "" {
		t.Fatalf("an up-to-date database: %+v %v", res, err)
	}

	// An older database: every embedded migration but the newest, as an earlier version left it.
	newest := olderDatabase(t, h.db)
	version, _, _ := strings.Cut(newest, "_")

	running, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Migrate(ctx, h.cfg, now); !errors.Is(err, controller.ErrStopController) {
		t.Errorf("with a controller running: %v", err)
	}
	_ = running.Close()

	res, err := controller.Migrate(ctx, h.cfg, now)
	if err != nil || len(res.Applied) != 1 || res.Applied[0] != newest || res.Copy != h.db+".before-migrate-20261009T120000Z" {
		t.Fatalf("migrate: %+v %v", res, err)
	}
	copyDB, err := store.OpenSQLite(ctx, res.Copy, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := copyDB.Writer.QueryRowContext(ctx, "SELECT count(*) FROM "+store.RevisionTable+" WHERE version = ?", version).Scan(&n); err != nil || n != 0 {
		t.Errorf("the copy is not the database before the migration: %d %v", n, err)
	}
	_ = copyDB.Close()
	if got := strings.Join(localActions(t, h), "\n"); !strings.Contains(got, "database.migrate "+newest) {
		t.Errorf("audit log:\n%s", got)
	}

	empty := newHost(t)
	empty.writeBoot(t, empty.fileKEK())
	if _, err := controller.Migrate(ctx, empty.cfg, now); err == nil || !strings.Contains(err.Error(), "controller init") {
		t.Errorf("no database: %v", err)
	}
}
