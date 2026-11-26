// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// suppliedPass is a passphrase an operator might supply: long, mixed and not a run.
const suppliedPass = "Tr4ffic-Light-Mango-91x"

// rootRowOf reads the root's row from the host's database.
func rootRowOf(t *testing.T, h host) (offline bool, sealed []byte, id string) {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	r := db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(storetest.SystemCtx(t))
	if r.KeyEnc == nil || len(*r.KeyEnc) == 0 {
		return true, nil, r.ID
	}
	return false, bytes.Clone(*r.KeyEnc), r.ID
}

// offlineActions returns the audit entries of one action.
func auditOf(t *testing.T, h host, action string) []string {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var out []string
	for _, e := range db.Client().AuditEntry.Query().Where(auditentry.Action(action)).Order(auditentry.BySeq()).AllX(storetest.SystemCtx(t)) {
		out = append(out, e.ActorID+"|"+e.TargetID+"|"+e.Diff+"|"+e.Reason)
	}
	return out
}

// TestCA_OfflineRootCeremony (docs/12-testing-and-quality.md): the ceremony of `rpmgr ca
// offline-root`. Each clause of the row is a step.
func TestCA_OfflineRootCeremony(t *testing.T) {
	ctx := context.Background()
	h, init := initHost(t)
	k1, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(filepath.Dir(h.db), "revocations.log")
	out := filepath.Join(t.TempDir(), "root.age")
	opts := func(o string, pass string) controller.OfflineRootOptions {
		return controller.OfflineRootOptions{ConfigPath: h.cfg, Out: o, Passphrase: pass, Getenv: noEnv}
	}
	_, oldSealed, rootID := rootRowOf(t, h)
	oldBackup := filepath.Join(t.TempDir(), "before.backup")
	if _, err := controller.Backup(ctx, h.cfg, oldBackup, "0.1.0", time.Now); err != nil {
		t.Fatal(err)
	}
	s1, _ := secret.NewSealer(k1)
	rctx := secret.Context{Table: "ca_keys", Column: "key_enc", RowID: rootID}
	if _, err := s1.Open(context.Background(), rctx, oldSealed); err != nil {
		t.Fatalf("the old KEK does not open the sealed key: %v", err)
	}

	t.Run("an existing output file is refused and nothing changes", func(t *testing.T) {
		if err := os.WriteFile(out, []byte("precious"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.OfflineRoot(ctx, opts(out, suppliedPass)); err == nil || !strings.Contains(err.Error(), "exists") {
			t.Errorf("an existing file: %v", err)
		}
		if b, _ := os.ReadFile(out); string(b) != "precious" {
			t.Errorf("the existing file was changed: %q", b)
		}
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), link); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.OfflineRoot(ctx, opts(link, suppliedPass)); err == nil {
			t.Error("a dangling link as the output")
		}
		if off, _, _ := rootRowOf(t, h); off {
			t.Error("a refused ceremony took the root offline")
		}
		if err := os.Remove(out); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a weak supplied passphrase is refused before any file is written", func(t *testing.T) {
		for _, weak := range []string{"short", "aaaaaaaaaaaaaaaaaaaaaaaa", "1234567890123456", "qwertyuiopasdfgh"} {
			if _, err := controller.OfflineRoot(ctx, opts(out, weak)); !errors.Is(err, pki.ErrWeakPassphrase) {
				t.Errorf("%q: %v", weak, err)
			}
		}
		if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a refused passphrase left a file: %v", err)
		}
		if off, _, _ := rootRowOf(t, h); off {
			t.Error("a refused ceremony took the root offline")
		}
	})

	t.Run("a revocation log that cannot be written leaves everything as it was", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes to a read-only file")
		}
		if err := os.Chmod(logPath, 0o400); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(logPath, 0o600) }()
		if _, err := controller.OfflineRoot(ctx, opts(out, suppliedPass)); err == nil {
			t.Error("a revocation log that is read-only")
		}
		if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a failed ceremony left a file: %v", err)
		}
		if off, _, _ := rootRowOf(t, h); off || len(auditOf(t, h, castore.RootActionOffline)) != 0 {
			t.Error("a failed ceremony changed the database")
		}
	})

	// The ceremony, with a generated passphrase, beside a controller that keeps the database (and
	// its write-ahead log) open.
	keep, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = keep.Close() }()
	res, err := controller.OfflineRoot(ctx, opts(out, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Passphrase == "" || res.Pin != init.RootPin || res.KEK != k1.Version() {
		t.Fatalf("result %+v", res)
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the file: %v %v", st, err)
	}
	file, _ := os.ReadFile(out)
	root, err := pki.OpenRootFile(file, res.Passphrase)
	if err != nil || pki.RootPin(root.Cert) != init.RootPin {
		t.Fatalf("the file does not open as the root: %v", err)
	}
	if _, err := pki.OpenRootFile(file, "not the passphrase"); !errors.Is(err, pki.ErrRootFile) {
		t.Errorf("a wrong passphrase: %v", err)
	}
	if off, _, _ := rootRowOf(t, h); !off {
		t.Fatal("the root's key is still in the database")
	}
	if _, err := controller.OfflineRoot(ctx, opts(filepath.Join(t.TempDir(), "again"), suppliedPass)); !errors.Is(err, castore.ErrRootOffline) {
		t.Errorf("a second ceremony: %v", err)
	}

	t.Run("the audit entry and the marker", func(t *testing.T) {
		entries := auditOf(t, h, castore.RootActionOffline)
		want := "local-cli|" + res.PublicKeyHash + "|kek:" + k1.Version() + "|"
		if len(entries) != 1 || !strings.HasPrefix(entries[0], want) || !strings.Contains(entries[0], res.FileSHA256) {
			t.Errorf("audit entries %q, want one starting %q", entries, want)
		}
		log, err := revlog.Read(logPath)
		if err != nil || len(log) != 1 || log[0].Kind != revlog.RootOffline || log[0].Subject != res.PublicKeyHash || log[0].Detail != k1.Version() {
			t.Errorf("revocation log %+v %v", log, err)
		}
	})

	t.Run("a generated passphrase is stored nowhere", func(t *testing.T) {
		for _, p := range []string{h.db, h.db + "-wal", logPath, h.cfg, h.kek} {
			if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(res.Passphrase)) {
				t.Errorf("the passphrase is in %s", p)
			}
		}
	})

	t.Run("the sealed key remains in the file or its log, which is why the KEK is rotated", func(t *testing.T) {
		var found bool
		for _, p := range []string{h.db, h.db + "-wal"} {
			if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, oldSealed) {
				found = true
			}
		}
		if !found {
			t.Error("the scans below would prove nothing: the sealed key is not in the database file or its log")
		}
	})

	t.Run("ca status warns until the KEK is rotated", func(t *testing.T) {
		st, err := controller.CAStatus(ctx, h.cfg)
		if err != nil || !st.GetRootOffline() || st.GetRootKeyResidueKek() != k1.Version() {
			t.Errorf("status %v %v", st, err)
		}
	})

	t.Run("a restore of an older archive takes the root offline again", func(t *testing.T) {
		_ = keep.Close()
		r, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: oldBackup})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.RootKeysDropped) != 1 || r.RootKeysDropped[0] != res.PublicKeyHash || r.Reapplied != 1 {
			t.Errorf("restore result %+v", r)
		}
		if off, _, _ := rootRowOf(t, h); !off {
			t.Error("the restore brought the root's key back")
		}
		// The warning survives the restore: the entry of the ceremony is written again from the marker.
		if st, err := controller.CAStatus(ctx, h.cfg); err != nil || st.GetRootKeyResidueKek() != k1.Version() || st.GetRootKekUnknown() {
			t.Errorf("status after the restore: %v %v", st, err)
		}
		if got := strings.Join(auditOf(t, h, "instance.restore"), "\n"); !strings.Contains(got, "held the key of the root "+res.PublicKeyHash) {
			t.Errorf("the restore's audit entry: %s", got)
		}
		// Restoring again changes nothing and does not say the archive held the key.
		if keep, err = store.OpenSQLite(ctx, h.db, store.SQLiteOptions{}); err != nil {
			t.Fatal(err)
		}
	})

	// The KEK rotation that destroys the old KEK, then the scans.
	prev := filepath.Join(t.TempDir(), "old-kek")
	if err := os.Rename(h.kek, prev); err != nil {
		t.Fatal(err)
	}
	k2 := writeKEK(t, h.kek, 0o600)
	if _, _, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{File: prev}, noEnv); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(prev); err != nil { // destroyed
		t.Fatal(err)
	}
	if st, err := controller.CAStatus(ctx, h.cfg); err != nil || !st.GetRootOffline() || st.GetRootKeyResidueKek() != "" {
		t.Errorf("status after the rotation: %v %v", st, err)
	}
	backup := filepath.Join(t.TempDir(), "after.backup")
	if _, err := controller.Backup(ctx, h.cfg, backup, "0.1.0", time.Now); err != nil {
		t.Fatal(err)
	}
	files := untar(t, backup)
	der, err := x509.MarshalPKCS8PrivateKey(root.Key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	scalar, err := root.Key.Bytes() // the raw private scalar
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := secret.NewSealer(k2)
	scan := map[string][]byte{"the backup's database": files[controller.BackupDatabase]}
	for name, p := range map[string]string{"the database file": h.db, "its write-ahead log": h.db + "-wal"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		scan[name] = b
	}
	if len(scan["its write-ahead log"]) == 0 {
		t.Error("the write-ahead log is empty, so the scan proves nothing")
	}
	for name, b := range scan {
		for what, needle := range map[string][]byte{"the private key (DER)": der, "the private key (PEM)": pemKey, "the private scalar": scalar,
			"the passphrase": []byte(res.Passphrase)} {
			if bytes.Contains(b, needle) {
				t.Errorf("%s holds %s", name, what)
			}
		}
		// What the old KEK could open may remain in free pages and the log; the destroyed KEK is
		// gone, and nothing the current one has opens it. A new backup has none of it.
		if bytes.Contains(b, oldSealed) {
			if name == "the backup's database" {
				t.Errorf("%s holds the root's key sealed under the old KEK", name)
			}
			if _, err := s2.Open(context.Background(), rctx, oldSealed); err == nil {
				t.Errorf("%s: the current KEK opens the old sealed key", name)
			}
		}
	}
}

// TestCA_OfflineRootIntermediateRoundTrip: request, signature on an offline host and import, with
// the functions the commands call; a wrong passphrase, a request that is not ours and a refusal at
// the confirmation change nothing.
func TestCA_OfflineRootIntermediateRoundTrip(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.age")
	if _, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: h.cfg, Out: rootFile, Passphrase: suppliedPass, Getenv: noEnv}); err != nil {
		t.Fatal(err)
	}
	// With the root offline, the online-root commands refuse.
	if _, err := controller.RotateIntermediate(ctx, h.cfg, noEnv); !errors.Is(err, castore.ErrRootOffline) {
		t.Errorf("rotate-intermediate with an offline root: %v", err)
	}
	csr := filepath.Join(dir, "next.csr")
	hash, err := controller.RequestIntermediate(ctx, h.cfg, csr, noEnv, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.RequestIntermediate(ctx, h.cfg, csr, noEnv, time.Now); err == nil {
		t.Error("an existing request file was overwritten")
	}
	if again, err := controller.RequestIntermediate(ctx, h.cfg, filepath.Join(dir, "again.csr"), noEnv, time.Now); err != nil || again != hash {
		t.Errorf("a second request must return the one that waits: %s %v", again, err)
	}
	cert := filepath.Join(dir, "next.crt")
	sign := func(pass string, confirm func(controller.IntermediateSummary) (bool, error)) (controller.IntermediateSummary, error) {
		return controller.SignIntermediate(controller.SignOptions{RootFile: rootFile, CSR: csr, Out: cert, Passphrase: pass, Confirm: confirm})
	}
	if _, err := sign("not the passphrase", nil); !errors.Is(err, pki.ErrRootFile) {
		t.Errorf("a wrong passphrase: %v", err)
	}
	if _, err := sign(suppliedPass, func(controller.IntermediateSummary) (bool, error) { return false, nil }); !errors.Is(err, controller.ErrDeclined) {
		t.Errorf("a declined confirmation: %v", err)
	}
	if _, err := os.Lstat(cert); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused signature left a certificate: %v", err)
	}
	var shown controller.IntermediateSummary
	sum, err := sign(suppliedPass, func(s controller.IntermediateSummary) (bool, error) { shown = s; return true, nil })
	if err != nil || sum.KeyHash != hash || shown.KeyHash != hash || !strings.Contains(shown.Constraints, "path length 0") {
		t.Fatalf("sign: %+v %v (the request's key is %s)", sum, err, hash)
	}
	if _, err := sign(suppliedPass, nil); err == nil {
		t.Error("an existing certificate was overwritten")
	}
	if _, err := controller.SignIntermediate(controller.SignOptions{RootFile: rootFile, CSR: rootFile, Out: filepath.Join(dir, "x"), Passphrase: suppliedPass}); !errors.Is(err, pki.ErrBadCSR) {
		t.Errorf("a request that is no request: %v", err)
	}

	// A certificate that does not chain, is refused and changes nothing.
	other := newOfflineRootFor(t, dir)
	if _, err := controller.ImportIntermediate(ctx, h.cfg, other, time.Now); !errors.Is(err, pki.ErrIntermediateRefused) {
		t.Errorf("a certificate of another root: %v", err)
	}
	if _, err := controller.ImportIntermediate(ctx, h.cfg, csr, time.Now); err == nil {
		t.Error("a request imported as a certificate")
	}
	got, err := controller.ImportIntermediate(ctx, h.cfg, cert, time.Now)
	if err != nil || got.KeyHash != hash {
		t.Fatalf("import: %+v %v", got, err)
	}
	if _, err := controller.ImportIntermediate(ctx, h.cfg, cert, time.Now); !errors.Is(err, castore.ErrNoRequest) {
		t.Errorf("a second import: %v", err)
	}
	for _, a := range []string{"ca.request_intermediate", "ca.import_intermediate"} {
		if e := auditOf(t, h, a); len(e) == 0 || !strings.Contains(e[len(e)-1], hash) {
			t.Errorf("audit %s: %q", a, e)
		}
	}
}

// newOfflineRootFor makes a certificate for the intermediate that waits, signed by a root that is
// not this installation's, and returns its path.
func newOfflineRootFor(t *testing.T, dir string) string {
	t.Helper()
	root, err := pki.NewRoot("rpmgr-7f3k2q6m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := pki.NewIntermediateRequest()
	if err != nil {
		t.Fatal(err)
	}
	_ = key
	cert, err := pki.SignIntermediate(root, csr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "other.crt")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A backup taken while the ceremony is in flight can hold the database from before its commit and a
// copy of the log from after the marker was appended. The restore applies the archive's own markers
// too, so the root does not come back online.
func TestRestore_MarkerInTheArchivesOwnLog(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	row := db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).OnlyX(storetest.SystemCtx(t))
	_ = db.Close()
	hash := pki.PublicKeyHash(row.PublicKey)
	rl, err := revlog.Open(filepath.Join(filepath.Dir(h.db), "revocations.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rl.Append(revlog.Entry{Kind: revlog.RootOffline, Subject: hash, Detail: "0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "mid-ceremony.backup")
	if _, err := controller.Backup(ctx, h.cfg, archive, "0.1.0", time.Now); err != nil {
		t.Fatal(err)
	}
	if off, _, _ := rootRowOf(t, h); off {
		t.Fatal("the premise: the database still holds the key")
	}
	r, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: archive})
	if err != nil {
		t.Fatal(err)
	}
	if off, _, _ := rootRowOf(t, h); !off || len(r.RootKeysDropped) != 1 || r.RootKeysDropped[0] != hash {
		t.Errorf("the root is online after the restore: %+v", r)
	}
	if e := auditOf(t, h, castore.RootActionOffline); len(e) != 1 || !strings.Contains(e[0], "kek:0123456789abcdef") {
		t.Errorf("the entry written from the marker: %q", e)
	}
}

// sign-intermediate with --key-sha256 refuses another request before it signs.
func TestSignIntermediateKeyHash(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.age")
	if _, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: h.cfg, Out: rootFile, Passphrase: suppliedPass, Getenv: noEnv}); err != nil {
		t.Fatal(err)
	}
	csr := filepath.Join(dir, "next.csr")
	hash, err := controller.RequestIntermediate(ctx, h.cfg, csr, noEnv, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(want, out string) error {
		_, err := controller.SignIntermediate(controller.SignOptions{RootFile: rootFile, CSR: csr, Out: out, Passphrase: suppliedPass, KeyHash: want})
		return err
	}
	cert := filepath.Join(dir, "next.crt")
	if err := sign(strings.Repeat("0", 64), cert); err == nil || !strings.Contains(err.Error(), "nothing was signed") {
		t.Errorf("another key's hash: %v", err)
	}
	if _, err := os.Lstat(cert); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused request left a certificate: %v", err)
	}
	if err := sign(strings.ToUpper(hash), cert); err != nil {
		t.Errorf("the right hash, in capitals: %v", err)
	}
}
