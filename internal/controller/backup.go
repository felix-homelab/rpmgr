// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The files of a backup archive (docs/10-operations.md, "Backup and restore").
const (
	BackupMeta        = "backup.json"
	BackupDatabase    = "controller.db"
	BackupRevocations = "revocations.log"
	BackupCheckpoints = "audit-checkpoints.log"
)

// BackupInfo is backup.json, which describes the archive.
type BackupInfo struct {
	Format      int       `json:"format"`
	Version     string    `json:"version"`
	Created     time.Time `json:"created"`
	TrustDomain string    `json:"trust_domain"`
	DBEpoch     string    `json:"db_epoch"`
	// SourceDialect is the engine the backup was taken from, sqlite or postgres; controller.db is
	// SQLite either way. Archives of earlier releases have none and came from SQLite.
	SourceDialect string `json:"source_dialect,omitempty"`
}

// Backup is `rpmgr backup`: one archive, mode 0600, of a consistent copy of the controller's
// database (VACUUM INTO on SQLite; on PostgreSQL the copier of migrate-db inside one snapshot
// transaction; either while the controller keeps running) and of its revocation log and audit
// checkpoints, which live outside the database. Secrets in the database stay envelope-encrypted;
// the KEK is not in it. It is local administration, audited as local-cli.
func Backup(ctx context.Context, path, out, version string, now func() time.Time) (BackupInfo, error) {
	d, err := bootDatabase(path)
	if err != nil {
		return BackupInfo{}, err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's path
	if err != nil {
		return BackupInfo{}, err
	}
	info, err := backup(ctx, d, f, version, now)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		return BackupInfo{}, err
	}
	return info, nil
}

// BackupTo is `rpmgr backup --out -`: the same archive, written to w, which the root updater reads
// from a backup run as the service user, so that root opens nothing in the state directory.
func BackupTo(ctx context.Context, path string, w io.Writer, version string, now func() time.Time) (BackupInfo, error) {
	d, err := bootDatabase(path)
	if err != nil {
		return BackupInfo{}, err
	}
	return backup(ctx, d, w, version, now)
}

func backup(ctx context.Context, d config.Database, w io.Writer, version string, now func() time.Time) (BackupInfo, error) {
	state := stateDir(d)
	if d.Driver != "postgres" {
		if root, err := os.OpenRoot(state); err == nil {
			// Run by root, SQLite would follow a link the service user planted for a journal name.
			err = refuseLinks(root, filepath.Base(d.DSN), filepath.Base(d.DSN)+"-wal", filepath.Base(d.DSN)+"-shm")
			_ = root.Close()
			if err != nil {
				return BackupInfo{}, err
			}
		}
	}
	tmp, err := os.MkdirTemp(state, ".backup-")
	if err != nil {
		return BackupInfo{}, err
	}
	defer func() {
		if es, err := os.ReadDir(tmp); err == nil {
			for _, e := range es {
				_ = os.Remove(filepath.Join(tmp, e.Name()))
			}
		}
		_ = os.Remove(tmp)
	}()
	copyPath := filepath.Join(tmp, BackupDatabase)
	var inst *ent.Instance
	if d.Driver == "postgres" {
		inst, err = snapshotPostgres(ctx, d, tmp, copyPath)
	} else {
		inst, err = snapshotSQLite(ctx, d.DSN, copyPath)
	}
	if err != nil {
		return BackupInfo{}, err
	}
	info := BackupInfo{Format: 1, Version: version, Created: now().UTC(), TrustDomain: inst.TrustDomain, DBEpoch: inst.DbEpoch, SourceDialect: dialectOf(d)}
	meta, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return BackupInfo{}, err
	}
	tw := tar.NewWriter(w)
	if err := addBytes(tw, BackupMeta, append(meta, '\n'), info.Created); err != nil {
		return BackupInfo{}, err
	}
	if err := addFile(tw, BackupDatabase, copyPath, info.Created); err != nil {
		return BackupInfo{}, err
	}
	for _, name := range []string{BackupRevocations, BackupCheckpoints} {
		b, err := os.ReadFile(filepath.Join(state, name)) //nolint:gosec // G304: the controller's state directory
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return BackupInfo{}, err
		}
		// Both logs are appended line by line; a line without its newline is still being written.
		if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
			b = b[:i+1]
		} else {
			b = nil
		}
		if err := addBytes(tw, name, b, info.Created); err != nil {
			return BackupInfo{}, err
		}
	}
	return info, tw.Close()
}

func dialectOf(d config.Database) string {
	if d.Driver == "postgres" {
		return "postgres"
	}
	return "sqlite"
}

// snapshotSQLite writes a consistent copy of the SQLite database at dsn to copyPath and returns
// its installation.
func snapshotSQLite(ctx context.Context, dsn, copyPath string) (*ent.Instance, error) {
	db, err := store.OpenSQLite(ctx, dsn, store.SQLiteOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	sys, err := authz.System(ctx, "local-cli", "rpmgr backup", audit.SystemScopes(db))
	if err != nil {
		return nil, err
	}
	inst, err := db.Client().Instance.Get(sys, 1)
	if err != nil {
		return nil, fmt.Errorf("controller: the database holds no installation: %w", err)
	}
	return inst, db.VacuumInto(ctx, copyPath)
}

// snapshotPostgres copies a PostgreSQL database into a SQLite file at copyPath, through the copier
// of `migrate-db` and inside one snapshot transaction (REPEATABLE READ, READ ONLY), so the copy
// holds one revision whatever a running controller writes meanwhile. It takes no controller lock
// and writes nothing to the database. The work file lives in tmp; the finished copy is a single
// file.
func snapshotPostgres(ctx context.Context, d config.Database, tmp, copyPath string) (*ent.Instance, error) {
	src, err := store.OpenPostgres(ctx, d.DSN, store.PostgresOptions{PasswordFile: d.PasswordFile, PasswordCredential: d.PasswordCredential})
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	if err := checkSource(ctx, src); err != nil {
		return nil, err
	}
	work, err := store.OpenSQLite(ctx, filepath.Join(tmp, "work.db"), store.SQLiteOptions{Create: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = work.Close() }()
	if err := migrateEmptyTarget(ctx, work); err != nil {
		return nil, err
	}
	if _, err := store.CopyDatabase(ctx, src, work, store.CopyOptions{}); err != nil {
		return nil, err
	}
	sys, err := authz.System(ctx, "local-cli", "rpmgr backup", audit.SystemScopes(work))
	if err != nil {
		return nil, err
	}
	inst, err := work.Client().Instance.Get(sys, 1)
	if err != nil {
		return nil, fmt.Errorf("controller: the database holds no installation: %w", err)
	}
	return inst, work.VacuumInto(ctx, copyPath)
}

func addBytes(tw *tar.Writer, name string, b []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: mod, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func addFile(tw *tar.Writer, name, path string, mod time.Time) error {
	f, err := os.Open(path) //nolint:gosec // G304: the backup's own copy
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: mod, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}
