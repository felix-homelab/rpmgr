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
	"github.com/felix-homelab/rpmgr/internal/store"
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
}

// Backup is `rpmgr backup`: one archive, mode 0600, of a consistent copy of the controller's
// database (VACUUM INTO, while the controller keeps running) and of its revocation log and audit
// checkpoints, which live outside the database. Secrets in the database stay envelope-encrypted;
// the KEK is not in it. It is local administration, audited as local-cli.
func Backup(ctx context.Context, path, out, version string, now func() time.Time) (BackupInfo, error) {
	cfg, err := loadController(path)
	if err != nil {
		return BackupInfo{}, err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's path
	if err != nil {
		return BackupInfo{}, err
	}
	info, err := backup(ctx, cfg.Database.DSN, f, version, now)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		return BackupInfo{}, err
	}
	return info, nil
}

func backup(ctx context.Context, dsn string, w io.Writer, version string, now func() time.Time) (BackupInfo, error) {
	db, err := store.OpenSQLite(ctx, dsn, store.SQLiteOptions{})
	if err != nil {
		return BackupInfo{}, err
	}
	defer func() { _ = db.Close() }()
	sys, err := authz.System(ctx, "local-cli", "rpmgr backup", audit.SystemScopes(db))
	if err != nil {
		return BackupInfo{}, err
	}
	inst, err := db.Client().Instance.Get(sys, 1)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("controller: the database holds no installation: %w", err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dsn), ".backup-")
	if err != nil {
		return BackupInfo{}, err
	}
	copyPath := filepath.Join(tmp, BackupDatabase)
	defer func() {
		_ = os.Remove(copyPath)
		_ = os.Remove(tmp)
	}()
	if err := db.VacuumInto(ctx, copyPath); err != nil {
		return BackupInfo{}, err
	}
	info := BackupInfo{Format: 1, Version: version, Created: now().UTC(), TrustDomain: inst.TrustDomain, DBEpoch: inst.DbEpoch}
	meta, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return BackupInfo{}, err
	}
	state := filepath.Dir(dsn)
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
