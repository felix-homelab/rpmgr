// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	entsql "entgo.io/ent/dialect/sql"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/acmestorage"
	"github.com/felix-homelab/rpmgr/internal/store/ent/apirequest"
	eauditsink "github.com/felix-homelab/rpmgr/internal/store/ent/auditsink"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsprovider"
	"github.com/felix-homelab/rpmgr/internal/store/ent/instancesecret"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
	"github.com/felix-homelab/rpmgr/internal/store/ent/totpcredential"
	ewebhook "github.com/felix-homelab/rpmgr/internal/store/ent/webhook"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// Local administration on the controller host (docs/16-cli.md): authorised by host access, audited
// as local-cli.

// ErrStopController is returned by a command that must not run beside a controller while one holds
// the database.
var ErrStopController = errors.New("controller: a controller is running on this database; stop it first")

// openLocal opens the database of the boot file at path beside a running controller, in the
// system scope of local-cli for the command what, which the audit log records.
func openLocal(ctx context.Context, path, what string) (config.Controller, *store.DB, context.Context, error) {
	cfg, err := loadController(path)
	if err != nil {
		return cfg, nil, nil, err
	}
	if _, err := os.Stat(cfg.Database.DSN); err != nil {
		return cfg, nil, nil, fmt.Errorf("controller: no database at %s; run `rpmgr controller init` first: %w", cfg.Database.DSN, err)
	}
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return cfg, nil, nil, err
	}
	sys, err := authz.System(ctx, "local-cli", what, audit.SystemScopes(db))
	if err != nil {
		_ = db.Close()
		return cfg, nil, nil, err
	}
	return cfg, db, sys, nil
}

// localKEK loads the KEK of the boot file for a command run from a shell, where a systemd
// credential is not loaded unless the command runs under systemd-run.
func localKEK(cfg config.Controller, getenv func(string) string) (secret.KEK, error) {
	k, err := loadKEK(cfg, getenv)
	if err != nil && cfg.KEK.Source == config.KEKSystemdCredential {
		path := filepath.Join("/etc/rpmgr/credstore", cfg.KEK.Name)
		return k, fmt.Errorf("controller: the KEK credential %s is not loaded: run the command under "+
			"systemd-run --pipe --wait --property=LoadCredentialEncrypted=%s:%s (%w)", cfg.KEK.Name, cfg.KEK.Name, path, err)
	}
	return k, err
}

// localWrapper opens the KEK source of the boot file for a command run from a shell; a Transit key
// is read and checked, so that a command stops with the reason when Transit cannot be used.
func localWrapper(ctx context.Context, cfg config.Controller, getenv func(string) string) (kekWrapper, error) {
	return openKEK(ctx, cfg, func(c config.Controller) (secret.KEK, error) { return localKEK(c, getenv) }, nil, nil)
}

// CAStatus is `rpmgr ca status`: the CA's keys that have not expired, as Settings → PKI shows them.
// It needs no KEK.
func CAStatus(ctx context.Context, path string) (*rpmgrv1.GetPkiStatusResponse, error) {
	_, db, sys, err := openLocal(ctx, path, "rpmgr ca status")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	resp, err := (&apisvc.Pki{DB: db, Sys: sys}).GetPkiStatus(sys, connect.NewRequest(&rpmgrv1.GetPkiStatusRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// RotateIntermediate is `rpmgr ca rotate-intermediate`: a new issuing intermediate now, beside a
// running controller, which reloads its keys within a minute (docs/04-security.md, "CA
// rotation"). It returns the new intermediate.
func RotateIntermediate(ctx context.Context, path string, getenv func(string) string) (*rpmgrv1.CAKey, error) {
	cfg, err := loadController(path)
	if err != nil {
		return nil, err
	}
	kek, err := localWrapper(ctx, cfg, getenv)
	if err != nil {
		return nil, err
	}
	sealer, err := secret.NewSealerWith(kek.Wrapper)
	if err != nil {
		return nil, err
	}
	_, db, sys, err := openLocal(ctx, path, "rpmgr ca rotate-intermediate")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	resp, err := (&apisvc.Pki{DB: db, Sys: sys, Sealer: sealer}).RotateIntermediate(sys, connect.NewRequest(&rpmgrv1.RotateIntermediateRequest{}))
	if err != nil {
		return nil, err
	}
	k := resp.Msg.GetIntermediate()
	_, err = audit.Record(sys, db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "ca.rotate_intermediate",
		TargetType: "ca", TargetID: k.GetSubject(), Result: audit.Success, Reason: "rotated on the controller host"})
	return k, err
}

// A sealed column (docs/04-security.md, "Secrets at rest and in logs"). Responses of request_ids
// live a day and are not recorded in secrets_meta; a rotation re-wraps them all the same.
type sealedColumn struct {
	table, id, column string
	meta              bool // recorded in secrets_meta
}

var sealedColumns = []sealedColumn{
	{cakey.Table, cakey.FieldID, cakey.FieldKeyEnc, true},
	{certificate.Table, certificate.FieldID, certificate.FieldKeyEnc, true},
	{acmestorage.Table, acmestorage.FieldID, acmestorage.FieldValueEnc, true},
	{instancesecret.Table, instancesecret.FieldID, instancesecret.FieldValueEnc, true},
	{totpcredential.Table, totpcredential.FieldID, totpcredential.FieldSeedEnc, true},
	{apirequest.Table, apirequest.FieldID, apirequest.FieldResponseEnc, false},
	{ewebhook.Table, ewebhook.FieldID, ewebhook.FieldSecretEnc, true},
	{ewebhook.Table, ewebhook.FieldID, ewebhook.FieldPreviousSecretEnc, true},
	{ewebhook.Table, ewebhook.FieldID, ewebhook.FieldURLEnc, true},
	{eauditsink.Table, eauditsink.FieldID, eauditsink.FieldSecretEnc, true},
	{dnsprovider.Table, dnsprovider.FieldID, dnsprovider.FieldCredentialEnc, true},
}

// SealedRef names one sealed value.
type SealedRef struct {
	Table, Column, RowID, KEKVersion string
}

func (r SealedRef) String() string { return r.Table + "." + r.Column + " " + r.RowID }

// KEKStatus is `rpmgr kek status`.
type KEKStatus struct {
	Current    string         // the version of the boot file's KEK; empty if it did not load
	CurrentErr error          // why it did not load
	Versions   map[string]int // sealed values by KEK version, as secrets_meta records them
	Old        []SealedRef    // values under another KEK than Current, which `kek rotate` re-wraps
}

// Mismatch reports whether the boot file's KEK wraps none of the recorded secrets while others do:
// the boot file names another KEK than the one the database was sealed with. A Transit key that
// was rotated is not one: its older versions are the same KEK, and `kek rotate` moves them.
func (s KEKStatus) Mismatch() bool {
	if s.Current == "" || len(s.Old) == 0 {
		return false
	}
	for v, n := range s.Versions {
		if n > 0 && secret.KEKIdentity(v) == secret.KEKIdentity(s.Current) {
			return false
		}
	}
	return true
}

// Write prints the status as `rpmgr kek status` shows it. It prints versions and counts, and the
// reason the KEK did not load, which holds no credential.
func (s KEKStatus) Write(w io.Writer) error {
	if s.CurrentErr != nil {
		fmt.Fprintf(w, "The boot file's KEK: not loaded (%v)\n\n", s.CurrentErr)
	} else {
		fmt.Fprintf(w, "The boot file's KEK: version %s\n\n", s.Current)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KEK VERSION\tSECRETS")
	for _, v := range slices.Sorted(maps.Keys(s.Versions)) {
		mark := ""
		if v == s.Current {
			mark = " (the boot file's)"
		}
		fmt.Fprintf(tw, "%s%s\t%d\n", v, mark, s.Versions[v])
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if s.Mismatch() {
		fmt.Fprintln(w, "\nThe boot file's KEK wraps none of the secrets: it is not the KEK of this database, or a\n"+
			"rotation is pending (rpmgr kek rotate --previous-file <the old KEK> or\n--previous-config <the old boot file>).")
	}
	if len(s.Old) > 0 && s.CurrentErr == nil {
		fmt.Fprintf(w, "\nUnder another KEK or key version than the boot file's (%d):\n", len(s.Old))
		for _, r := range s.Old {
			fmt.Fprintf(w, "  %s  (%s)\n", r, r.KEKVersion)
		}
	}
	return nil
}

// StatusKEK is `rpmgr kek status`: which KEK versions wrap the stored secrets, by secrets_meta,
// beside a running controller. Records of rows deleted since are left out.
func StatusKEK(ctx context.Context, path string, getenv func(string) string) (KEKStatus, error) {
	cfg, db, sys, err := openLocal(ctx, path, "rpmgr kek status")
	if err != nil {
		return KEKStatus{}, err
	}
	defer func() { _ = db.Close() }()
	st := KEKStatus{Versions: map[string]int{}}
	if k, err := localWrapper(ctx, cfg, getenv); err != nil {
		st.CurrentErr = err
	} else {
		st.Current = k.Version
	}
	err = store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
		rows, err := tx.SecretMeta.Query().Order(ent.Asc(secretmeta.FieldTableName), ent.Asc(secretmeta.FieldRowID)).All(sys)
		if err != nil {
			return err
		}
		for _, c := range sealedColumns {
			live, err := sealedValues(sys, tx, db.Dialect, c)
			if err != nil {
				return err
			}
			for _, r := range rows {
				if r.TableName != c.table || r.ColumnName != c.column || live[r.RowID] == nil {
					continue
				}
				st.Versions[r.KekVersion]++
				if r.KekVersion != st.Current {
					st.Old = append(st.Old, SealedRef{Table: r.TableName, Column: r.ColumnName, RowID: r.RowID, KEKVersion: r.KekVersion})
				}
			}
		}
		return nil
	})
	return st, err
}

// sealedValues returns the non-empty values of a sealed column by row ID.
func sealedValues(ctx context.Context, tx *ent.Tx, dialect string, c sealedColumn) (map[string][]byte, error) {
	q, args := entsql.Dialect(dialect).Select(c.id, c.column).From(entsql.Table(c.table)).Where(entsql.NotNull(c.column)).Query()
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]byte{}
	for rows.Next() {
		var id string
		var v []byte
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		if len(v) > 0 {
			out[id] = v
		}
	}
	return out, rows.Err()
}

// ErrPreviousNeeded is returned by RotateKEK for a file or credential KEK without the previous one:
// only a Transit key has earlier versions of itself to re-wrap.
var ErrPreviousNeeded = errors.New("controller: the previous KEK is needed: --previous-file or --previous-config")

// PreviousKEK names the KEK before a rotation: a file of the format of kek.source file, or a boot
// file whose kek section names it, of any source, to move between a file or credential and Transit.
// At most one is set; with neither, the boot file's KEK must be a Transit key, whose earlier
// versions are re-wrapped to the latest.
type PreviousKEK struct {
	File, Config string
}

// RotateKEK is `rpmgr kek rotate`: with every controller stopped, it re-wraps the data key of every
// stored secret under the boot file's KEK, opening them with it or with the previous one; the
// secrets themselves are not re-encrypted (docs/04-security.md, "Secrets at rest and in logs"). It
// is one transaction: a secret that opens with neither KEK changes nothing, and Transit being down
// stops it. It returns how many values it re-wrapped and the new version.
func RotateKEK(ctx context.Context, path string, previous PreviousKEK, getenv func(string) string) (int, string, error) {
	if previous.File != "" && previous.Config != "" {
		return 0, "", errors.New("controller: the previous KEK is a file or a boot file, not both")
	}
	cfg, err := loadController(path)
	if err != nil {
		return 0, "", err
	}
	if previous == (PreviousKEK{}) && cfg.KEK.Source != config.KEKKMS {
		return 0, "", ErrPreviousNeeded
	}
	kek, err := localWrapper(ctx, cfg, getenv)
	if err != nil {
		return 0, "", err
	}
	var prev []secret.Wrapper
	from := "earlier versions of " + kek.Version
	switch {
	case previous.File != "":
		old, err := secret.LoadKEKFile(previous.File)
		if err != nil {
			return 0, "", fmt.Errorf("controller: the previous KEK: %w", err)
		}
		prev, from = append(prev, secret.NewLocalWrapper(old)), old.Version()
	case previous.Config != "":
		pcfg, err := loadController(previous.Config)
		if err != nil {
			return 0, "", fmt.Errorf("controller: the previous KEK: %w", err)
		}
		old, err := localWrapper(ctx, pcfg, getenv)
		if err != nil {
			return 0, "", fmt.Errorf("controller: the previous KEK: %w", err)
		}
		prev, from = append(prev, old.Wrapper), old.Version
	}
	sealer, err := secret.NewSealerWith(kek.Wrapper, prev...)
	if err != nil {
		return 0, "", err
	}
	// Only SQLite exists in this phase, so the one lock a command can take is the exclusive one;
	// beside replicas it would be the shared one.
	unlock, err := store.HoldLock(cfg.Database.DSN)
	if errors.Is(err, store.ErrLocked) {
		return 0, "", ErrStopController
	}
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = unlock() }()
	_, db, sys, err := openLocal(ctx, path, "rpmgr kek rotate")
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = db.Close() }()
	n := 0
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		var failed []string
		for _, c := range sealedColumns {
			values, err := sealedValues(sys, tx, db.Dialect, c)
			if err != nil {
				return err
			}
			ids := make([]string, 0, len(values))
			for id := range values {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			if c.meta {
				if _, err := tx.SecretMeta.Delete().Where(secretmeta.TableName(c.table), secretmeta.ColumnName(c.column)).Exec(sys); err != nil {
					return err
				}
			}
			for _, id := range ids {
				re, err := sealer.Rewrap(sys, secret.Context{Table: c.table, Column: c.column, RowID: id}, values[id])
				if errors.Is(err, secret.ErrOpen) {
					failed = append(failed, c.table+"."+c.column+" "+id)
					continue
				}
				if err != nil {
					// Transit is down or refuses: nothing is known about this value.
					return fmt.Errorf("controller: %s.%s %s: %w", c.table, c.column, id, err)
				}
				if !slices.Equal(re, values[id]) {
					q, args := entsql.Dialect(db.Dialect).Update(c.table).Set(c.column, re).Where(entsql.EQ(c.id, id)).Query()
					if _, err := tx.ExecContext(sys, q, args...); err != nil {
						return err
					}
					n++
				}
				if c.meta {
					version, err := secret.KEKVersion(re)
					if err != nil {
						return err
					}
					if err := tx.SecretMeta.Create().SetTableName(c.table).SetRowID(id).SetColumnName(c.column).
						SetKekVersion(version).Exec(sys); err != nil {
						return err
					}
				}
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("controller: %d secrets open with neither the boot file's KEK nor the previous one, so nothing was re-wrapped: %s",
				len(failed), strings.Join(failed, ", "))
		}
		_, err := audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "kek.rotate",
			TargetType: "kek", TargetID: kek.Version, Result: audit.Success,
			Reason: fmt.Sprintf("%d secrets re-wrapped from %s", n, from)})
		return err
	})
	if err != nil {
		return 0, "", err
	}
	return n, kek.Version, nil
}

// MigrateResult is what `rpmgr migrate` did.
type MigrateResult struct {
	Applied []string // the migration files, in order
	Copy    string   // the copy of the database taken before them; empty when none was pending
}

// Migrate is `rpmgr migrate`: with the controller stopped, it applies the pending migrations of
// this binary to the database, after a VACUUM INTO copy of it (docs/06-data-model.md,
// "Migrations"). A single-node controller migrates when it starts as well.
func Migrate(ctx context.Context, path string, now func() time.Time) (MigrateResult, error) {
	cfg, err := loadController(path)
	if err != nil {
		return MigrateResult{}, err
	}
	dsn := cfg.Database.DSN
	if _, err := os.Stat(dsn); err != nil {
		return MigrateResult{}, fmt.Errorf("controller: no database at %s; run `rpmgr controller init` first: %w", dsn, err)
	}
	unlock, err := store.HoldLock(dsn)
	if errors.Is(err, store.ErrLocked) {
		return MigrateResult{}, ErrStopController
	}
	if err != nil {
		return MigrateResult{}, err
	}
	defer func() { _ = unlock() }()
	db, err := store.OpenSQLite(ctx, dsn, store.SQLiteOptions{})
	if err != nil {
		return MigrateResult{}, err
	}
	defer func() { _ = db.Close() }()
	dir, err := migrations.Dir(db.Dialect)
	if err != nil {
		return MigrateResult{}, err
	}
	pending, err := store.Pending(ctx, db, dir)
	if err != nil {
		return MigrateResult{}, err
	}
	var res MigrateResult
	if len(pending) > 0 {
		res.Copy = dsn + ".before-migrate-" + now().UTC().Format("20060102T150405Z")
		if err := db.VacuumInto(ctx, res.Copy); err != nil {
			return MigrateResult{}, err
		}
	}
	n, err := store.Migrate(ctx, db, dir)
	for _, f := range pending[:n] {
		res.Applied = append(res.Applied, f.Name())
	}
	if err != nil {
		return res, fmt.Errorf("%w; the database before it is %s", err, res.Copy)
	}
	sys, err := authz.System(ctx, "local-cli", "rpmgr migrate", audit.SystemScopes(db))
	if err != nil {
		return res, err
	}
	if len(res.Applied) > 0 {
		_, err = audit.Record(sys, db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "database.migrate",
			Result: audit.Success, Reason: strings.Join(res.Applied, ", ")})
	}
	return res, err
}
