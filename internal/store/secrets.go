// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
)

// RecordSealed records the KEK version of a value that was sealed with Sealer.Seal for c, in tx,
// the transaction that writes the sealed value (docs/04-security.md, "Secrets at rest and in
// logs"). Seal before the transaction and record inside it: with a key service as the KEK, a seal
// can take as long as Transit does, and a write transaction on SQLite holds the single writer for
// all of it.
func RecordSealed(ctx context.Context, tx *ent.Tx, c secret.Context, sealed []byte) error {
	version, err := secret.KEKVersion(sealed)
	if err != nil {
		return err
	}
	n, err := tx.SecretMeta.Update().
		Where(secretmeta.TableName(c.Table), secretmeta.RowID(c.RowID), secretmeta.ColumnName(c.Column)).
		SetKekVersion(version).Save(ctx)
	if err != nil || n > 0 {
		return err
	}
	return tx.SecretMeta.Create().SetTableName(c.Table).SetRowID(c.RowID).SetColumnName(c.Column).
		SetKekVersion(version).Exec(ctx)
}

// ForgetSealed drops the record of a sealed value whose row is deleted, so that a KEK rotation
// does not look for it.
func ForgetSealed(ctx context.Context, tx *ent.Tx, c secret.Context) error {
	_, err := tx.SecretMeta.Delete().Where(secretmeta.TableName(c.Table), secretmeta.RowID(c.RowID), secretmeta.ColumnName(c.Column)).Exec(ctx)
	return err
}
