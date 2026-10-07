// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
)

// Seal encrypts v for column c.Column of row c.RowID in table c.Table and records the KEK version
// in secrets_meta, in tx, the transaction that writes the sealed value (docs/04-security.md,
// "Secrets at rest and in logs").
func Seal(ctx context.Context, tx *ent.Tx, s *secret.Sealer, c secret.Context, v secret.Value) ([]byte, error) {
	sealed, err := s.Seal(c, v)
	if err != nil {
		return nil, err
	}
	version, err := secret.KEKVersion(sealed)
	if err != nil {
		return nil, err
	}
	n, err := tx.SecretMeta.Update().
		Where(secretmeta.TableName(c.Table), secretmeta.RowID(c.RowID), secretmeta.ColumnName(c.Column)).
		SetKekVersion(version).Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		err = tx.SecretMeta.Create().SetTableName(c.Table).SetRowID(c.RowID).SetColumnName(c.Column).
			SetKekVersion(version).Exec(ctx)
	}
	return sealed, err
}
