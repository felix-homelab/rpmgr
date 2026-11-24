// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The instance secrets.
const (
	// SMTPPassword is the mail relay's password.
	SMTPPassword = "smtp_password"
)

// SetInstanceSecret stores a secret of the instance settings under the KEK, replacing its value;
// an empty value removes it. ctx must carry the system scope.
func SetInstanceSecret(ctx context.Context, db *store.DB, sealer *secret.Sealer, name string, v secret.Value) error {
	return store.WriteTx(ctx, db, func(tx *ent.Tx) error {
		if err := tx.InstanceSecret.DeleteOneID(name).Exec(ctx); err != nil && !ent.IsNotFound(err) {
			return err
		}
		if v.IsZero() {
			return store.ForgetSealed(ctx, tx, secretContext(name))
		}
		// Recorded in secrets_meta, so a KEK rotation finds it.
		sealed, err := store.Seal(ctx, tx, sealer, secretContext(name), v)
		if err != nil {
			return err
		}
		return tx.InstanceSecret.Create().SetID(name).SetValueEnc(sealed).SetUpdatedAt(time.Now()).Exec(ctx)
	})
}

// InstanceSecret returns a secret of the instance settings; a zero Value if it is not set.
func InstanceSecret(ctx context.Context, c *ent.Client, sealer *secret.Sealer, name string) (secret.Value, error) {
	row, err := c.InstanceSecret.Get(ctx, name)
	if ent.IsNotFound(err) {
		return secret.Value{}, nil
	}
	if err != nil {
		return secret.Value{}, err
	}
	return sealer.Open(secretContext(name), row.ValueEnc)
}

func secretContext(name string) secret.Context {
	return secret.Context{Table: "instance_secrets", Column: "value_enc", RowID: name}
}
