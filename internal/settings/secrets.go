// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The instance secrets.
const (
	// SMTPPassword is the mail relay's password.
	SMTPPassword = "smtp_password"
	// PageTokenKey authenticates the API's page tokens.
	PageTokenKey = "page_token_key"
	// PagePreviewKey authenticates the previews of gateway pages.
	PagePreviewKey = "page_preview_key"
)

// instanceKeyLen is the length of the random keys that no other row holds.
const instanceKeyLen = 32

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

// InstanceKey returns the 32-byte key stored under name, a key that no other row holds, such as
// PageTokenKey. A missing one is made from crypto/rand, sealed and inserted in one transaction;
// when another replica inserted it first, that one is read, so that every replica holds the same
// key (docs/04-security.md, "Secrets at rest and in logs"). ctx must carry the system scope.
func InstanceKey(ctx context.Context, db *store.DB, sealer *secret.Sealer, name string) ([]byte, error) {
	for range 2 {
		v, err := InstanceSecret(ctx, db.Client(), sealer, name)
		if err != nil {
			return nil, err
		}
		if !v.IsZero() {
			return instanceKey(name, v)
		}
		key := make([]byte, instanceKeyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		err = store.WriteTx(ctx, db, func(tx *ent.Tx) error {
			sealed, err := store.Seal(ctx, tx, sealer, secretContext(name), secret.FromBytes(key))
			if err != nil {
				return err
			}
			return tx.InstanceSecret.Create().SetID(name).SetValueEnc(sealed).SetUpdatedAt(time.Now()).Exec(ctx)
		})
		if err == nil {
			return key, nil
		}
		if !ent.IsConstraintError(err) {
			return nil, err
		}
		// Another replica was first: read its key.
	}
	return nil, fmt.Errorf("settings: cannot make the key %s", name)
}

func instanceKey(name string, v secret.Value) ([]byte, error) {
	if v.Len() != instanceKeyLen {
		return nil, fmt.Errorf("settings: the key %s is %d bytes, want %d", name, v.Len(), instanceKeyLen)
	}
	return []byte(v.Reveal()), nil
}
