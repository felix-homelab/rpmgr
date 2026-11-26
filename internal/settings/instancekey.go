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

// The keys that no other row holds, sealed in instance_secrets.
const (
	// PageTokenKey authenticates the API's page tokens.
	PageTokenKey = "page_token_key"
	// PagePreviewKey authenticates the previews of gateway pages.
	PagePreviewKey = "page_preview_key"
)

// instanceKeyLen is the length of the random keys that no other row holds.
const instanceKeyLen = 32

// InstanceKey returns the 32-byte key stored under name, a key that no other row holds, such as
// PageTokenKey. A missing one is made from crypto/rand, sealed and inserted in one transaction;
// when another replica inserted it first, that one is read, so that every replica holds the same
// key (docs/04-security.md, "Secrets at rest and in logs"). ctx must carry the system scope.
func InstanceKey(ctx context.Context, db *store.DB, sealer *secret.Sealer, name string) ([]byte, error) {
	if name != PageTokenKey && name != PagePreviewKey {
		return nil, fmt.Errorf("settings: %q is not a key that is made here", name)
	}
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
		sealed, err := sealer.Seal(ctx, secretContext(name), secret.FromBytes(key))
		if err != nil {
			return nil, err
		}
		err = store.WriteTx(ctx, db, func(tx *ent.Tx) error {
			if err := store.RecordSealed(ctx, tx, secretContext(name), sealed); err != nil {
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
