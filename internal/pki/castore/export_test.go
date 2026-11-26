// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// RootKeyForTest opens the online root's key, to know what must never be stored once it is offline.
func RootKeyForTest(ctx context.Context, db *store.DB, s *secret.Sealer) (pki.KeyPair, error) {
	r, err := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return pki.KeyPair{}, err
	}
	return openKey(ctx, s, r)
}
