// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"context"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
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

// ExportRootOffline plans and applies the export in tx, for tests that have no key service to wait
// for. The server code plans before its transaction.
func ExportRootOffline(ctx context.Context, tx *ent.Tx, s *secret.Sealer, passphrase string,
	persist func(file []byte) (readBack []byte, err error)) (RootExport, error) {
	p, err := PlanRootExport(ctx, tx.CAKey, s)
	if err != nil {
		return RootExport{}, err
	}
	return p.Apply(ctx, tx, passphrase, persist)
}

// RequestIntermediateSigning plans and applies a request in tx, for tests that have no key service
// to wait for, and returns the request (PEM).
func RequestIntermediateSigning(ctx context.Context, tx *ent.Tx, s *secret.Sealer, now time.Time) ([]byte, error) {
	p, err := PlanSigningRequest(ctx, tx.CAKey, s, now)
	if err != nil {
		return nil, err
	}
	if _, err := p.Apply(ctx, tx); err != nil {
		return nil, err
	}
	return p.CSR(), nil
}
