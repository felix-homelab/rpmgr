// SPDX-License-Identifier: Apache-2.0

package castore_test

import (
	"testing"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestRootOfflineMarker: ExportRootOffline names the KEK that sealed the key and the key's hash for
// the marker; a restore applies the marker to a database that still holds the key, once, and to
// none that holds another root; the residue is reported while the KEK still wraps a secret.
func TestRootOfflineMarker(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		before := rootRow(t, db)
		residue := func() string {
			t.Helper()
			k, err := castore.RootKeyResidue(sys, db)
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
		if residue() != "" {
			t.Error("an online root has no residue")
		}
		var exp castore.RootExport
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			exp, err = castore.ExportRootOffline(sys, tx, s, rootPass, func(f []byte) ([]byte, error) { return f, nil })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if exp.KEK != kek.Version() || exp.PublicKeyHash != pki.PublicKeyHash(before.PublicKey) {
			t.Errorf("export reports KEK %s and hash %s", exp.KEK, exp.PublicKeyHash)
		}
		if residue() != "" {
			t.Error("without an audit entry the residue is unknown, and nothing is claimed")
		}
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: castore.RootActionOffline,
				TargetType: "ca", TargetID: exp.PublicKeyHash, Result: audit.Success, Diff: castore.RootOfflineDiff(exp.KEK)})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if got := residue(); got != kek.Version() {
			t.Errorf("residue %q, want %s while the KEK wraps the other secrets", got, kek.Version())
		}
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := tx.SecretMeta.Delete().Where(secretmeta.KekVersion(kek.Version())).Exec(sys)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if residue() != "" {
			t.Error("no secret is wrapped by the KEK any more, so the residue is gone")
		}

		// The marker applied to a database that holds the key.
		apply := func(hash string) (held, found bool) {
			t.Helper()
			if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
				var err error
				held, found, err = castore.ApplyRootOffline(sys, tx, hash)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
		if held, found := apply(exp.PublicKeyHash); held || !found {
			t.Errorf("an offline root: held %v found %v", held, found)
		}
		if held, found := apply("00" + exp.PublicKeyHash[2:]); held || found {
			t.Errorf("another root: held %v found %v", held, found)
		}
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			return tx.CAKey.UpdateOneID(before.ID).SetKeyEnc(*before.KeyEnc).Exec(sys)
		}); err != nil {
			t.Fatal(err)
		}
		if held, found := apply(exp.PublicKeyHash); !held || !found || !keyOffline(rootRow(t, db)) {
			t.Errorf("a database that holds the key: held %v found %v", held, found)
		}
	})
}
