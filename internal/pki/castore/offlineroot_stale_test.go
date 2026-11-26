// SPDX-License-Identifier: Apache-2.0

package castore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// The plans of the offline root are made outside a write transaction, so another writer can come
// between a plan and its Apply; these tests put it there.

func passthrough(f []byte) ([]byte, error) { return f, nil }

// exportRoot takes the root offline with the test helper, which plans and applies in one transaction.
func exportRoot(t *testing.T, db *store.DB, s *secret.Sealer) {
	t.Helper()
	sys := storetest.SystemCtx(t)
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		_, err := castore.ExportRootOffline(sys, tx, s, rootPass, passthrough)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func countRows(t *testing.T, db *store.DB, kind cakey.Kind, status cakey.Status) int {
	t.Helper()
	n, err := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(kind), cakey.StatusEQ(status)).Count(storetest.SystemCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func applyIn(t *testing.T, db *store.DB, p *castore.Plan) ([]string, error) {
	t.Helper()
	sys := storetest.SystemCtx(t)
	var done []string
	err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		var err error
		done, err = p.Apply(sys, tx)
		return err
	})
	return done, err
}

// A root whose sealed key changed after the plan (a KEK rotation re-wrapped it) is not the one the
// plan opened: the export fails with ErrRotated before it writes a file or touches the row.
func TestRootExportPlanStale(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		plan, err := castore.PlanRootExport(sys, db.ReadClient().CAKey, s)
		if err != nil {
			t.Fatal(err)
		}
		root := rootRow(t, db)
		opened, err := s.Open(context.Background(), secret.Context{Table: "ca_keys", Column: "key_enc", RowID: root.ID}, *root.KeyEnc)
		if err != nil {
			t.Fatal(err)
		}
		resealed, err := s.Seal(context.Background(), secret.Context{Table: "ca_keys", Column: "key_enc", RowID: root.ID}, opened)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(resealed, *root.KeyEnc) {
			t.Fatal("sealing twice gave the same bytes")
		}
		if err := db.Client().CAKey.UpdateOneID(root.ID).SetKeyEnc(resealed).Exec(sys); err != nil {
			t.Fatal(err)
		}
		persisted := 0
		err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := plan.Apply(sys, tx, rootPass, func(f []byte) ([]byte, error) { persisted++; return f, nil })
			return err
		})
		if !errors.Is(err, castore.ErrRotated) {
			t.Fatalf("Apply of a stale plan = %v, want ErrRotated", err)
		}
		if persisted != 0 {
			t.Errorf("a stale plan wrote %d files", persisted)
		}
		if got := rootRow(t, db); got.KeyEnc == nil || !bytes.Equal(*got.KeyEnc, resealed) {
			t.Error("a stale plan changed key_enc")
		}
	})
}

// Of two exports planned together the second finds the root offline and writes no file.
func TestRootExportPlansTwice(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		a, err := castore.PlanRootExport(sys, db.ReadClient().CAKey, s)
		if err != nil {
			t.Fatal(err)
		}
		b, err := castore.PlanRootExport(sys, db.ReadClient().CAKey, s)
		if err != nil {
			t.Fatal(err)
		}
		files := 0
		apply := func(p *castore.RootExportPlan) error {
			return store.WriteTx(sys, db, func(tx *ent.Tx) error {
				_, err := p.Apply(sys, tx, rootPass, func(f []byte) ([]byte, error) { files++; return f, nil })
				return err
			})
		}
		if err := apply(a); err != nil {
			t.Fatal(err)
		}
		if err := apply(b); !errors.Is(err, castore.ErrRootOffline) {
			t.Fatalf("the second export = %v, want ErrRootOffline", err)
		}
		if files != 1 {
			t.Errorf("%d files written, want 1", files)
		}
		if !keyOffline(rootRow(t, db)) {
			t.Error("the root is online after the export")
		}
	})
}

// A root that is no longer active after the plan is not taken offline, and the lock that makes
// exports and requests take turns does not make it active again.
func TestRootExportPlanRootNotActive(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		plan, err := castore.PlanRootExport(sys, db.ReadClient().CAKey, s)
		if err != nil {
			t.Fatal(err)
		}
		root := rootRow(t, db)
		if err := db.Client().CAKey.UpdateOneID(root.ID).SetStatus(cakey.StatusRetired).Exec(sys); err != nil {
			t.Fatal(err)
		}
		files := 0
		err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
			_, err := plan.Apply(sys, tx, rootPass, func(f []byte) ([]byte, error) { files++; return f, nil })
			return err
		})
		if !errors.Is(err, castore.ErrRotated) {
			t.Fatalf("Apply for a root that is not active = %v, want ErrRotated", err)
		}
		if files != 0 {
			t.Errorf("%d files written, want 0", files)
		}
		got := rootRow(t, db)
		if got.Status != cakey.StatusRetired {
			t.Errorf("the root is %s again, want retired", got.Status)
		}
		if keyOffline(got) {
			t.Error("the root's key was taken out of the database")
		}
	})
}

// Of two requests planned while none waits, the first is written; the second is stale and writes
// nothing, so that exactly one request waits.
func TestSigningRequestPlansTwice(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		exportRoot(t, db, s)
		a, err := castore.PlanSigningRequest(sys, db.ReadClient().CAKey, s, t0)
		if err != nil {
			t.Fatal(err)
		}
		b, err := castore.PlanSigningRequest(sys, db.ReadClient().CAKey, s, t0)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a.CSR(), b.CSR()) {
			t.Fatal("two plans made the same request")
		}
		if _, err := applyIn(t, db, a); err != nil {
			t.Fatal(err)
		}
		if _, err := applyIn(t, db, b); !errors.Is(err, castore.ErrRotated) {
			t.Fatalf("the second request = %v, want ErrRotated", err)
		}
		if n := countRows(t, db, cakey.KindIntermediate, cakey.StatusNext); n != 1 {
			t.Fatalf("%d next intermediates, want 1", n)
		}
		// Planned again, it returns the request that waits.
		c, err := castore.PlanSigningRequest(sys, db.ReadClient().CAKey, s, t0)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c.CSR(), a.CSR()) {
			t.Error("a new plan did not return the request that waits")
		}
		if done, err := applyIn(t, db, c); err != nil || len(done) != 0 {
			t.Errorf("applying the waiting request: %v %v", done, err)
		}
	})
}

// A rotation planned with an offline root and no request waiting would make a request; one made
// first by the CLI leaves the rotation stale, and exactly one request waits.
func TestRotationVersusRequest(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		exportRoot(t, db, s)
		half := t0.Add(pki.IntermediateLifetime / 2)
		rot, err := castore.PlanRotation(sys, db.ReadClient().CAKey, s, half)
		if err != nil {
			t.Fatal(err)
		}
		req, err := castore.PlanSigningRequest(sys, db.ReadClient().CAKey, s, half)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := applyIn(t, db, req); err != nil {
			t.Fatal(err)
		}
		if _, err := applyIn(t, db, rot); !errors.Is(err, castore.ErrRotated) {
			t.Fatalf("the rotation = %v, want ErrRotated", err)
		}
		if n := countRows(t, db, cakey.KindIntermediate, cakey.StatusNext); n != 1 {
			t.Fatalf("%d next intermediates, want 1", n)
		}
	})
}

// A promotion planned for the signed next intermediate, which was retired meanwhile, is stale: the
// old intermediate stays active.
func TestPromotionPlanStale(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		e := goOffline(t, db, kek)
		cert, err := pki.SignIntermediate(e.root, e.csr, t0.Add(day))
		if err != nil {
			t.Fatal(err)
		}
		if err := e.importDER(t, cert.Raw, t0.Add(day)); err != nil {
			t.Fatal(err)
		}
		at := t0.Add(200 * day)
		plan, err := castore.PlanRotation(sys, db.ReadClient().CAKey, e.s, at)
		if err != nil {
			t.Fatal(err)
		}
		next := e.pending(t)
		if err := db.Client().CAKey.UpdateOneID(next.ID).SetStatus(cakey.StatusRetired).Exec(sys); err != nil {
			t.Fatal(err)
		}
		if _, err := applyIn(t, db, plan); !errors.Is(err, castore.ErrRotated) {
			t.Fatalf("the promotion = %v, want ErrRotated", err)
		}
		if n := countRows(t, db, cakey.KindIntermediate, cakey.StatusActive); n != 1 {
			t.Fatalf("%d active intermediates, want 1", n)
		}
		if got, err := db.ReadClient().CAKey.Get(sys, next.ID); err != nil || got.Status != cakey.StatusRetired {
			t.Fatalf("the retired key was activated: %v", err)
		}
	})
}

// A rotation planned while the root was online, and applied after `ca offline-root` took its key out
// of the database, is stale: it would make an intermediate with a key that is no longer there.
func TestRotationPlannedBeforeRootWentOffline(t *testing.T) {
	withCA(t, func(t *testing.T, db *store.DB, kek secret.KEK, _ *castore.CA) {
		sys := storetest.SystemCtx(t)
		s := sealer(t, kek)
		half := t0.Add(pki.IntermediateLifetime / 2)
		rot, err := castore.PlanRotation(sys, db.ReadClient().CAKey, s, half)
		if err != nil {
			t.Fatal(err)
		}
		exportRoot(t, db, s)
		if _, err := applyIn(t, db, rot); !errors.Is(err, castore.ErrRotated) {
			t.Fatalf("the rotation = %v, want ErrRotated", err)
		}
		if n := countRows(t, db, cakey.KindIntermediate, cakey.StatusActive); n != 1 {
			t.Fatalf("%d active intermediates, want 1", n)
		}
		if n := countRows(t, db, cakey.KindIntermediate, cakey.StatusRetired); n != 0 {
			t.Fatalf("%d retired intermediates, want 0", n)
		}
	})
}
