// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// signedBy signs a checkpoint of every chain that has entries after its last with the key of ca, as the job
// does; with the old CA's key after a replacement it is what whoever holds the leaked key can do.
func signedBy(t *testing.T, e env, signer pki.KeyPair, now time.Time) []audit.Checkpoint {
	t.Helper()
	var out []audit.Checkpoint
	if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
		var err error
		out, err = audit.WriteCheckpoints(sys(t), tx, signer, now, audit.Pending)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestVerifyChain_CompromisedRootCheckpoints: after a root was replaced as compromised, a checkpoint that the
// old root vouches for counts only below the seq of the entry that records the replacement in its chain.
// The signer chooses a checkpoint's time, so a time would bound nothing; whoever holds the leaked key can
// sign a checkpoint for a head the replacement did not see, and it is refused, as is one at the entry itself,
// and one in a chain with no such entry; a checkpoint of the new key verifies at any seq.
func TestVerifyChain_CompromisedRootCheckpoints(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		kek, err := secret.NewKEK(raw)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := secret.NewSealer(kek)
		ctx := sys(t)
		now := time.Now()
		if err := store.WriteTx(ctx, e.db, func(tx *ent.Tx) error {
			return castore.InitCA(ctx, tx, s, "rpmgr-teststor", now.Add(-time.Hour))
		}); err != nil {
			t.Fatal(err)
		}
		old, err := castore.LoadCA(ctx, e.db, s, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		leaked := old.AuditSigner() // what the attacker has
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
			record(t, e.db, login(e.b, "usr_2"))
		}
		if cps := signedBy(t, e, leaked, now); len(cps) != 2 {
			t.Fatalf("%d checkpoints before the replacement", len(cps))
		}

		// The replacement: new keys; the entry of the replacement in the chain of a only.
		plan, err := castore.PlanCompromisedRoot(ctx, e.db.ReadClient().CAKey, s, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteTx(ctx, e.db, func(tx *ent.Tx) error {
			if _, err := plan.Apply(ctx, tx); err != nil {
				return err
			}
			_, err := audit.AnchorCompromise(ctx, tx, e.a, plan.Replaced(), "test")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		fresh, err := castore.LoadCA(ctx, e.db, s, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		signers, inters, roots, err := castore.SignerCertificates(ctx, e.db, pki.PurposeAuditCheckpoint)
		if err != nil || len(roots) != 2 || !roots[0].Equal(plan.NewRoot()) {
			t.Fatalf("signer certificates: %d roots, %v", len(roots), err)
		}
		trust := audit.Trust{Root: roots[0], Roots: roots, Intermediates: inters, Signers: signers}

		// As the org's own admin verifies: the scope of the org, which sees no CA key through the store.
		verifyA := func() error { _, _, err := audit.VerifyChain(storetest.OrgCtx(t, e.a), e.db, e.a, trust); return err }
		refused := func(what string, err error) {
			t.Helper()
			if err == nil || !strings.Contains(err.Error(), audit.ErrCompromisedRoot.Error()) {
				t.Fatalf("%s: %v, want the refusal of a checkpoint under the replaced root", what, err)
			}
		}
		// What was signed before the replacement counts, in the chain that records it.
		if err := verifyA(); err != nil {
			t.Fatalf("chain a with its checkpoint from before: %v", err)
		}
		// The chain with no entry of the replacement has no cutoff, so nothing under the replaced root counts.
		_, _, err = audit.VerifyChain(ctx, e.db, e.b, trust)
		refused("chain b, with no entry of the replacement", err)

		// The leaked key signs a checkpoint of the entry that records the replacement, then, later, one of a
		// head the replacement never saw: both are refused; a checkpoint of the new key verifies at any seq.
		at := signedBy(t, e, leaked, now.Add(time.Minute))
		if c := chainOf(at, e.a); c == nil || c.Seq != 4 {
			t.Fatalf("the checkpoint under the leaked key: %+v", at)
		}
		refused("a checkpoint at the replacement's entry under the leaked key", verifyA())
		if err := store.WriteTx(ctx, e.db, func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, "DELETE FROM audit_checkpoints WHERE id = $1", chainOf(at, e.a).ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if cps := signedBy(t, e, fresh.AuditSigner(), now.Add(2*time.Minute)); chainOf(cps, e.a) == nil || chainOf(cps, e.a).Seq != 4 {
			t.Fatalf("the checkpoint of the new key: %+v", cps)
		}
		if err := verifyA(); err != nil {
			t.Fatalf("chain a with the new key's checkpoint at the replacement's entry: %v", err)
		}
		// An export leaves out the checkpoints of the replaced root once the new key anchors the replacement, so
		// that it verifies with the new pin alone; the chain it carries is still checked entry by entry.
		var lines []string
		if err := audit.Export(ctx, e.db, e.a, trust, now, func(l []byte) error { lines = append(lines, string(l)); return nil }); err != nil {
			t.Fatal(err)
		}
		exported := strings.Join(lines, "\n") + "\n"
		if strings.Contains(exported, pki.KeyID(leaked.Cert)) {
			t.Fatal("the export holds a checkpoint of the replaced key")
		}
		if res, err := audit.VerifyExport(strings.NewReader(exported), pki.RootPin(plan.NewRoot())); err != nil || res.Entries == 0 {
			t.Fatalf("an export after the replacement with the new pin: %+v, %v", res, err)
		}
		if _, err := audit.VerifyExport(strings.NewReader(exported), pki.RootPin(old.Root())); err == nil {
			t.Fatal("an export after the replacement verified with the old pin")
		}
		record(t, e.db, login(e.a, "usr_1"))
		if cps := signedBy(t, e, leaked, now.Add(3*time.Minute)); chainOf(cps, e.a) == nil || chainOf(cps, e.a).Seq != 5 {
			t.Fatalf("the forged checkpoint: %+v", cps)
		}
		refused("a checkpoint after the replacement under the leaked key", verifyA())
	})
}

// freshCA initialises a CA for the audit tests and returns its sealer and the CA.
func freshCA(t *testing.T, e env, age time.Duration) (*secret.Sealer, *castore.CA) {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	kek, err := secret.NewKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := secret.NewSealer(kek)
	if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
		return castore.InitCA(sys(t), tx, s, "rpmgr-teststor", time.Now().Add(-age))
	}); err != nil {
		t.Fatal(err)
	}
	ca, err := castore.LoadCA(sys(t), e.db, s, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return s, ca
}

// replace replaces the roots as the command does, recording the replacement in the chain of each org.
func replace(t *testing.T, e env, s *secret.Sealer, now time.Time, orgs ...string) *castore.CompromisePlan {
	t.Helper()
	plan, err := castore.PlanCompromisedRoot(sys(t), e.db.ReadClient().CAKey, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
		if _, err := plan.Apply(sys(t), tx); err != nil {
			return err
		}
		for _, org := range orgs {
			if _, err := audit.AnchorCompromise(sys(t), tx, org, plan.Replaced(), "test"); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return plan
}

func trustOf(t *testing.T, e env) audit.Trust {
	t.Helper()
	signers, inters, roots, err := castore.SignerCertificates(sys(t), e.db, pki.PurposeAuditCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	return audit.Trust{Root: roots[0], Roots: roots, Intermediates: inters, Signers: signers}
}

// A root that an earlier rotation retired is ended by a later replacement too, and gets its cutoff: after
// R1 to R2, the drop of R1 and the replacement of R2, a checkpoint under R1 from before still verifies, one
// under the leaked R1 key after the replacement is refused, and nothing is left retired under a leaked key.
func TestVerifyChain_RetiredRootCompromisedToo(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		ctx := sys(t)
		now := time.Now()
		s, ca1 := freshCA(t, e, 100*24*time.Hour)
		leaked1 := ca1.AuditSigner()
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		signedBy(t, e, leaked1, now.Add(-time.Hour))
		rp, err := castore.PlanNewRoot(ctx, e.db.ReadClient().CAKey, s, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteTx(ctx, e.db, func(tx *ent.Tx) error { _, err := rp.Apply(ctx, tx); return err }); err != nil {
			t.Fatal(err)
		}
		dp, err := castore.PlanDropRoot(ctx, e.db.ReadClient().CAKey, now.Add(time.Minute), castore.DropOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteTx(ctx, e.db, func(tx *ent.Tx) error { _, err := dp.Apply(ctx, tx); return err }); err != nil {
			t.Fatal(err)
		}
		plan := replace(t, e, s, now.Add(2*time.Minute), e.a)
		if len(plan.Replaced()) != 2 {
			t.Fatalf("the replacement ended %d roots, want the retired R1 and R2", len(plan.Replaced()))
		}
		if n := e.db.Client().CAKey.Query().CountX(ctx); n != 12 {
			t.Fatalf("%d CA keys", n)
		}
		trust := trustOf(t, e)
		verify := func() error {
			_, _, err := audit.VerifyChain(storetest.OrgCtx(t, e.a), e.db, e.a, trust)
			return err
		}
		if err := verify(); err != nil {
			t.Fatalf("the checkpoint under the retired root, from before: %v", err)
		}
		record(t, e.db, login(e.a, "usr_1"))
		signedBy(t, e, leaked1, now.Add(3*time.Minute))
		if err := verify(); err == nil || !strings.Contains(err.Error(), audit.ErrCompromisedRoot.Error()) {
			t.Fatalf("a checkpoint under the leaked retired root after the replacement: %v", err)
		}
	})
}

// The cutoff outlives the audit entry: retention removes the entry that records the replacement, and the
// checkpoints that count are still told from those that do not.
func TestVerifyChain_CompromiseCutoffSurvivesPrune(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		ctx := sys(t)
		now := time.Now()
		s, ca1 := freshCA(t, e, time.Hour)
		leaked := ca1.AuditSigner()
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		signedBy(t, e, leaked, now)
		plan := replace(t, e, s, now, e.a)
		fresh, err := castore.LoadCA(ctx, e.db, s, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		signedBy(t, e, fresh.AuditSigner(), now.Add(time.Minute)) // seq 4
		record(t, e.db, login(e.a, "usr_1"))
		signedBy(t, e, fresh.AuditSigner(), now.Add(2*time.Minute)) // seq 5
		trust := trustOf(t, e)
		verify := func() error {
			_, _, err := audit.VerifyChain(storetest.OrgCtx(t, e.a), e.db, e.a, trust)
			return err
		}
		if err := verify(); err != nil {
			t.Fatal(err)
		}
		var pruned int64
		if err := store.WriteTx(ctx, e.db, func(tx *ent.Tx) (err error) {
			pruned, err = audit.Prune(ctx, tx, e.a, time.Now().Add(time.Hour))
			return err
		}); err != nil || pruned < 4 {
			t.Fatalf("prune removed up to %d: %v", pruned, err)
		}
		if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action(audit.ActionRootCompromised)).CountX(ctx); n != 0 {
			t.Fatalf("the entry of the replacement is still there (%d)", n)
		}
		if err := store.ReadTx(ctx, e.db, func(tx *ent.Tx, _ store.Revision) error {
			ct, err := trust.WithCompromises(ctx, tx)
			if err != nil || len(ct.Compromised) != 1 || ct.Compromised[0].Cutoff[e.a] != 4 || pki.PublicKeyHash(ct.Compromised[0].Root.RawSubjectPublicKeyInfo) != plan.Replaced()[0] {
				t.Fatalf("cutoffs after the prune: %+v, %v", ct.Compromised, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := verify(); err != nil {
			t.Fatalf("after retention removed the entry of the replacement: %v", err)
		}
		record(t, e.db, login(e.a, "usr_1"))
		signedBy(t, e, leaked, now.Add(3*time.Minute))
		if err := verify(); err == nil || !strings.Contains(err.Error(), audit.ErrCompromisedRoot.Error()) {
			t.Fatalf("a forged checkpoint after the entry was pruned: %v", err)
		}
	})
}
