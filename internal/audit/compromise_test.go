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
			_, err := audit.Append(ctx, tx, audit.Entry{OrgID: e.a, ActorType: audit.ActorSystem, ActorID: "local-cli", Action: audit.ActionRootCompromised,
				TargetType: "ca", Result: audit.Success, Diff: audit.RootsDiff(plan.Replaced())})
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
		// An export checked offline against the new pin cannot reach the old root, so the checkpoint it holds
		// from before the replacement fails there; the documentation says to verify older history with an
		// export from before and the old pin.
		var lines []string
		if err := audit.Export(ctx, e.db, e.a, trust, now, func(l []byte) error { lines = append(lines, string(l)); return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := audit.VerifyExport(strings.NewReader(strings.Join(lines, "\n")+"\n"), pki.RootPin(plan.NewRoot())); err == nil {
			t.Fatal("an offline verification against the new pin accepted a checkpoint of the replaced root")
		}
		record(t, e.db, login(e.a, "usr_1"))
		if cps := signedBy(t, e, leaked, now.Add(3*time.Minute)); chainOf(cps, e.a) == nil || chainOf(cps, e.a).Seq != 5 {
			t.Fatalf("the forged checkpoint: %+v", cps)
		}
		refused("a checkpoint after the replacement under the leaked key", verifyA())
	})
}
