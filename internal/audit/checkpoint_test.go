// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// withCA is setup with a CA, whose audit-checkpoint key signs, and the trust that verifies it.
func withCA(t *testing.T, f func(t *testing.T, e env, ca *pki.CA, trust audit.Trust)) {
	setup(t, func(t *testing.T, e env) {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		kek, err := secret.NewKEK(raw)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := secret.NewSealer(kek)
		ctx := sys(t)
		if err := store.WriteTx(ctx, e.db, func(tx *ent.Tx) error {
			return pki.InitCA(ctx, tx, s, "rpmgr-teststor", time.Now().Add(-time.Hour))
		}); err != nil {
			t.Fatal(err)
		}
		ca, err := pki.LoadCA(ctx, e.db, s, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		signers, inters, root, err := pki.SignerCertificates(ctx, e.db, pki.PurposeAuditCheckpoint)
		if err != nil || len(signers) != 1 {
			t.Fatalf("signer certificates: %d %v", len(signers), err)
		}
		f(t, e, ca, audit.Trust{Root: root, Intermediates: inters, Signers: signers})
	})
}

func checkpoint(t *testing.T, e env, ca *pki.CA, now time.Time, due func(audit.Head, *audit.Checkpoint) bool) []audit.Checkpoint {
	t.Helper()
	var out []audit.Checkpoint
	if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
		var err error
		out, err = audit.WriteCheckpoints(sys(t), tx, ca.AuditSigner(), now, due)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func chainOf(cps []audit.Checkpoint, org string) *audit.Checkpoint {
	for i := range cps {
		if cps[i].OrgID == org {
			return &cps[i]
		}
	}
	return nil
}

// TestDue: a chain with new entries is due an hour after its last checkpoint, or after a thousand
// entries; one without new entries never is, and a chain without a checkpoint is at once.
func TestDue(t *testing.T) {
	now := time.Now()
	last := &audit.Checkpoint{Seq: 4, Time: now}
	for _, c := range []struct {
		seq  int64
		at   time.Time
		last *audit.Checkpoint
		want bool
	}{
		{4, now.Add(2 * time.Hour), last, false},
		{5, now.Add(time.Hour - time.Second), last, false},
		{5, now.Add(time.Hour), last, true},
		{4 + audit.CheckpointEntries - 1, now, last, false},
		{4 + audit.CheckpointEntries, now, last, true},
		{1, now, nil, true},
	} {
		if got := audit.Due(c.at)(audit.Head{Seq: c.seq}, c.last); got != c.want {
			t.Errorf("seq %d at %s after %+v: %v", c.seq, c.at.Sub(now), c.last, got)
		}
	}
	if audit.Pending(audit.Head{Seq: 4}, last) || !audit.Pending(audit.Head{Seq: 5}, last) {
		t.Error("Pending")
	}
}

// TestCheckpoints: due chains get a signed checkpoint of their head, which verifies with the CA's
// certificates, once per hour or thousand entries.
func TestCheckpoints(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *pki.CA, trust audit.Trust) {
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		now := time.Now()
		first := checkpoint(t, e, ca, now, audit.Due(now))
		cp := chainOf(first, e.a)
		if cp == nil || cp.Seq != 3 || cp.KeyID != pki.KeyID(ca.AuditSigner().Cert) || chainOf(first, e.b) != nil {
			t.Fatalf("first checkpoints: %+v", first)
		}
		if again := checkpoint(t, e, ca, now, audit.Due(now)); len(again) != 0 {
			t.Fatalf("checkpoints without new entries: %+v", again)
		}
		record(t, e.db, login(e.a, "usr_1"))
		if early := checkpoint(t, e, ca, now.Add(time.Minute), audit.Due(now.Add(time.Minute))); len(early) != 0 {
			t.Fatalf("checkpoints within the hour: %+v", early)
		}
		if late := checkpoint(t, e, ca, now.Add(time.Hour), audit.Due(now.Add(time.Hour))); chainOf(late, e.a) == nil || chainOf(late, e.a).Seq != 4 {
			t.Fatalf("checkpoints after the hour: %+v", late)
		}
		record(t, e.db, login(e.a, "usr_1"))
		head, last, err := audit.VerifyChain(sys(t), e.db, e.a, trust)
		if err != nil || head.Seq != 5 || last == nil || last.Seq != 4 {
			t.Fatalf("VerifyChain: %+v %+v %v", head, last, err)
		}
		if _, _, err := audit.VerifyChain(storetest.OrgCtx(t, e.b), e.db, e.a, trust); !errors.Is(err, audit.ErrOutsideScope) {
			t.Fatalf("another org's chain: %v", err)
		}
	})
}

// TestVerifyChain_Checkpoints: a chain of five entries with checkpoints at 3 and 4 verifies from
// the checkpoint before its first entry left once a prefix was removed, but not without one; a
// forged signature, a chain rewritten under a checkpoint and a cut tail a checkpoint covers are
// detected.
func TestVerifyChain_Checkpoints(t *testing.T) {
	cases := []struct {
		name    string
		tamper  func(t *testing.T, e env, x exec)
		wantSeq int64 // 0: the chain verifies
	}{
		{"checkpointed prefix removed", func(t *testing.T, e env, x exec) {
			x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq <= 3", e.a)
		}, 0},
		{"prefix removed without a checkpoint", func(t *testing.T, e env, x exec) {
			x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq <= 2", e.a)
		}, 2},
		{"forged signature", func(t *testing.T, e env, x exec) {
			x(t, "UPDATE audit_checkpoints SET signature = $1 WHERE org_id = $2 AND seq = 4", []byte("forged"), e.a)
		}, 4},
		{"chain rewritten with hashes and head", func(t *testing.T, e env, x exec) {
			e4 := entryAt(t, e, e.a, 4)
			e4.Action = "session.logout"
			h4 := audit.ChainHash(e4.PrevHash, e4)
			e5 := entryAt(t, e, e.a, 5)
			e5.PrevHash = h4
			h5 := audit.ChainHash(h4, e5)
			x(t, "UPDATE audit_log SET action = $1, hash = $2 WHERE org_id = $3 AND seq = 4", e4.Action, h4, e.a)
			x(t, "UPDATE audit_log SET prev_hash = $1, hash = $2 WHERE org_id = $3 AND seq = 5", h4, h5, e.a)
			x(t, "UPDATE audit_heads SET hash = $1 WHERE chain = $2", h5, e.a)
		}, 4},
		{"cut tail a checkpoint covers", func(t *testing.T, e env, x exec) {
			x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq >= 4", e.a)
			x(t, "UPDATE audit_heads SET seq = 3, hash = (SELECT hash FROM audit_log WHERE org_id = $1 AND seq = 3) WHERE chain = $1", e.a)
		}, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCA(t, func(t *testing.T, e env, ca *pki.CA, trust audit.Trust) {
				now := time.Now()
				for range 3 {
					record(t, e.db, login(e.a, "usr_1"))
				}
				checkpoint(t, e, ca, now, audit.Pending)
				record(t, e.db, login(e.a, "usr_1"))
				checkpoint(t, e, ca, now.Add(time.Hour), audit.Pending)
				record(t, e.db, login(e.a, "usr_1"))
				tc.tamper(t, e, func(t *testing.T, q string, args ...any) {
					t.Helper()
					if _, err := e.db.Writer.ExecContext(context.Background(), q, args...); err != nil {
						t.Fatal(err)
					}
				})
				head, _, err := audit.VerifyChain(sys(t), e.db, e.a, trust)
				var ce *audit.ChainError
				switch {
				case tc.wantSeq == 0 && (err != nil || head.Seq != 5):
					t.Fatalf("VerifyChain: %+v %v, want head 5", head, err)
				case tc.wantSeq != 0 && (!errors.As(err, &ce) || ce.Seq != tc.wantSeq):
					t.Fatalf("VerifyChain: %v, want a break at %d", err, tc.wantSeq)
				}
			})
		})
	}
}

// TestCheckpointLog: the local log keeps every checkpoint with its signer's certificate, so each
// verifies with the root and the intermediates alone; an altered line does not.
func TestCheckpointLog(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *pki.CA, trust audit.Trust) {
		record(t, e.db, login(e.a, "usr_1"))
		record(t, e.db, login(e.b, "usr_2"))
		l := &audit.CheckpointLog{Path: filepath.Join(t.TempDir(), "audit-checkpoints.log")}
		if err := l.Append(checkpoint(t, e, ca, time.Now(), audit.Pending)); err != nil {
			t.Fatal(err)
		}
		record(t, e.db, login(e.a, "usr_1"))
		if err := l.Append(checkpoint(t, e, ca, time.Now(), audit.Pending)); err != nil {
			t.Fatal(err)
		}
		cps, err := audit.ReadCheckpointLog(l.Path)
		if err != nil || len(cps) < 3 {
			t.Fatalf("the log: %d checkpoints, %v", len(cps), err)
		}
		bare := audit.Trust{Root: trust.Root, Intermediates: trust.Intermediates}
		for _, c := range cps {
			if err := bare.VerifySignature(c); err != nil {
				t.Fatalf("checkpoint %s/%d: %v", c.Chain(), c.Seq, err)
			}
		}
		altered := cps[len(cps)-1]
		altered.Seq++
		if err := bare.VerifySignature(altered); err == nil {
			t.Fatal("an altered checkpoint verifies")
		}
		altered = cps[len(cps)-1]
		altered.Certificate = trust.Root.Raw
		if err := bare.VerifySignature(altered); err == nil {
			t.Fatal("a checkpoint with another certificate verifies")
		}
	})
}

// TestPrune: retention removes a chain's entries only up to its newest checkpoint older than the
// cutoff, with the checkpoints before it, and the chain still verifies from that checkpoint; a
// cutoff before every checkpointed entry removes nothing; other chains are untouched.
func TestPrune(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *pki.CA, trust audit.Trust) {
		now := time.Now()
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		record(t, e.db, login(e.b, "usr_2"))
		checkpoint(t, e, ca, now, audit.Pending)
		for range 2 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		checkpoint(t, e, ca, now.Add(time.Hour), audit.Pending)
		record(t, e.db, login(e.a, "usr_1"))
		prune := func(org string, cutoff time.Time) int64 {
			t.Helper()
			var seq int64
			if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
				var err error
				seq, err = audit.Prune(sys(t), tx, org, cutoff)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return seq
		}
		if seq := prune(e.a, now.Add(-time.Hour)); seq != 0 {
			t.Fatalf("a cutoff before every entry removed up to %d", seq)
		}
		if seq := prune(e.a, time.Now().Add(time.Hour)); seq != 5 {
			t.Fatalf("pruned up to %d, want the newest checkpoint, 5", seq)
		}
		head, last, err := audit.VerifyChain(sys(t), e.db, e.a, trust)
		if err != nil || head.Seq != 6 || last == nil || last.Seq != 5 {
			t.Fatalf("after retention: %+v %+v %v", head, last, err)
		}
		if n := e.db.Client().AuditEntry.Query().CountX(sys(t)); n != 2 {
			t.Fatalf("%d entries left, want entry 6 of org A and org B's", n)
		}
		if n := e.db.Client().AuditCheckpoint.Query().CountX(sys(t)); n != 2 {
			t.Fatalf("%d checkpoints left, want org A's at 5 and org B's", n)
		}
		if seq := prune(e.a, time.Now().Add(time.Hour)); seq != 0 {
			t.Fatalf("pruned again up to %d", seq)
		}
		if _, _, err := audit.VerifyChain(sys(t), e.db, e.b, trust); err != nil {
			t.Fatalf("org B's chain: %v", err)
		}
	})
}

// TestUncovered: the oldest entry no checkpoint covers is found across chains, and none once
// every chain is checkpointed.
func TestUncovered(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *pki.CA, trust audit.Trust) {
		if _, ok, err := audit.Uncovered(sys(t), e.db); err != nil || ok {
			t.Fatalf("an empty log: %v %v", ok, err)
		}
		first := record(t, e.db, login(e.a, "usr_1"))
		record(t, e.db, login(e.b, "usr_2"))
		oldest, ok, err := audit.Uncovered(sys(t), e.db)
		if err != nil || !ok || !oldest.Equal(first.Time) {
			t.Fatalf("uncovered: %v %v %v, want %v", oldest, ok, err, first.Time)
		}
		checkpoint(t, e, ca, time.Now(), audit.Pending)
		if _, ok, err := audit.Uncovered(sys(t), e.db); err != nil || ok {
			t.Fatalf("after checkpoints: %v %v", ok, err)
		}
		later := record(t, e.db, login(e.b, "usr_2"))
		if oldest, ok, _ := audit.Uncovered(sys(t), e.db); !ok || !oldest.Equal(later.Time) {
			t.Fatalf("a new entry: %v %v, want %v", oldest, ok, later.Time)
		}
	})
}
