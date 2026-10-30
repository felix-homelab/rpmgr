// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/sinkverify"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The AWS documentation's example secret key, which the repository's secret scan allows.
const awsKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" //nolint:gosec // G101: the AWS documentation's example

// rawExec runs SQL behind the audit package's back, as someone with write access to the database.
func rawExec(t *testing.T, e env) exec {
	return func(t *testing.T, q string, args ...any) {
		t.Helper()
		if _, err := e.db.Writer.ExecContext(context.Background(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCheckHeld: checkpoints held outside the database must name the stored hash of the entry at
// their seq; one beyond the head means entries were cut; one older than the first entry the
// retention left is not compared; the lowest seq that does not fit is the one reported, however
// the input is ordered and however many there are.
func TestCheckHeld(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		const n = 450
		for range n {
			record(t, e.db, login(e.a, "usr_1"))
		}
		held := func(seqs ...int64) []audit.Checkpoint {
			var out []audit.Checkpoint
			for _, s := range seqs {
				out = append(out, audit.Checkpoint{OrgID: e.a, Seq: s, HeadHash: entryAt(t, e, e.a, s).Hash})
			}
			return out
		}
		compared, err := audit.CheckHeld(sys(t), e.db, e.a, held(450, 3, 1, 200, 201))
		if err != nil || compared != 5 {
			t.Fatalf("matching checkpoints: %d %v", compared, err)
		}
		var all []int64
		for s := int64(1); s <= n; s++ {
			all = append(all, s)
		}
		if compared, err = audit.CheckHeld(sys(t), e.db, e.a, held(all...)); err != nil || compared != n {
			t.Fatalf("every seq, in batches: %d %v", compared, err)
		}
		if compared, err = audit.CheckHeld(sys(t), e.db, e.a, nil); err != nil || compared != 0 {
			t.Fatalf("nothing held: %d %v", compared, err)
		}

		var ce *audit.ChainError
		bad := held(10, 300, 301)
		bad[1].HeadHash = bytes.Repeat([]byte{1}, 32)
		bad[2].HeadHash = bytes.Repeat([]byte{2}, 32)
		if _, err = audit.CheckHeld(sys(t), e.db, e.a, []audit.Checkpoint{bad[2], bad[1], bad[0]}); !errors.As(err, &ce) || ce.Seq != 300 ||
			!strings.Contains(ce.Problem, "rewritten") || ce.Chain != e.a {
			t.Fatalf("a rewritten chain: %v", err)
		}
		beyond := []audit.Checkpoint{{OrgID: e.a, Seq: n + 1, HeadHash: bytes.Repeat([]byte{3}, 32)}}
		if _, err = audit.CheckHeld(sys(t), e.db, e.a, beyond); !errors.As(err, &ce) || ce.Seq != n+1 || !strings.Contains(ce.Problem, "removed") {
			t.Fatalf("a checkpoint beyond the head: %v", err)
		}
		// Another chain's entries are not this chain's.
		if _, err = audit.CheckHeld(sys(t), e.db, e.b, held(1)); !errors.As(err, &ce) || ce.Seq != 1 {
			t.Fatalf("a chain that is empty: %v", err)
		}
		if _, err = audit.CheckHeld(sys(t), e.db, "", held(1)); !errors.As(err, &ce) {
			t.Fatalf("the instance chain, which is empty: %v", err)
		}

		// The retention removed a prefix: what lies before the first entry is not compared.
		old := held(50, 150)
		rawExec(t, e)(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq <= 100", e.a)
		compared, err = audit.CheckHeld(sys(t), e.db, e.a, []audit.Checkpoint{{OrgID: e.a, Seq: 50, HeadHash: []byte("anything")}, old[1]})
		if err != nil || compared != 1 {
			t.Fatalf("after a retention cut: %d %v", compared, err)
		}
	})
}

// sinkWorld is a chain with signed checkpoints shipped to an object-storage sink.
type sinkWorld struct {
	e      env
	ca     *castore.CA
	trust  audit.Trust
	srv    *objstoretest.Server
	runner *auditsink.Runner
	row    *ent.AuditSink
	x      exec
}

// newSinkWorld records three entries, signs a checkpoint at 3, records a fourth, signs one at 4,
// records a fifth, and ships everything to a sink that gets entries.
func newSinkWorld(t *testing.T, e env, ca *castore.CA, trust audit.Trust) *sinkWorld {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	kek, err := secret.NewKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := secret.NewSealer(kek)
	w := &sinkWorld{e: e, ca: ca, trust: trust, srv: objstoretest.New(t), x: rawExec(t, e)}
	id := ids.New("ask")
	sealed, err := sealer.Seal(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: id}, secret.New(awsKey))
	if err != nil {
		t.Fatal(err)
	}
	set := auditsink.S3Settings{Endpoint: w.srv.URL, Region: objstoretest.Region, Bucket: objstoretest.Bucket, AccessKeyID: objstoretest.AccessKeyID}
	w.row = e.db.Client().AuditSink.Create().SetID(id).SetKind("s3").SetName("vault").SetSettings(set.Map()).SetSecretEnc(sealed).SetEntries(true).SaveX(sys(t))
	w.runner = auditsink.NewRunner(auditsink.Options{DB: e.db, Sealer: sealer, Now: time.Now, Logger: slog.New(slog.DiscardHandler)})
	now := time.Now()
	for range 3 {
		record(t, e.db, login(e.a, "usr_1"))
	}
	checkpoint(t, e, ca, now, audit.Pending)
	record(t, e.db, login(e.a, "usr_1"))
	checkpoint(t, e, ca, now.Add(time.Hour), audit.Pending)
	record(t, e.db, login(e.a, "usr_1"))
	if err := w.runner.Pass(sys(t), func(*ent.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n := len(w.srv.Keys()); n != 2+5 {
		t.Fatalf("%d objects after shipping: %v", n, w.srv.Keys())
	}
	return w
}

func (w *sinkWorld) verify(t *testing.T, prev *sinkverify.Verification) (*sinkverify.Verification, error) {
	t.Helper()
	row := *w.row
	row.Verification = prev
	return w.runner.VerifyS3(sys(t), &row, w.trust)
}

func (w *sinkWorld) chain(t *testing.T, v *sinkverify.Verification) sinkverify.Chain {
	t.Helper()
	if v == nil || len(v.Chains) != 1 || v.Chains[0].Chain != w.e.a {
		t.Fatalf("verification %+v", v)
	}
	return v.Chains[0]
}

// objectGets counts the reads of objects, not of listings.
func objectGets(srv *objstoretest.Server) int {
	n := 0
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r, "GET audit/") {
			n++
		}
	}
	return n
}

func (w *sinkWorld) cpKey(seq int) string {
	return "audit/" + w.e.a + "/checkpoints/" + strings.Repeat("0", 19) + string(rune('0'+seq))
}

func (w *sinkWorld) entryKey(seq int) string {
	return "audit/" + w.e.a + "/entries/" + strings.Repeat("0", 19) + string(rune('0'+seq))
}

// TestAuditSink_RewriteDetectedAgainstSink (#656; docs/04-security.md, "Audit log"): someone with
// write access to the database rewrites an entry that a checkpoint covers, recomputes the hashes
// after it, fixes the head and deletes the database's checkpoints. The chain verifies in the
// database after that, and only the checkpoint the object-storage sink holds shows the rewrite; the
// sink's objects cannot be overwritten, so the sink still holds the original.
func TestAuditSink_RewriteDetectedAgainstSink(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		w := newSinkWorld(t, e, ca, trust)
		v, err := w.verify(t, nil)
		c := w.chain(t, v)
		if err != nil || !c.Intact() || c.CheckpointSeq != 4 || c.Checked != 2 {
			t.Fatalf("an untouched chain: %+v %v", c, err)
		}

		e4 := entryAt(t, e, e.a, 4)
		e4.Action = "session.logout"
		h4 := audit.ChainHash(e4.PrevHash, e4)
		e5 := entryAt(t, e, e.a, 5)
		e5.PrevHash = h4
		h5 := audit.ChainHash(h4, e5)
		w.x(t, "UPDATE audit_log SET action = $1, hash = $2 WHERE org_id = $3 AND seq = 4", e4.Action, h4, e.a)
		w.x(t, "UPDATE audit_log SET prev_hash = $1, hash = $2 WHERE org_id = $3 AND seq = 5", h4, h5, e.a)
		w.x(t, "UPDATE audit_heads SET hash = $1 WHERE chain = $2", h5, e.a)
		w.x(t, "DELETE FROM audit_checkpoints WHERE org_id = $1", e.a)
		if head, _, err := audit.VerifyChain(sys(t), e.db, e.a, trust); err != nil || head.Seq != 5 {
			t.Fatalf("the rewritten chain does not verify in the database, so the sink is not needed: %+v %v", head, err)
		}

		// The sink's own objects cannot be overwritten: a resend of the rewritten entry finds other
		// bytes under its key, and the original stays.
		before, _ := w.srv.Get(w.entryKey(4))
		w.x(t, "DELETE FROM audit_sink_cursors")
		if err := w.runner.Pass(sys(t), func(*ent.Tx) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if after, _ := w.srv.Get(w.entryKey(4)); !bytes.Equal(before, after) {
			t.Fatal("the sink's object was overwritten")
		}
		if got := e.db.Client().AuditSink.GetX(sys(t), w.row.ID).LastError; !strings.Contains(got, "other bytes") {
			t.Fatalf("a resend of a rewritten entry: %q", got)
		}

		v, err = w.verify(t, nil)
		c = w.chain(t, v)
		if err != nil || c.Intact() || !strings.Contains(c.Problem, "seq 4") || !strings.Contains(c.Problem, "rewritten") ||
			c.CheckpointSeq != 3 || c.Checked != 1 {
			t.Fatalf("a chain rewritten under a checkpoint of the sink: %+v %v", c, err)
		}
		// The next verification, which starts from the last one that verified, finds it again.
		prev := &sinkverify.Verification{Chains: []sinkverify.Chain{{Chain: e.a, CheckpointSeq: 3}}}
		if v, err = w.verify(t, prev); err != nil || w.chain(t, v).Intact() {
			t.Fatalf("a later verification: %+v %v", v, err)
		}
	})
}

// TestVerifyS3 (#656): what a read-back of the sink reports for a sink that lost, altered or was
// handed something else, for a database that lost entries, for a sink that is not there, and which
// checkpoints a later read-back reads.
func TestVerifyS3(t *testing.T) {
	cases := []struct {
		name      string
		tamper    func(t *testing.T, w *sinkWorld)
		gap       string
		problem   string
		wantSeq   int64
		wantCheck int
	}{
		{"an intact sink", func(*testing.T, *sinkWorld) {}, "", "", 4, 2},
		{"a checkpoint object missing", func(t *testing.T, w *sinkWorld) { w.srv.Remove(w.cpKey(3)) }, "checkpoints 3 missing from the sink", "", 4, 1},
		{"an entry object missing", func(t *testing.T, w *sinkWorld) { w.srv.Remove(w.entryKey(2)) }, "entries 2 missing from the sink", "", 4, 2},
		{"the newest entry missing", func(t *testing.T, w *sinkWorld) { w.srv.Remove(w.entryKey(5)) }, "entries 5 missing from the sink", "", 4, 2},
		{"every entry missing", func(t *testing.T, w *sinkWorld) {
			for i := 1; i <= 5; i++ {
				w.srv.Remove(w.entryKey(i))
			}
		}, "entries 1-5 missing from the sink", "", 4, 2},
		{"a checkpoint with another head hash", func(t *testing.T, w *sinkWorld) {
			b, _ := w.srv.Get(w.cpKey(4))
			i := strings.Index(string(b), `"head_hash":"`) + len(`"head_hash":"`)
			w.srv.Tamper(w.cpKey(4), append(append(append([]byte{}, b[:i]...), "ff"...), b[i+2:]...))
		}, "", "the checkpoint at seq 4 has no valid signature", 3, 1},
		{"a checkpoint with a forged signature", func(t *testing.T, w *sinkWorld) {
			b, _ := w.srv.Get(w.cpKey(3))
			i := strings.Index(string(b), `"signature":"`) + len(`"signature":"`)
			w.srv.Tamper(w.cpKey(3), append(append(append([]byte{}, b[:i]...), "AAAA"...), b[i+4:]...))
		}, "", "the checkpoint at seq 3 has no valid signature", 0, 0},
		{"an object that is no checkpoint", func(t *testing.T, w *sinkWorld) { w.srv.Tamper(w.cpKey(4), []byte("not json")) },
			"", "is not a checkpoint", 3, 1},
		{"a checkpoint under another key", func(t *testing.T, w *sinkWorld) {
			b, _ := w.srv.Get(w.cpKey(4))
			w.srv.Tamper(w.cpKey(3), b)
		}, "", "is not the checkpoint its key names", 0, 0},
		{"a database that lost its tail", func(t *testing.T, w *sinkWorld) {
			w.x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq >= 4", w.e.a)
			w.x(t, "DELETE FROM audit_checkpoints WHERE org_id = $1", w.e.a)
			w.x(t, "UPDATE audit_heads SET seq = 3, hash = (SELECT hash FROM audit_log WHERE org_id = $1 AND seq = 3) WHERE chain = $1", w.e.a)
		}, "", "entries were removed", 3, 1},
		{"a database whose entry was edited", func(t *testing.T, w *sinkWorld) {
			w.x(t, "UPDATE audit_log SET action = 'session.logout' WHERE org_id = $1 AND seq = 2", w.e.a)
		}, "", "does not verify in the database", 4, 2},
		{"a database after the retention cut", func(t *testing.T, w *sinkWorld) {
			w.x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq <= 3", w.e.a)
		}, "", "", 4, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
				w := newSinkWorld(t, e, ca, trust)
				tc.tamper(t, w)
				v, err := w.verify(t, nil)
				if err != nil {
					t.Fatal(err)
				}
				c := w.chain(t, v)
				if (tc.gap == "") != (c.Gap == "") || (tc.gap != "" && c.Gap != tc.gap) || !strings.Contains(c.Problem, tc.problem) ||
					(tc.problem == "") != (c.Problem == "") || c.CheckpointSeq != tc.wantSeq || c.Checked != tc.wantCheck || c.Intact() != (tc.gap == "" && tc.problem == "") {
					t.Fatalf("%+v, want gap %q problem %q seq %d checked %d", c, tc.gap, tc.problem, tc.wantSeq, tc.wantCheck)
				}
				if tc.wantSeq != 0 && c.CheckpointTime.IsZero() {
					t.Error("no time for the last verified checkpoint")
				}
			})
		})
	}

	t.Run("a later read-back starts at the last verified checkpoint", func(t *testing.T) {
		withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
			w := newSinkWorld(t, e, ca, trust)
			v, err := w.verify(t, nil)
			if err != nil {
				t.Fatal(err)
			}
			gets := objectGets(w.srv)
			v2, err := w.verify(t, v)
			if c := w.chain(t, v2); err != nil || !c.Intact() || c.CheckpointSeq != 4 || c.Checked != 1 || objectGets(w.srv)-gets != 1 {
				t.Fatalf("second read-back: %+v %v, %d GETs", c, err, objectGets(w.srv)-gets)
			}
			// Nothing newer, and an older object gone: not looked at again, so not found.
			w.srv.Remove(w.cpKey(3))
			if v3, err := w.verify(t, v2); err != nil || w.chain(t, v3).Gap == "" {
				t.Fatalf("a missing older checkpoint is still a gap: %+v %v", v3, err)
			}
		})
	})

	t.Run("a sink that cannot be read", func(t *testing.T) {
		withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
			w := newSinkWorld(t, e, ca, trust)
			w.srv.Fault = func(string, string) (int, time.Duration) { return 500, 0 }
			var un *auditsink.UnreachableError
			if v, err := w.verify(t, nil); !errors.As(err, &un) || v != nil || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), awsKey) {
				t.Fatalf("a store that answers 500: %v %v", v, err)
			}
			w.srv.Fault = nil
			w.srv.Close()
			if v, err := w.verify(t, nil); !errors.As(err, &un) || v != nil || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("a store that is down: %v %v", v, err)
			}
		})
	})

	t.Run("a sink that is not an object-storage sink", func(t *testing.T) {
		withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
			w := newSinkWorld(t, e, ca, trust)
			row := *w.row
			row.Kind = "syslog"
			if _, err := w.runner.VerifyS3(sys(t), &row, trust); err == nil || !strings.Contains(err.Error(), "only an object-storage sink") {
				t.Fatalf("a syslog sink: %v", err)
			}
			row = *w.row
			row.SecretEnc = nil
			if _, err := w.runner.VerifyS3(sys(t), &row, trust); err == nil || !strings.Contains(err.Error(), "no secret key") {
				t.Fatalf("a sink without a key: %v", err)
			}
			row.SecretEnc = &[]byte{1, 2, 3}
			if _, err := w.runner.VerifyS3(sys(t), &row, trust); err == nil || strings.Contains(err.Error(), awsKey) {
				t.Fatalf("a key that cannot be opened: %v", err)
			}
		})
	})
}
