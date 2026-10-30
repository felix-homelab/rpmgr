// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// export returns the lines of an export of org's chain as an offline verifier gets them.
func export(t *testing.T, e env, org string, trust audit.Trust) []string {
	t.Helper()
	ctx := sys(t)
	if org != "" {
		ctx = storetest.OrgCtx(t, org)
	}
	_, _, lines, err := exported(t, ctx, e, org, trust)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = string(l)
	}
	return out
}

func verifyLines(lines []string, pin string) (audit.ExportResult, error) {
	return audit.VerifyExport(strings.NewReader(strings.Join(lines, "\n")+"\n"), pin)
}

// edit changes the JSON object of a line.
func edit(t *testing.T, line string, f func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestAuditExport_TamperDetectedOffline (docs/04-security.md, "Audit log"): an export verifies
// against the CA's pin alone; an edited, removed or reordered entry, a forged checkpoint, a wrong
// pin, a checkpoint of a key the CA never certified, a cut-off export and another format version
// are refused; entries after the newest checkpoint are reported, not refused.
func TestAuditExport_TamperDetectedOffline(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		pin := pki.RootPin(trust.Root)
		now := time.Now()
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		checkpoint(t, e, ca, now, audit.Pending)
		for range 2 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		checkpoint(t, e, ca, now.Add(time.Hour), audit.Pending)
		record(t, e.db, login(e.a, "usr_1"))
		lines := export(t, e, e.a, trust)
		// header, entries 1-3, checkpoint 3, entries 4-5, checkpoint 5, entry 6 (unanchored)
		if len(lines) != 9 || !strings.Contains(lines[4], `"type":"checkpoint"`) {
			t.Fatalf("the export is %d lines: %v", len(lines), lines)
		}

		res, err := verifyLines(lines, pin)
		if err != nil || res.Chain != e.a || res.Entries != 6 || res.Checkpoints != 2 || res.AnchoredSeq != 5 || res.Unanchored != 1 ||
			res.FirstSeq != 1 || res.LastSeq != 6 {
			t.Fatalf("an intact export: %+v %v", res, err)
		}

		broken := func(name string, bad []string, seq int64) {
			t.Helper()
			_, err := verifyLines(bad, pin)
			var ce *audit.ChainError
			if !errors.As(err, &ce) || !errors.Is(err, audit.ErrBroken) {
				t.Errorf("%s: %v, want a broken chain", name, err)
			} else if seq != 0 && ce.Seq != seq {
				t.Errorf("%s: broken at %d, want %d (%s)", name, ce.Seq, seq, ce.Problem)
			}
		}
		with := func(i int, line string) []string { c := slices.Clone(lines); c[i] = line; return c }
		without := func(i int) []string { return slices.Delete(slices.Clone(lines), i, i+1) }

		broken("an edited entry", with(2, edit(t, lines[2], func(m map[string]any) { m["ip"] = "198.51.100.9" })), 2)
		broken("an edited hash", with(2, edit(t, lines[2], func(m map[string]any) { m["hash"] = "AAAA" })), 0)
		broken("a removed entry", without(2), 2)
		broken("a removed first entry", without(1), 0)
		broken("a removed entry after a checkpoint", without(6), 0)
		reordered := slices.Clone(lines)
		reordered[2], reordered[3] = reordered[3], reordered[2]
		broken("reordered entries", reordered, 0)
		broken("a forged checkpoint head", with(4, edit(t, lines[4], func(m map[string]any) { m["head_hash"] = "AAAA" })), 0)
		broken("a forged checkpoint signature", with(4, edit(t, lines[4], func(m map[string]any) { m["signature"] = "AAAA" })), 0)
		broken("a checkpoint of an unknown key", with(4, edit(t, lines[4], func(m map[string]any) { m["key_id"] = "k_forged" })), 0)
		broken("a checkpoint moved to another entry", with(4, edit(t, lines[4], func(m map[string]any) { m["seq"] = 2 })), 0)
		broken("a missing last checkpoint", lines[:7], 0)
		broken("a missing tail entry", lines[:8], 0)
		broken("a missing last entry and checkpoint", lines[:6], 0)
		broken("an entry flagged anchored", with(8, edit(t, lines[8], func(m map[string]any) { delete(m, "unanchored") })), 6)
		broken("an entry flagged unanchored", with(1, edit(t, lines[1], func(m map[string]any) { m["unanchored"] = true })), 1)
		broken("an entry of another chain", append(slices.Clone(lines[:1]), lines[2:]...), 0)

		if _, err := verifyLines(lines, pki.RootPin(trust.Intermediates[0])); !errors.Is(err, audit.ErrExportPin) {
			t.Errorf("a wrong pin: %v", err)
		}
		if _, err := verifyLines(lines, "sha256:short"); err == nil || errors.Is(err, audit.ErrBroken) {
			t.Errorf("a malformed pin: %v", err)
		}
		other := with(0, edit(t, lines[0], func(m map[string]any) { m["format"] = "rpmgr-audit-export/2" }))
		if _, err := verifyLines(other, pin); !errors.Is(err, audit.ErrExportFormat) {
			t.Errorf("another format version: %v", err)
		}
		for name, in := range map[string]string{"empty": "", "not JSON": "{", "not a header": lines[1] + "\n",
			"a line of another type": lines[0] + "\n" + `{"type":"x"}` + "\n", "a line too long": lines[0] + "\n" + strings.Repeat("a", 5<<20)} {
			if _, err := audit.VerifyExport(strings.NewReader(in), pin); !errors.Is(err, audit.ErrExportFormat) && err == nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		if _, err := audit.VerifyExport(bytes.NewReader(nil), pin); err == nil {
			t.Error("an empty export verified")
		}
	})
}

// TestVerifyExport_ShapesOfAChain: an empty chain, a chain without a checkpoint, the instance
// chain and a chain after retention verify; retention without its anchor does not.
func TestVerifyExport_ShapesOfAChain(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		pin := pki.RootPin(trust.Root)
		if res, err := verifyLines(export(t, e, e.a, trust), pin); err != nil || res.Entries != 0 {
			t.Fatalf("an empty chain: %+v %v", res, err)
		}
		record(t, e.db, login(e.a, "usr_1"))
		if res, err := verifyLines(export(t, e, e.a, trust), pin); err != nil || res.Entries != 1 || res.Unanchored != 1 || res.AnchoredSeq != 0 {
			t.Fatalf("a chain without a checkpoint: %+v %v", res, err)
		}
		record(t, e.db, audit.Entry{ActorType: audit.ActorUser, ActorID: "usr_1", Action: "ca.rotate_intermediate", Result: audit.Success})
		if res, err := verifyLines(export(t, e, "", trust), pin); err != nil || res.Chain != audit.InstanceChain || res.Entries == 0 {
			t.Fatalf("the instance chain: %+v %v", res, err)
		}

		now := time.Now()
		for range 2 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		checkpoint(t, e, ca, now, audit.Pending)
		record(t, e.db, login(e.a, "usr_1"))
		if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
			_, err := audit.Prune(sys(t), tx, e.a, time.Now().Add(time.Hour))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		lines := export(t, e, e.a, trust)
		res, err := verifyLines(lines, pin)
		if err != nil || res.FirstSeq != 4 || res.Entries != 1 || res.Checkpoints != 1 {
			t.Fatalf("a chain after retention: %+v %v", res, err)
		}
		if _, err := verifyLines(slices.Delete(slices.Clone(lines), 1, 2), pin); !errors.Is(err, audit.ErrBroken) {
			t.Fatalf("retention without its anchoring checkpoint: %v", err)
		}
	})
}

// TestVerifyExport_HeaderAndTruncation (docs/04-security.md, "Audit log"): the header is not signed,
// so the verifier reports only what it verified from the entries; a first entry that is not the
// header's first_seq is refused; a cut at the start or end that falls on a checkpoint, with the
// header adjusted, verifies and needs a reference from outside; a cut elsewhere does not.
func TestVerifyExport_HeaderAndTruncation(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		pin := pki.RootPin(trust.Root)
		now := time.Now()
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		checkpoint(t, e, ca, now, audit.Pending)
		for range 2 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		checkpoint(t, e, ca, now.Add(time.Hour), audit.Pending)
		record(t, e.db, login(e.a, "usr_1"))
		lines := export(t, e, e.a, trust)
		// header, entries 1-3, checkpoint 3, entries 4-5, checkpoint 5, entry 6
		hdr := func(f func(m map[string]any)) string { return edit(t, lines[0], f) }
		join := func(first string, rest ...string) []string { return append([]string{first}, rest...) }
		refused := func(name string, in []string) {
			t.Helper()
			if res, err := verifyLines(in, pin); !errors.Is(err, audit.ErrBroken) {
				t.Errorf("%s: %+v %v, want a broken chain", name, res, err)
			}
		}

		refused("a header naming a later first entry", join(hdr(func(m map[string]any) { m["first_seq"] = 2 }), lines[1:]...))
		refused("a header naming an earlier first entry", join(hdr(func(m map[string]any) { m["first_seq"] = 0 }), lines[1:]...))
		refused("a header with a first_seq for no entries", join(hdr(func(m map[string]any) { m["first_seq"] = 7 }), lines[1:]...))
		refused("leading entries cut away, not at a checkpoint", join(hdr(func(m map[string]any) { m["first_seq"] = 3 }), lines[3:]...))
		refused("trailing entries cut away, the header unchanged", lines[:6])

		// Cut on a checkpoint: the file verifies, with the seqs of what is left.
		head := hdr(func(m map[string]any) { m["first_seq"] = 4 })
		res, err := verifyLines(join(head, lines[4:]...), pin)
		if err != nil || res.FirstSeq != 4 || res.LastSeq != 6 || res.Entries != 3 {
			t.Fatalf("leading entries cut up to a checkpoint: %+v %v", res, err)
		}
		older := hdr(func(m map[string]any) { m["last_seq"] = 3; m["anchored_seq"] = 3 })
		res, err = verifyLines(join(older, lines[1:5]...), pin)
		if err != nil || res.FirstSeq != 1 || res.LastSeq != 3 || res.AnchoredSeq != 3 || res.Unanchored != 0 {
			t.Fatalf("trailing entries cut back to an older checkpoint: %+v %v", res, err)
		}
	})
}

// TestVerifyExport_KeyNotForCheckpoints: a key the CA certified, but for another purpose, does not
// make a checkpoint valid.
func TestVerifyExport_KeyNotForCheckpoints(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		pin := pki.RootPin(trust.Root)
		for range 2 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
			_, err := audit.WriteCheckpoints(sys(t), tx, ca.ConfigSigner(), time.Now(), audit.Pending)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		// The export names the config-signing certificate as a signer, as a forger would.
		trust.Signers = append(slices.Clone(trust.Signers), ca.ConfigSigner().Cert)
		lines := export(t, e, e.a, trust)
		if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, `"type":"checkpoint"`) }) {
			t.Fatalf("no checkpoint in the export: %v", lines)
		}
		if _, err := verifyLines(lines, pin); !errors.Is(err, audit.ErrBroken) {
			t.Fatalf("a checkpoint signed with a certified key of another purpose: %v", err)
		}
	})
}

// TestVerifyExport_TruncatedFinalLine: an export cut inside its last line is refused, whatever
// the line is, and so is one that lost its final line end only when the line is cut.
func TestVerifyExport_TruncatedFinalLine(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		pin := pki.RootPin(trust.Root)
		for range 2 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		checkpoint(t, e, ca, time.Now(), audit.Pending)
		record(t, e.db, login(e.a, "usr_1"))
		lines := export(t, e, e.a, trust)
		whole := strings.Join(lines, "\n")
		if _, err := audit.VerifyExport(strings.NewReader(whole), pin); err != nil { // no final line end is fine
			t.Fatalf("an export without its final newline: %v", err)
		}
		for _, drop := range []int{1, 10, len(lines[len(lines)-1]) / 2} {
			if _, err := audit.VerifyExport(strings.NewReader(whole[:len(whole)-drop]), pin); err == nil {
				t.Errorf("an export cut %d bytes into its last line verified", drop)
			}
		}
		// A checkpoint line cut off as the final line.
		cp := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, `"type":"checkpoint"`) })
		cut := strings.Join(lines[:cp], "\n") + "\n" + lines[cp][:len(lines[cp])/2]
		if _, err := audit.VerifyExport(strings.NewReader(cut), pin); err == nil {
			t.Error("an export cut inside a checkpoint line verified")
		}
	})
}

// TestVerifyExport_LongChain: an export of a few thousand entries verifies, and exporting and
// verifying it stays far inside the export deadline of docs/03-connections.md (5 min) and a
// bounded amount of memory.
func TestVerifyExport_LongChain(t *testing.T) {
	if testing.Short() {
		t.Skip("a long chain")
	}
	const n = 3000
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		pin := pki.RootPin(trust.Root)
		for i := range n {
			record(t, e.db, login(e.a, "usr_1"))
			if i == n/2 {
				checkpoint(t, e, ca, time.Now(), audit.Pending)
			}
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		lines := export(t, e, e.a, trust)
		res, err := verifyLines(lines, pin)
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		if err != nil || res.Entries != n || res.FirstSeq != 1 || res.LastSeq != n || res.Checkpoints != 1 || res.Unanchored != n-n/2-1 {
			t.Fatalf("a chain of %d entries: %+v %v", n, res, err)
		}
		if took > time.Minute {
			t.Errorf("export and verify took %v, want well inside the 5 min export deadline", took)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 512<<20 {
			t.Errorf("export and verify allocated %d MiB for %d entries", alloc>>20, n)
		}
	})
}

// TestExport_DeadlineEndsASlowConsumer: an export whose consumer is slower than the context's
// deadline stops with the deadline's error instead of holding its read transaction open.
func TestExport_DeadlineEndsASlowConsumer(t *testing.T) {
	withCA(t, func(t *testing.T, e env, _ *castore.CA, trust audit.Trust) {
		for range 40 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		ctx, cancel := context.WithTimeout(storetest.OrgCtx(t, e.a), 150*time.Millisecond)
		defer cancel()
		var lines int
		err := audit.Export(ctx, e.db, e.a, trust, time.Now(), func([]byte) error {
			lines++
			time.Sleep(20 * time.Millisecond)
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a slow consumer: %v after %d lines, want the deadline", err, lines)
		}
		if lines >= 41 {
			t.Fatalf("the export wrote all %d lines past its deadline", lines)
		}
	})
}
