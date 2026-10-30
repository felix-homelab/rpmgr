// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
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
