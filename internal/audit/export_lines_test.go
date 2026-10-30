// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// exported runs Export of a chain in ctx and returns its lines by type, in order.
func exported(t *testing.T, ctx context.Context, e env, org string, trust audit.Trust) (audit.ExportHeader, []string, []json.RawMessage, error) {
	t.Helper()
	var lines []json.RawMessage
	err := audit.Export(ctx, e.db, org, trust, time.Now(), func(b []byte) error {
		lines = append(lines, bytes.Clone(b))
		return nil
	})
	var h audit.ExportHeader
	var types []string
	for i, l := range lines {
		var typ struct{ Type string }
		if json.Unmarshal(l, &typ) != nil {
			t.Fatalf("line %d is not JSON: %s", i, l)
		}
		types = append(types, typ.Type)
		if i == 0 {
			if err := json.Unmarshal(l, &h); err != nil {
				t.Fatal(err)
			}
		}
	}
	return h, types, lines, err
}

func wantTypes(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("line types %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line types %v, want %v", got, want)
		}
	}
}

// TestExport: the header names the format, the chain and the seqs, each checkpoint follows the
// entry it covers, and the entries after the newest checkpoint are flagged unanchored.
func TestExport(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		now := time.Now()
		for range 3 {
			record(t, e.db, login(e.a, "usr_1"))
		}
		record(t, e.db, login(e.b, "usr_2"))
		checkpoint(t, e, ca, now, audit.Pending)
		record(t, e.db, login(e.a, "usr_1"))
		record(t, e.db, login(e.a, "usr_1"))

		h, types, lines, err := exported(t, storetest.OrgCtx(t, e.a), e, e.a, trust)
		if err != nil {
			t.Fatal(err)
		}
		wantTypes(t, types, "header", "entry", "entry", "entry", "checkpoint", "entry", "entry")
		if h.Format != audit.ExportFormat || h.Chain != e.a || h.FirstSeq != 1 || h.LastSeq != 5 || h.AnchoredSeq != 3 ||
			len(h.Root) == 0 || len(h.Signers) != 1 {
			t.Fatalf("header %+v", h)
		}
		for i, l := range lines[1:] {
			var en audit.ExportEntry
			if err := json.Unmarshal(l, &en); err != nil {
				t.Fatal(err)
			}
			if en.Type == audit.LineEntry && (en.Unanchored != (en.Seq > 3) || len(en.Hash) == 0 || len(en.PrevHash) == 0) {
				t.Fatalf("entry %d of the export: %+v", i, en)
			}
		}
		// The instance chain is the system scope's, and a chain of its own.
		ih, itypes, _, err := exported(t, sys(t), e, "", trust)
		if err != nil || ih.Chain != audit.InstanceChain {
			t.Fatalf("the instance chain: %+v %v", ih, err)
		}
		if ih.LastSeq != int64(len(itypes)-1) {
			t.Fatalf("the instance chain has %d entries in %v, header %+v", ih.LastSeq, itypes, ih)
		}
	})
}

// TestExport_RetentionCut: after retention removed the first entries, the export starts at the
// checkpoint that anchors the first entry left.
func TestExport_RetentionCut(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
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
		if err := store.WriteTx(sys(t), e.db, func(tx *ent.Tx) error {
			_, err := audit.Prune(sys(t), tx, e.a, time.Now().Add(time.Hour))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		h, types, _, err := exported(t, storetest.OrgCtx(t, e.a), e, e.a, trust)
		if err != nil {
			t.Fatal(err)
		}
		wantTypes(t, types, "header", "checkpoint", "entry")
		if h.FirstSeq != 6 || h.LastSeq != 6 || h.AnchoredSeq != 5 {
			t.Fatalf("header %+v", h)
		}
	})
}

// TestExport_EmptyAndUnanchored: a chain without entries exports its header alone; a chain
// without a checkpoint exports every entry as unanchored.
func TestExport_EmptyAndUnanchored(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		h, types, _, err := exported(t, storetest.OrgCtx(t, e.a), e, e.a, trust)
		if err != nil {
			t.Fatal(err)
		}
		wantTypes(t, types, "header")
		if h.FirstSeq != 0 || h.LastSeq != 0 || h.AnchoredSeq != 0 {
			t.Fatalf("header of an empty chain %+v", h)
		}
		record(t, e.db, login(e.a, "usr_1"))
		h, types, lines, err := exported(t, storetest.OrgCtx(t, e.a), e, e.a, trust)
		if err != nil {
			t.Fatal(err)
		}
		wantTypes(t, types, "header", "entry")
		var en audit.ExportEntry
		if err := json.Unmarshal(lines[1], &en); err != nil || !en.Unanchored || h.AnchoredSeq != 0 {
			t.Fatalf("entry %+v header %+v: %v", en, h, err)
		}
	})
}

// TestExport_Scope: an org scope exports its own chain only, a missing scope nothing, and a line
// function that fails (a client that went away) ends the export with its error.
func TestExport_Scope(t *testing.T) {
	withCA(t, func(t *testing.T, e env, ca *castore.CA, trust audit.Trust) {
		record(t, e.db, login(e.a, "usr_1"))
		for name, c := range map[string]struct {
			ctx context.Context
			org string
		}{
			"another org":                   {storetest.OrgCtx(t, e.b), e.a},
			"the instance chain, org scope": {storetest.OrgCtx(t, e.a), ""},
		} {
			if _, _, _, err := exported(t, c.ctx, e, c.org, trust); !errors.Is(err, audit.ErrOutsideScope) {
				t.Errorf("%s: %v", name, err)
			}
		}
		if _, _, _, err := exported(t, context.Background(), e, e.a, trust); err == nil {
			t.Error("an export without a scope")
		}
		gone := errors.New("client went away")
		n := 0
		err := audit.Export(storetest.OrgCtx(t, e.a), e.db, e.a, trust, time.Now(), func([]byte) error {
			n++
			return gone
		})
		if !errors.Is(err, gone) || n != 1 {
			t.Fatalf("an aborted export: %v after %d lines", err, n)
		}
	})
}
