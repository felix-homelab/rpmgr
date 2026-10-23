// SPDX-License-Identifier: Apache-2.0

package snapshot_test

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const offerManifest = `{"seq":7,"version":"0.2.0","floor":"0.1.0","channel":"stable","issued_at":"2026-10-20T00:00:00Z",` +
	`"artifacts":[{"os":"linux","arch":"amd64","variant":"full","sha256":"` +
	"0101010101010101010101010101010101010101010101010101010101010101" + `","size":10},` +
	`{"os":"linux","arch":"amd64","variant":"connector","sha256":"` +
	"0202020202020202020202020202020202020202020202020202020202020202" + `","size":8}]}`

// TestReleaseOffer (D121, docs/04-security.md, "Over-the-air updates", step 3): an agent with the
// capability ota whose rollout target is offered gets the running rollout's release with every
// file under /dl/; an agent without the capability, one whose target is not offered, every agent
// of a paused rollout, and every agent while the mirror does not hold the release (D125) get none.
func TestReleaseOffer(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		c := db.Client()
		rel := c.Release.Create().SetVersion("0.2.0").SetChannel("stable").SetManifestSeq(7).SetManifest([]byte(offerManifest)).
			SetSignature([]byte("manifest sig")).SetSigningKeyStatement([]byte(`{"statement":1}`)).
			SetStatementSignature([]byte("statement sig")).SetSource("check").SetMirroredAt(time.Now()).SaveX(sys)
		ro := c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").SaveX(sys)
		offered := c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID("con_1").SetAgentKind("connector").SetBucket(3).
			SetState(rollouttarget.StateOffered).SaveX(sys)
		c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID("con_2").SetAgentKind("connector").SetBucket(4).ExecX(sys)

		cmp := &snapshot.Compiler{Offer: snapshot.ReleaseOfferAt("https://controller.example")}
		ota := testAgent
		ota.Capabilities = []string{agentproto.CapTunnelQUIC, agentproto.CapOTA}
		snap, err := cmp.Compile(sys, db, ota)
		if err != nil {
			t.Fatal(err)
		}
		o := snap.GetReleaseOffer()
		if o.GetVersion() != "0.2.0" || o.GetSeq() != 7 || o.GetBaseUrl() != "https://controller.example" {
			t.Fatalf("offer %v, want 0.2.0, seq 7 and the controller's public URL", o)
		}
		var names []string
		for _, f := range o.GetFiles() {
			names = append(names, f.GetName())
		}
		want := []string{"signing-key.json", "signing-key.json.minisig", "manifest.json.minisig", "manifest.json",
			"rpmgr-0.2.0-linux-amd64", "rpmgr-0.2.0-linux-amd64-connector"}
		if !slices.Equal(names, want) {
			t.Fatalf("offered files %v, want %v", names, want)
		}
		sum := sha256.Sum256([]byte(offerManifest))
		if f := o.GetFiles()[3]; f.GetSize() != uint64(len(offerManifest)) || string(f.GetSha256()) != string(sum[:]) {
			t.Errorf("manifest.json offered as %d bytes, %x", f.GetSize(), f.GetSha256())
		}
		if f := o.GetFiles()[5]; f.GetSize() != 8 || hex.EncodeToString(f.GetSha256()) != "0202020202020202020202020202020202020202020202020202020202020202" {
			t.Errorf("the connector artifact offered as %d bytes, %x", f.GetSize(), f.GetSha256())
		}

		// The same agent without the capability, and an agent whose target is still pending.
		if snap, err := cmp.Compile(sys, db, testAgent); err != nil || snap.GetReleaseOffer() != nil {
			t.Errorf("an agent without ota: offer %v, error %v", snap.GetReleaseOffer(), err)
		}
		pending := ota
		pending.Identity.ID = "con_2"
		if snap, err := cmp.Compile(sys, db, pending); err != nil || snap.GetReleaseOffer() != nil {
			t.Errorf("a pending target: offer %v, error %v", snap.GetReleaseOffer(), err)
		}
		// A paused rollout offers nothing, and a staged target is not offered again.
		c.Rollout.UpdateOne(ro).SetState(rollout.StatePaused).ExecX(sys)
		if snap, err := cmp.Compile(sys, db, ota); err != nil || snap.GetReleaseOffer() != nil {
			t.Errorf("a paused rollout: offer %v, error %v", snap.GetReleaseOffer(), err)
		}
		c.Rollout.UpdateOne(ro).SetState(rollout.StateRunning).ExecX(sys)
		// A release the mirror does not hold, such as after a newer manifest was uploaded, is
		// offered again only once the mirror holds it (D125).
		c.Release.UpdateOne(rel).ClearMirroredAt().ExecX(sys)
		if snap, err := cmp.Compile(sys, db, ota); err != nil || snap.GetReleaseOffer() != nil {
			t.Errorf("a release the mirror does not hold: offer %v, error %v", snap.GetReleaseOffer(), err)
		}
		c.Release.UpdateOne(rel).SetMirroredAt(time.Now()).ExecX(sys)
		if snap, err := cmp.Compile(sys, db, ota); err != nil || snap.GetReleaseOffer().GetVersion() != "0.2.0" {
			t.Errorf("once the mirror holds the release again: offer %v, error %v", snap.GetReleaseOffer(), err)
		}
		c.RolloutTarget.UpdateOne(offered).SetState(rollouttarget.StateStaged).ExecX(sys)
		if snap, err := cmp.Compile(sys, db, ota); err != nil || snap.GetReleaseOffer() != nil {
			t.Errorf("a staged target: offer %v, error %v", snap.GetReleaseOffer(), err)
		}
	})
}

// TestOffer_Malformed: a recorded manifest that does not parse, names another version or has an
// artifact checksum that is not SHA-256 is an error, never an offer.
func TestOffer_Malformed(t *testing.T) {
	for name, m := range map[string]string{
		"not json":      `{`,
		"other version": `{"seq":7,"version":"0.3.0","artifacts":[]}`,
		"short sha":     `{"seq":7,"version":"0.2.0","artifacts":[{"os":"linux","arch":"amd64","variant":"full","sha256":"01","size":1}]}`,
		"negative size": `{"seq":7,"version":"0.2.0","artifacts":[{"os":"linux","arch":"amd64","variant":"full","sha256":"` +
			"0101010101010101010101010101010101010101010101010101010101010101" + `","size":-1}]}`,
	} {
		if o, err := snapshot.Offer(&ent.Release{Version: "0.2.0", Manifest: []byte(m)}, "https://controller.example"); err == nil {
			t.Errorf("%s: offer %v, want an error", name, o)
		}
	}
	o, err := snapshot.Offer(&ent.Release{Version: "0.2.0", Manifest: []byte(offerManifest)}, "https://controller.example")
	if err != nil || len(o.GetFiles()) != 6 {
		t.Fatalf("a valid manifest: %v, %v", o, err)
	}
}
