// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// offerRecorder is an Applier that records the release offer of the last snapshot applied.
type offerRecorder struct {
	recorder
	mu    sync.Mutex
	offer *agentv1.ReleaseOffer
	seen  bool
}

func (r *offerRecorder) Apply(ctx context.Context, snap *agentv1.Snapshot, c agent.Changes) []*agentv1.ResourceStatus {
	r.mu.Lock()
	r.offer, r.seen = snap.GetReleaseOffer(), true
	r.mu.Unlock()
	return r.recorder.Apply(ctx, snap, c)
}

func (r *offerRecorder) last() (*agentv1.ReleaseOffer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.offer, r.seen
}

// TestOTA_OfferOnlyWithCapability (docs/03-connections.md, "Versioning and capabilities"): of two
// connectors whose rollout targets are offered, the one that announces ota gets the release in its
// snapshot and the one that does not gets none.
func TestOTA_OfferOnlyWithCapability(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	withOTA := c.EnrollConnector(t, filepath.Join(dir, "ota", "identity"))
	without := c.EnrollConnector(t, filepath.Join(dir, "plain", "identity"))

	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		rel, err := tx.Release.Create().SetVersion("0.2.0").SetChannel("stable").SetManifestSeq(7).
			SetManifest([]byte(`{"seq":7,"version":"0.2.0","floor":"0.1.0","channel":"stable","issued_at":"2026-10-20T00:00:00Z","artifacts":[]}`)).
			SetSignature([]byte("sig")).SetSigningKeyStatement([]byte(`{"statement":1}`)).SetStatementSignature([]byte("sig")).
			SetSource("upload").SetMirroredAt(time.Now()).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		ro, err := tx.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").Save(c.Sys)
		if err != nil {
			return nil, err
		}
		for _, id := range []string{withOTA.AgentID, without.AgentID} {
			if err := tx.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(id).SetAgentKind("connector").SetBucket(1).
				SetState(rollouttarget.StateOffered).Exec(c.Sys); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}

	plain := startOfferAgent(t, c, without, filepath.Join(dir, "plain", "state"), false)
	ota := startOfferAgent(t, c, withOTA, filepath.Join(dir, "ota", "state"), true)

	waitFor(t, "the offer in the ota connector's snapshot", func() bool {
		o, _ := ota.last()
		return o.GetVersion() == "0.2.0" && o.GetSeq() == 7 && len(o.GetFiles()) == 4
	})
	// The offer names the controller's public URL, not the agent's control endpoint: every agent
	// fetches from the same /dl/ (slice 2.7's follow-up, #857).
	if o, _ := ota.last(); o.GetBaseUrl() != c.URL {
		t.Errorf("offer base URL %q, want the controller's public URL %q", o.GetBaseUrl(), c.URL)
	}
	waitFor(t, "the plain connector's snapshot", func() bool { _, seen := plain.last(); return seen })
	if o, _ := plain.last(); o != nil {
		t.Fatalf("a connector without ota was offered %v", o)
	}
}

// startOfferAgent runs a connector's control session at version 0.1.0 with an offerRecorder; with
// ota, it announces the capability, with a policy that declines every offer.
func startOfferAgent(t *testing.T, c *itest.Controller, id agent.Loaded, state string, ota bool) *offerRecorder {
	t.Helper()
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	var update *agent.UpdateOptions
	if ota {
		update = &agent.UpdateOptions{Dir: filepath.Join(state, "update"), StatusFile: filepath.Join(state, "status.json"), Variant: "full",
			Policy: func() *policy.Policy {
				return &policy.Policy{AutoUpdate: policy.AutoUpdateOff, UpdateChannel: policy.ChannelStable}
			}}
	}
	rec := &offerRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
			Applier: rec, Backoff: fast(), Logger: c.Logs.Logger(), Update: update})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return rec
}

// TestOTA_OfferOnceMirrored (D125): a rollout of a release the mirror does not hold yet offers
// nothing; the release check marking it mirrored afterwards records a revision, so the agent's
// snapshot offers it without any other change; a newer manifest, which the mirror does not hold
// yet, withdraws the offer the same way.
func TestOTA_OfferOnceMirrored(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	con := c.EnrollConnector(t, filepath.Join(dir, "ota", "identity"))
	manifest := func(seq uint64) *release.Signed {
		m := fmt.Sprintf(`{"seq":%d,"version":"0.2.0","floor":"0.1.0","channel":"stable","issued_at":"2026-10-20T00:00:00Z","artifacts":[]}`, seq)
		return &release.Signed{Manifest: &release.Manifest{Seq: seq, Version: "0.2.0", Channel: release.Stable},
			ManifestJSON: []byte(m), ManifestSig: []byte("sig"), Statement: []byte(`{"statement":1}`), StatementSig: []byte("sig")}
	}
	rel, err := store.RecordRelease(c.Sys, c.DB, manifest(7), "upload", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		ro, err := tx.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").Save(c.Sys)
		if err != nil {
			return nil, err
		}
		return []string{ro.ID}, tx.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(con.AgentID).SetAgentKind("connector").
			SetBucket(1).SetState(rollouttarget.StateOffered).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}

	ota := startOfferAgent(t, c, con, filepath.Join(dir, "ota", "state"), true)
	waitFor(t, "the ota connector's snapshot", func() bool { _, seen := ota.last(); return seen })
	if o, _ := ota.last(); o != nil {
		t.Fatalf("a release the mirror does not hold was offered: %v", o)
	}

	now := time.Now()
	if _, err := store.RecordRelease(c.Sys, c.DB, manifest(7), "check", &now); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the offer once the mirror holds the release", func() bool {
		o, _ := ota.last()
		return o.GetVersion() == "0.2.0" && o.GetSeq() == 7
	})

	if _, err := store.RecordRelease(c.Sys, c.DB, manifest(8), "upload", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the offer withdrawn while the mirror lacks the newer manifest", func() bool { o, _ := ota.last(); return o == nil })
}

// TestOTA_ReportsUpdatePolicy: an agent that updates over the air reports auto_update and
// update_channel of its local policy file in Hello, and again when the file changes; a file that
// does not parse, one others may write and one it cannot read count as auto_update off, and a
// missing file is the defaults. An agent without OTA reports none.
func TestOTA_ReportsUpdatePolicy(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	id := c.EnrollConnector(t, filepath.Join(dir, "ota", "identity"))
	plain := c.EnrollConnector(t, filepath.Join(dir, "plain", "identity"))
	file := filepath.Join(dir, "policy.yaml")
	write := func(text string, mode os.FileMode) {
		t.Helper()
		_ = os.Remove(file) // a file made unreadable cannot be written
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil { //nolint:gosec // G302: the test makes the file untrusted on purpose
			t.Fatal(err)
		}
	}
	write("version: 1\nauto_update: notify\nupdate_channel: prerelease\n", 0o600)
	state := filepath.Join(dir, "ota", "state")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
			Applier: &recorder{}, Backoff: fast(), Logger: c.Logs.Logger(),
			Update: &agent.UpdateOptions{Dir: filepath.Join(state, "update"), StatusFile: filepath.Join(state, "status.json"), Variant: "full",
				PolicyEvery: 20 * time.Millisecond, Policy: func() *policy.Policy { p, _ := policy.Load(file); return p }}})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	plainState := filepath.Join(dir, "plain", "state")
	if err := os.MkdirAll(plainState, 0o750); err != nil {
		t.Fatal(err)
	}
	pctx, pcancel := context.WithCancel(context.Background())
	pdone := make(chan struct{})
	go func() {
		_ = agent.RunControl(pctx, agent.ControlOptions{IdentityDir: plain.Dir, StateDir: plainState, Version: "0.1.0",
			Applier: &recorder{}, Backoff: fast(), Logger: c.Logs.Logger()})
		close(pdone)
	}()
	t.Cleanup(func() { pcancel(); <-pdone })

	reported := func() (string, string) {
		s, err := c.DB.ReadClient().AgentSession.Get(c.Sys, id.AgentID)
		if err != nil {
			return "", ""
		}
		return s.UpdateAuto, s.UpdateChannel
	}
	expect := func(what, auto, channel string) {
		t.Helper()
		waitFor(t, what, func() bool { a, ch := reported(); return a == auto && ch == channel })
	}
	expect("the policy of Hello", "notify", "prerelease")
	write("version: 1\nauto_update: auto\nupdate_channel: stable\n", 0o600)
	expect("the policy after the file changed", "auto", "stable")
	write("version: 1\nauto_update: [", 0o600)
	expect("a file that does not parse", "off", "stable")
	write("version: 1\nauto_update: auto\nupdate_channel: prerelease\n", 0o600)
	expect("the policy again", "auto", "prerelease")
	write("version: 1\nauto_update: auto\nupdate_channel: prerelease\n", 0o666)
	expect("a file others may write", "off", "stable")
	write("version: 1\nauto_update: auto\nupdate_channel: prerelease\n", 0o600)
	expect("a file made safe again", "auto", "prerelease")
	if os.Geteuid() != 0 { // root reads any file
		write("version: 1\nauto_update: auto\nupdate_channel: prerelease\n", 0)
		expect("a file that cannot be read", "off", "stable")
		write("version: 1\nauto_update: notify\nupdate_channel: stable\n", 0o600)
		expect("a file that can be read again", "notify", "stable")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	expect("a missing file", "auto", "stable")

	// An agent without OTA reports nothing.
	waitFor(t, "the plain agent's session", func() bool {
		s, err := c.DB.ReadClient().AgentSession.Get(c.Sys, plain.AgentID)
		return err == nil && s.UpdateAuto == "" && s.UpdateChannel == ""
	})
}
