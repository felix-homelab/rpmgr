// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/policy"
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

	start := func(id agent.Loaded, state string, update *agent.UpdateOptions) *offerRecorder {
		if err := os.MkdirAll(state, 0o750); err != nil {
			t.Fatal(err)
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
	plain := start(without, filepath.Join(dir, "plain", "state"), nil)
	ota := start(withOTA, filepath.Join(dir, "ota", "state"), &agent.UpdateOptions{Dir: filepath.Join(dir, "ota", "state", "update"),
		StatusFile: filepath.Join(dir, "status.json"), Variant: "full",
		Policy: func() *policy.Policy {
			return &policy.Policy{AutoUpdate: policy.AutoUpdateOff, UpdateChannel: policy.ChannelStable}
		}})

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
