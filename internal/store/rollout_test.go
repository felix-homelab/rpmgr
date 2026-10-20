// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
)

// TestRolloutBucket: an agent's bucket is fixed by its ID (values computed independently from
// SHA-256), lies in 0–99 and spreads agents evenly, so a stage of p % takes about p % of them.
func TestRolloutBucket(t *testing.T) {
	for id, want := range map[string]int{"con_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R": 20, "gw_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R": 86, "": 88} {
		if got := store.RolloutBucket(id); got != want {
			t.Errorf("RolloutBucket(%q) = %d, want %d", id, got, want)
		}
	}
	const n = 20000
	var counts [store.RolloutBuckets]int
	for range n {
		b := store.RolloutBucket(ids.New("con"))
		if b < 0 || b >= store.RolloutBuckets {
			t.Fatalf("bucket %d out of range", b)
		}
		counts[b]++
	}
	for b, c := range counts {
		if c < n/store.RolloutBuckets/2 || c > n/store.RolloutBuckets*2 {
			t.Errorf("bucket %d holds %d of %d agents", b, c, n)
		}
	}
	below := 0
	for b := range 25 {
		below += counts[b]
	}
	if below < n*20/100 || below > n*30/100 {
		t.Errorf("a 25 %% stage takes %d of %d agents", below, n)
	}
}

func newRelease(ctx context.Context, c *ent.Client, version string) (*ent.Release, error) {
	return c.Release.Create().SetVersion(version).SetChannel("stable").SetManifestSeq(3).SetManifest([]byte(`{"seq":3}`)).
		SetSignature([]byte("sig")).SetSigningKeyStatement([]byte(`{"statement":1}`)).SetStatementSignature([]byte("sig")).
		SetSource("check").Save(ctx)
}

// TestRelease_OneRowPerVersion: a version is stored once, and releases are the instance's: an
// org's scope neither reads nor writes them.
func TestRelease_OneRowPerVersion(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		sys := systemCtx(t)
		if _, err := newRelease(sys, c, "0.2.0"); err != nil {
			t.Fatal(err)
		}
		if _, err := newRelease(sys, c, "0.2.0"); !store.IsUniqueViolation(err) {
			t.Fatalf("a second row of 0.2.0: %v, want a unique violation", err)
		}
		a, _ := seed(t, c)
		if _, err := c.Release.Query().All(orgCtx(t, a.org)); err == nil {
			t.Error("an org's scope read the releases")
		}
		if _, err := newRelease(orgCtx(t, a.org), c, "0.3.0"); err == nil {
			t.Error("an org's scope created a release")
		}
		if _, err := c.Release.Create().SetVersion("0.4.0").SetChannel("stable").SetManifestSeq(0).
			SetManifest([]byte("{}")).SetSignature([]byte("s")).SetSigningKeyStatement([]byte("{}")).
			SetStatementSignature([]byte("s")).SetSource("check").Save(sys); err == nil {
			t.Error("a release with seq 0 was stored")
		}
	})
}

// TestRollout_OneActive (D121): one rollout runs or is paused at a time, however its state is
// changed; a completed or cancelled one lets the next start; the active flag cannot be set by hand.
func TestRollout_OneActive(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		sys := systemCtx(t)
		rel, err := newRelease(sys, c, "0.2.0")
		if err != nil {
			t.Fatal(err)
		}
		create := func() (*ent.Rollout, error) {
			return c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").Save(sys)
		}
		first, err := create()
		if err != nil {
			t.Fatal(err)
		}
		if !first.Active || first.State != rollout.StateRunning || first.Stage != rollout.StageCanary || first.Version != 1 {
			t.Fatalf("a new rollout: %+v", first)
		}
		if _, err := create(); !store.IsUniqueViolation(err) {
			t.Fatalf("a second rollout while one runs: %v, want a unique violation", err)
		}
		first = c.Rollout.UpdateOne(first).SetState(rollout.StatePaused).SetPauseReason("con_x rolled back").SaveX(sys)
		if !first.Active || first.Version != 2 {
			t.Fatalf("a paused rollout: active %v, version %d", first.Active, first.Version)
		}
		if _, err := create(); !store.IsUniqueViolation(err) {
			t.Fatalf("a second rollout while one is paused: %v, want a unique violation", err)
		}
		// A bulk update keeps the flag in step too.
		c.Rollout.Update().Where(rollout.ID(first.ID)).SetState(rollout.StateCompleted).ExecX(sys)
		if c.Rollout.GetX(sys, first.ID).Active {
			t.Fatal("a completed rollout is still active")
		}
		second, err := create()
		if err != nil {
			t.Fatalf("a rollout after the first completed: %v", err)
		}
		// The flag follows the state, not the caller.
		if c.Rollout.UpdateOne(second).SetActive(false).SaveX(sys).Active != true {
			t.Fatal("a running rollout was marked inactive by hand")
		}
		c.Rollout.UpdateOne(second).SetState(rollout.StateCancelled).ExecX(sys)
		if _, err := create(); err != nil {
			t.Fatalf("a rollout after the second was cancelled: %v", err)
		}
		if _, err := c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").SetState(rollout.StateCompleted).
			SetPercentage(101).Save(sys); err == nil {
			t.Error("a percentage of 101 was stored")
		}
		if _, err := c.Rollout.Create().SetReleaseID("rel_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R").SetCreatedBy("usr_admin").
			SetState(rollout.StateCompleted).Save(sys); err == nil {
			t.Error("a rollout of an unknown release was stored")
		}
		a, _ := seed(t, c)
		if _, err := c.Rollout.Query().All(orgCtx(t, a.org)); err == nil {
			t.Error("an org's scope read the rollouts")
		}
	})
}

// TestRolloutTarget_OnePerAgent: an agent has one row per rollout, and its bucket stays in 0–99.
func TestRolloutTarget_OnePerAgent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		sys := systemCtx(t)
		rel, err := newRelease(sys, c, "0.2.0")
		if err != nil {
			t.Fatal(err)
		}
		ro := c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").SaveX(sys)
		target := func(agent string, bucket int) error {
			return c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(agent).SetAgentKind("connector").
				SetBucket(bucket).Exec(sys)
		}
		agent := ids.New("con")
		if err := target(agent, store.RolloutBucket(agent)); err != nil {
			t.Fatal(err)
		}
		if err := target(agent, store.RolloutBucket(agent)); !store.IsUniqueViolation(err) {
			t.Fatalf("a second row for the same agent: %v, want a unique violation", err)
		}
		for _, b := range []int{-1, 100} {
			if err := target(ids.New("con"), b); err == nil {
				t.Errorf("bucket %d was stored", b)
			}
		}
		if err := c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(ids.New("gw")).SetAgentKind("controller").
			SetBucket(1).Exec(sys); err == nil {
			t.Errorf("agent kind %q was stored", "controller")
		}
	})
}
