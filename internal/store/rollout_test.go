// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
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

// queue runs QueueRolloutTargets in its own transaction.
func queue(ctx context.Context, c *ent.Client, rolloutID string, agents ...string) ([]*ent.RolloutTarget, error) {
	tx, err := c.Tx(ctx)
	if err != nil {
		return nil, err
	}
	in := make([]store.RolloutAgent, 0, len(agents))
	for _, a := range agents {
		kind := rollouttarget.AgentKindConnector
		if strings.HasPrefix(a, "gw_") {
			kind = rollouttarget.AgentKindGateway
		}
		in = append(in, store.RolloutAgent{ID: a, Kind: kind, VersionBefore: "0.1.0"})
	}
	out, err := store.QueueRolloutTargets(ctx, tx, rolloutID, in)
	if err != nil {
		return nil, errors.Join(err, tx.Rollback())
	}
	return out, tx.Commit()
}

// TestQueueRolloutTargets (D129): an easy rollout's queue keeps the order agents were added in,
// from position 1; agents join a running or paused one at the end; an agent already queued keeps
// its place; a staged rollout and an ended one take no agents.
func TestQueueRolloutTargets(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		sys := systemCtx(t)
		rel, err := newRelease(sys, c, "0.2.0")
		if err != nil {
			t.Fatal(err)
		}
		staged := c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").SaveX(sys)
		if staged.Mode != rollout.ModeAdvanced {
			t.Fatalf("a rollout created without a mode is %q, want advanced", staged.Mode)
		}
		con1, con2, gw1, con3 := ids.New("con"), ids.New("con"), ids.New("gw"), ids.New("con")
		if _, err := queue(sys, c, staged.ID, con1); !errors.Is(err, store.ErrRolloutNotEasy) {
			t.Fatalf("queueing on a staged rollout: %v, want ErrRolloutNotEasy", err)
		}
		c.Rollout.UpdateOne(staged).SetState(rollout.StateCancelled).ExecX(sys)
		if _, err := queue(sys, c, staged.ID, con1); !errors.Is(err, store.ErrRolloutNotEasy) {
			t.Fatalf("queueing on a cancelled staged rollout: %v, want ErrRolloutNotEasy", err)
		}
		if _, err := queue(sys, c, "rol_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R", con1); !ent.IsNotFound(err) {
			t.Fatalf("queueing on an unknown rollout: %v, want not found", err)
		}

		easy := c.Rollout.Create().SetReleaseID(rel.ID).SetMode(rollout.ModeEasy).SetCreatedBy("usr_admin").SaveX(sys)
		got, err := queue(sys, c, easy.ID, con2, con1, gw1)
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range []string{con2, con1, gw1} {
			g := got[i]
			if g.AgentID != want || pos(g) != i+1 || g.Canary || g.Bucket != store.RolloutBucket(want) ||
				g.VersionBefore != "0.1.0" || g.State != rollouttarget.StatePending {
				t.Errorf("target %d: %+v, want agent %s at position %d", i, g, want, i+1)
			}
		}
		if got[2].AgentKind != rollouttarget.AgentKindGateway {
			t.Errorf("the gateway's target has kind %q", got[2].AgentKind)
		}

		// A paused rollout takes agents too; one already queued keeps its place, also when named twice.
		c.Rollout.UpdateOne(easy).SetState(rollout.StatePaused).ExecX(sys)
		again, err := queue(sys, c, easy.ID, con3, con1, con3)
		if err != nil {
			t.Fatal(err)
		}
		if pos(again[0]) != 4 || again[1].ID != got[1].ID || pos(again[1]) != 2 || again[2].ID != again[0].ID {
			t.Errorf("queueing con3, con1, con3: positions %d, %d, %d", pos(again[0]), pos(again[1]), pos(again[2]))
		}
		var order []string
		for _, r := range c.RolloutTarget.Query().Where(rollouttarget.RolloutID(easy.ID)).
			Order(ent.Asc(rollouttarget.FieldPosition)).AllX(sys) {
			order = append(order, r.AgentID)
		}
		if want := []string{con2, con1, gw1, con3}; !slices.Equal(order, want) {
			t.Errorf("the queue is %v, want %v", order, want)
		}
		if _, err := queue(sys, c, easy.ID); err != nil {
			t.Errorf("queueing no agent: %v", err)
		}

		for _, end := range []rollout.State{rollout.StateCompleted, rollout.StateCancelled} {
			c.Rollout.UpdateOneID(easy.ID).SetState(end).ExecX(sys)
			if _, err := queue(sys, c, easy.ID, ids.New("con")); !errors.Is(err, store.ErrRolloutEnded) {
				t.Errorf("queueing on a %s rollout: %v, want ErrRolloutEnded", end, err)
			}
		}
		if n := c.RolloutTarget.Query().Where(rollouttarget.RolloutID(easy.ID)).CountX(sys); n != 4 {
			t.Errorf("the ended rollout holds %d targets, want 4", n)
		}
	})
}

// pos is a target's place in the queue, 0 for none.
func pos(t *ent.RolloutTarget) int {
	if t.Position == nil {
		return 0
	}
	return *t.Position
}

// TestRolloutTarget_PositionUnique: a place in an easy rollout's queue is taken once, while the
// targets of a staged rollout have none; a position is at least 1.
func TestRolloutTarget_PositionUnique(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		sys := systemCtx(t)
		rel, err := newRelease(sys, c, "0.2.0")
		if err != nil {
			t.Fatal(err)
		}
		ro := c.Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_admin").SaveX(sys)
		target := func(position int) error {
			id := ids.New("con")
			create := c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(id).SetAgentKind("connector").SetBucket(store.RolloutBucket(id))
			if position != 0 {
				create.SetPosition(position)
			}
			return create.Exec(sys)
		}
		for i := range 2 {
			if err := target(0); err != nil {
				t.Fatalf("staged target %d without a position: %v", i, err)
			}
		}
		if err := target(1); err != nil {
			t.Fatal(err)
		}
		if err := target(1); !store.IsUniqueViolation(err) {
			t.Errorf("a second target at position 1: %v, want a unique violation", err)
		}
		if err := target(-1); err == nil {
			t.Error("position -1 was stored")
		}
		if err := c.RolloutTarget.Create().SetRolloutID(ro.ID).SetAgentID(ids.New("con")).SetAgentKind("connector").
			SetBucket(1).SetPosition(0).Exec(sys); err == nil {
			t.Error("position 0 was stored")
		}
	})
}
