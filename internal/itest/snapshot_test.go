// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
)

// orgResources compiles one resource per org, a stand-in for the resource kinds of later slices.
func orgResources(ctx context.Context, tx *ent.Tx, _ snapshot.Agent) ([]*agentv1.Resource, error) {
	orgs, err := tx.Org.Query().Order(org.ByID()).All(ctx)
	if err != nil {
		return nil, err
	}
	var rs []*agentv1.Resource
	for _, o := range orgs {
		rs = append(rs, &agentv1.Resource{Id: o.ID, Kind: &agentv1.Resource_Reference{
			Reference: &agentv1.ResourceReference{Size: uint64(len(o.Name))}}})
	}
	return rs, nil
}

// recorder is an Applier that records the revisions it applied and what changed.
type recorder struct {
	mu      sync.Mutex
	seqs    []uint64
	changes []agent.Changes
}

func (r *recorder) Validate(*agentv1.Snapshot) []*agentv1.SnapshotError { return nil }

func (r *recorder) Apply(_ context.Context, snap *agentv1.Snapshot, c agent.Changes) []*agentv1.ResourceStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seqs = append(r.seqs, snap.GetRevision().GetSeq())
	r.changes = append(r.changes, c)
	return nil
}

func (r *recorder) applied() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seqs)
}

// TestSnapshots_EndToEnd: an enrolled agent receives, verifies, applies and acknowledges its
// snapshot; a new revision reaches it with unchanged resources kept; after a restart it runs its
// last-known-good copy before any session, also with the controller down, and a controller that
// sees the same snapshot in Hello sends none.
func TestSnapshots_EndToEnd(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	id := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	state := filepath.Join(dir, "state")
	run := func(rec *recorder) context.CancelFunc {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
				Applier: rec, Backoff: fast(), Logger: c.Logs.Logger()})
			close(done)
		}()
		return func() { cancel(); <-done }
	}
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	status := func() controller.ApplyState {
		st, err := c.DB.Client().AgentState.Get(c.Sys, id.AgentID)
		if err != nil {
			return ""
		}
		return controller.ApplyStatus(st, time.Now())
	}

	rec := &recorder{}
	stop := run(rec)
	waitFor(t, "the first snapshot", func() bool { return len(rec.applied()) == 1 })
	waitFor(t, "apply status applied", func() bool { return status() == controller.ApplyApplied })

	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		o, err := tx.Org.Create().SetName("org-b").SetSlug("org-b").Save(c.Sys)
		return []string{o.ID}, err
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the second snapshot", func() bool { return len(rec.applied()) == 2 })
	rec.mu.Lock()
	second := rec.changes[1]
	rec.mu.Unlock()
	if !slices.Equal(second.Unchanged, []string{c.Org}) || len(second.Added) != 1 || len(second.Changed) != 0 {
		t.Fatalf("changes of an unrelated revision: %+v", second)
	}
	waitFor(t, "apply status applied", func() bool { return status() == controller.ApplyApplied })
	stop()

	// A restart: the last-known-good copy runs at once; the controller sends nothing new.
	sent := c.DB.Client().CompiledSnapshot.Query().CountX(c.Sys)
	rec2 := &recorder{}
	stop = run(rec2)
	waitFor(t, "the last-known-good snapshot", func() bool { return len(rec2.applied()) == 1 })
	waitFor(t, "a new session", func() bool { return slices.Contains(c.Sessions.Connected(), id.AgentID) })
	time.Sleep(300 * time.Millisecond)
	if got := rec2.applied(); len(got) != 1 || got[0] != rec.applied()[1] {
		t.Fatalf("after a restart the agent applied %v, want only the last-known-good revision %d", got, rec.applied()[1])
	}
	if n := c.DB.Client().CompiledSnapshot.Query().CountX(c.Sys); n != sent || status() != controller.ApplyApplied {
		t.Fatalf("%d snapshots sent before the restart, %d after, status %s", sent, n, status())
	}
	stop()

	// With the controller down the agent still starts from its copy.
	c.Stop()
	rec3 := &recorder{}
	stop = run(rec3)
	defer stop()
	waitFor(t, "the last-known-good snapshot without a controller", func() bool { return len(rec3.applied()) == 1 })
}
