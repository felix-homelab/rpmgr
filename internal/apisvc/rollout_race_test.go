// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"sync"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestRollouts_ConcurrentChanges: changes of one rollout at the same time never lose one, on either
// dialect (READ COMMITTED on PostgreSQL): a pause and a cancel at once leave it cancelled, the
// pause refused if it came second; of two advances under one etag exactly one succeeds, the other
// is ETAG_MISMATCH. Each change makes a revision, so the agents' snapshots compile again.
func TestRollouts_ConcurrentChanges(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		r := &apisvc.Releases{DB: db, Sys: sys, Version: "1.5.0"}
		rel := db.Client().Release.Create().SetVersion("1.4.2").SetChannel("stable").SetManifestSeq(1).SetManifest([]byte("m")).
			SetSignature([]byte("s")).SetSigningKeyStatement([]byte("k")).SetStatementSignature([]byte("t")).SetSource("upload").SaveX(sys)
		ctx := context.Background()
		before := db.Client().ConfigRevision.Query().CountX(sys)
		const rounds = 15
		for i := 0; i < rounds; i++ {
			ro := db.Client().Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_test").SaveX(sys)
			var pauseErr, cancelErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				_, pauseErr = r.PauseRollout(ctx, connect.NewRequest(&rpmgrv1.PauseRolloutRequest{RolloutId: ro.ID}))
			})
			wg.Go(func() {
				_, cancelErr = r.CancelRollout(ctx, connect.NewRequest(&rpmgrv1.CancelRolloutRequest{RolloutId: ro.ID}))
			})
			wg.Wait()
			if cancelErr != nil || (pauseErr != nil && reason(pauseErr) != apisvc.ReasonRolloutState) {
				t.Fatalf("round %d: pause %v, cancel %v", i, pauseErr, cancelErr)
			}
			if got := db.Client().Rollout.GetX(sys, ro.ID); got.State != rollout.StateCancelled || got.Active {
				t.Fatalf("round %d: a pause and a cancel at once left the rollout %s", i, got.State)
			}

			ro = db.Client().Rollout.Create().SetReleaseID(rel.ID).SetCreatedBy("usr_test").SaveX(sys)
			errs := make([]error, 2)
			for j, pct := range []int32{10, 20} {
				wg.Go(func() {
					_, errs[j] = r.AdvanceRollout(ctx, connect.NewRequest(&rpmgrv1.AdvanceRolloutRequest{RolloutId: ro.ID, Etag: "1",
						Next: &rpmgrv1.AdvanceRolloutRequest_Percentage{Percentage: pct}}))
				})
			}
			wg.Wait()
			if (errs[0] == nil) == (errs[1] == nil) || (reason(errs[0]) != api.ReasonEtagMismatch && reason(errs[1]) != api.ReasonEtagMismatch) {
				t.Fatalf("round %d: two advances under one etag: %v", i, errs)
			}
			if got := db.Client().Rollout.GetX(sys, ro.ID); got.Version != 2 {
				t.Fatalf("round %d: the rollout is at version %d after one advance", i, got.Version)
			}
			db.Client().Rollout.UpdateOneID(ro.ID).SetState(rollout.StateCancelled).ExecX(sys)
		}
		// pause or not, one cancel and one advance per round
		if n := db.Client().ConfigRevision.Query().CountX(sys) - before; n < 2*rounds {
			t.Errorf("%d revisions for %d rounds of changes", n, rounds)
		}
	})
}
