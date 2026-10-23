// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	entrelease "github.com/felix-homelab/rpmgr/internal/store/ent/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func signedRelease(version string, seq uint64) *release.Signed {
	m := fmt.Sprintf(`{"seq":%d,"version":%q}`, seq, version)
	return &release.Signed{Manifest: &release.Manifest{Seq: seq, Version: version, Channel: release.Stable},
		ManifestJSON: []byte(m), ManifestSig: []byte("sig"), Statement: []byte(`{"statement":1}`), StatementSig: []byte("sig")}
}

// TestRecordRelease (D125): a new version is stored; a manifest with a higher seq replaces the
// recorded one and clears the mark that the mirror holds the release, one with a lower or equal
// seq changes nothing but the mark; a seq beyond the database's range is refused. While a running
// or paused rollout targets the release, a change of the mark is a configuration change, so the
// agents' snapshots compile again; a write that leaves the mark as it was, or of a release no
// active rollout targets, is not.
func TestRecordRelease(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		c := db.Client()
		revisions := func() int { return c.ConfigRevision.Query().CountX(sys) }
		at := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
		record := func(version string, seq uint64, mirrored *time.Time) *ent.Release {
			t.Helper()
			row, err := store.RecordRelease(sys, db, signedRelease(version, seq), entrelease.SourceUpload, mirrored)
			if err != nil {
				t.Fatalf("record %s seq %d: %v", version, seq, err)
			}
			return row
		}

		start := revisions()
		row := record("0.2.0", 5, nil)
		if row.ManifestSeq != 5 || row.MirroredAt != nil || row.Source != entrelease.SourceUpload {
			t.Fatalf("a new release: %+v", row)
		}
		// Without an active rollout, the mark changes without a revision.
		if row = record("0.2.0", 5, &at); row.MirroredAt == nil || revisions() != start {
			t.Fatalf("mirrored without a rollout: %v, %d revisions, want %d", row.MirroredAt, revisions(), start)
		}
		if row = record("0.2.0", 6, nil); row.ManifestSeq != 6 || row.MirroredAt != nil || revisions() != start {
			t.Fatalf("a newer manifest without a rollout: seq %d mirrored %v, %d revisions", row.ManifestSeq, row.MirroredAt, revisions())
		}
		if row = record("0.2.0", 4, nil); row.ManifestSeq != 6 || string(row.Manifest) != `{"seq":6,"version":"0.2.0"}` {
			t.Fatalf("an older manifest replaced the recorded one: seq %d", row.ManifestSeq)
		}

		ro := c.Rollout.Create().SetReleaseID(row.ID).SetCreatedBy("usr_admin").SaveX(sys)
		// The mirror comes to hold the target: a revision naming the release.
		if row = record("0.2.0", 6, &at); row.MirroredAt == nil || revisions() != start+1 {
			t.Fatalf("the target mirrored: %v, %d revisions, want %d", row.MirroredAt, revisions(), start+1)
		}
		last := c.ConfigRevision.Query().Order(ent.Desc(configrevision.FieldID)).FirstX(sys)
		if len(last.ChangedResources) != 1 || last.ChangedResources[0] != row.ID {
			t.Errorf("the revision names %v, want the release %s", last.ChangedResources, row.ID)
		}
		// Mirrored again, or an older manifest: the mark stays, no revision.
		record("0.2.0", 6, &at)
		if row = record("0.2.0", 3, nil); row.MirroredAt == nil || revisions() != start+1 {
			t.Fatalf("no change of the mark: %v, %d revisions, want %d", row.MirroredAt, revisions(), start+1)
		}
		// A newer manifest of the paused target clears the mark: a revision.
		c.Rollout.UpdateOne(ro).SetState(rollout.StatePaused).ExecX(sys)
		if row = record("0.2.0", 7, nil); row.MirroredAt != nil || row.ManifestSeq != 7 || revisions() != start+2 {
			t.Fatalf("a newer manifest of the target: %v seq %d, %d revisions, want %d", row.MirroredAt, row.ManifestSeq, revisions(), start+2)
		}
		// Once the rollout is over, the mark changes without a revision again.
		c.Rollout.UpdateOne(ro).SetState(rollout.StateCancelled).ExecX(sys)
		if row = record("0.2.0", 7, &at); row.MirroredAt == nil || revisions() != start+2 {
			t.Fatalf("after the rollout: %v, %d revisions, want %d", row.MirroredAt, revisions(), start+2)
		}

		if _, err := store.RecordRelease(sys, db, signedRelease("0.3.0", math.MaxInt64+1), entrelease.SourceCheck, nil); err == nil {
			t.Error("a seq beyond the database's range was recorded")
		}
	})
}
