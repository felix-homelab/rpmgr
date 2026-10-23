// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	entrelease "github.com/felix-homelab/rpmgr/internal/store/ent/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// RecordRelease records a verified release in the releases table: a new version, or a manifest
// with a higher seq than the recorded one, which replaces it (docs/06-data-model.md, "Webhooks and
// releases (Phase 2)"); a replaced manifest clears the mark that the mirror holds the release.
// mirrored, if set, is when the mirror came to hold every artifact with this manifest. When the
// mark changes for the target of a running or paused rollout, the write records a revision, so
// the agents' snapshots compile again and offer the release only while the mirror holds it, and
// the targets the rollout offered it to wait for their agents afresh from then on (D125). It
// returns the release's row as it is now. ctx carries the system scope.
func RecordRelease(ctx context.Context, db *DB, s *release.Signed, source entrelease.Source, mirrored *time.Time) (*ent.Release, error) {
	m := s.Manifest
	if m.Seq > math.MaxInt64 {
		return nil, fmt.Errorf("release: the manifest of %s has seq %d, beyond what the database holds", m.Version, m.Seq)
	}
	seq := int64(m.Seq) //nolint:gosec // G115: checked above
	var out *ent.Release
	err := configTxIfChanged(ctx, db, func(tx *ent.Tx) ([]string, error) {
		row, err := tx.Release.Query().Where(entrelease.Version(m.Version)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			// No rollout targets a release before it is recorded.
			out, err = tx.Release.Create().SetVersion(m.Version).SetChannel(entrelease.Channel(m.Channel)).SetManifestSeq(seq).
				SetManifest(s.ManifestJSON).SetSignature(s.ManifestSig).SetSigningKeyStatement(s.Statement).
				SetStatementSignature(s.StatementSig).SetSource(source).SetNillableMirroredAt(mirrored).Save(ctx)
			return nil, err
		case err != nil:
			return nil, err
		}
		u := row.Update()
		if seq > row.ManifestSeq {
			u.SetChannel(entrelease.Channel(m.Channel)).SetManifestSeq(seq).SetManifest(s.ManifestJSON).
				SetSignature(s.ManifestSig).SetSigningKeyStatement(s.Statement).SetStatementSignature(s.StatementSig).SetSource(source)
		}
		switch {
		case mirrored != nil:
			u.SetMirroredAt(*mirrored)
		case seq > row.ManifestSeq:
			u.ClearMirroredAt() // the mirror holds the older manifest until it syncs the version again (D125)
		}
		if out, err = u.Save(ctx); err != nil {
			return nil, err
		}
		if (row.MirroredAt != nil) == (out.MirroredAt != nil) {
			return nil, nil
		}
		ro, err := tx.Rollout.Query().Where(rollout.Active(true), rollout.ReleaseID(row.ID)).Only(ctx)
		if ent.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		// A target offered the release waits for its agent from now on: the time the mirror did
		// not hold the release does not count towards a stall.
		at := time.Now()
		if mirrored != nil {
			at = *mirrored
		}
		err = tx.RolloutTarget.Update().Where(rollouttarget.RolloutID(ro.ID),
			rollouttarget.StateIn(rollouttarget.StateOffered, rollouttarget.StateStaged)).SetUpdatedAt(at).Exec(ctx)
		return []string{row.ID}, err
	})
	return out, err
}
