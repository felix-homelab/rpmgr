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
)

// RecordRelease records a verified release in the releases table: a new version, or a manifest
// with a higher seq than the recorded one, which replaces it (docs/06-data-model.md, "Webhooks and
// releases (Phase 2)"); a replaced manifest clears the mark that the mirror holds the release.
// mirrored, if set, is when the mirror came to hold every artifact with this manifest. When the
// mark changes for the target of a running or paused rollout, the write is a configuration
// transaction, so the agents' snapshots compile again and offer the release only while the mirror
// holds it (D125). It returns the release's row as it is now. ctx carries the system scope.
func RecordRelease(ctx context.Context, db *DB, s *release.Signed, source entrelease.Source, mirrored *time.Time) (*ent.Release, error) {
	m := s.Manifest
	if m.Seq > math.MaxInt64 {
		return nil, fmt.Errorf("release: the manifest of %s has seq %d, beyond what the database holds", m.Version, m.Seq)
	}
	seq := int64(m.Seq) //nolint:gosec // G115: checked above
	var out *ent.Release
	write := func(fn func(tx *ent.Tx) error) error { return WriteTx(ctx, db, fn) }
	if row, err := db.Client().Release.Query().Where(entrelease.Version(m.Version)).Only(ctx); err == nil {
		was := row.MirroredAt != nil
		is := mirrored != nil || (was && seq <= row.ManifestSeq)
		target, err := db.Client().Rollout.Query().Where(rollout.Active(true), rollout.ReleaseID(row.ID)).Exist(ctx)
		if err != nil {
			return nil, err
		}
		if was != is && target {
			write = func(fn func(tx *ent.Tx) error) error {
				_, err := ConfigTx(ctx, db, func(tx *ent.Tx) ([]string, error) { return []string{row.ID}, fn(tx) })
				return err
			}
		}
	} else if !ent.IsNotFound(err) {
		return nil, err
	}
	err := write(func(tx *ent.Tx) error {
		row, err := tx.Release.Query().Where(entrelease.Version(m.Version)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			out, err = tx.Release.Create().SetVersion(m.Version).SetChannel(entrelease.Channel(m.Channel)).SetManifestSeq(seq).
				SetManifest(s.ManifestJSON).SetSignature(s.ManifestSig).SetSigningKeyStatement(s.Statement).
				SetStatementSignature(s.StatementSig).SetSource(source).SetNillableMirroredAt(mirrored).Save(ctx)
			return err
		case err != nil:
			return err
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
		out, err = u.Save(ctx)
		return err
	})
	return out, err
}
