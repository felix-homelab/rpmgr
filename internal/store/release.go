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
)

// RecordRelease records a verified release in the releases table: a new version, or a manifest
// with a higher seq than the recorded one, which replaces it (docs/06-data-model.md, "Webhooks and
// releases (Phase 2)"). mirrored, if set, is when the mirror came to hold every artifact. It
// returns the release's row as it is now. ctx carries the system scope.
func RecordRelease(ctx context.Context, db *DB, s *release.Signed, source entrelease.Source, mirrored *time.Time) (*ent.Release, error) {
	m := s.Manifest
	if m.Seq > math.MaxInt64 {
		return nil, fmt.Errorf("release: the manifest of %s has seq %d, beyond what the database holds", m.Version, m.Seq)
	}
	seq := int64(m.Seq) //nolint:gosec // G115: checked above
	var out *ent.Release
	err := WriteTx(ctx, db, func(tx *ent.Tx) error {
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
		if mirrored != nil {
			u.SetMirroredAt(*mirrored)
		}
		out, err = u.Save(ctx)
		return err
	})
	return out, err
}
