// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollout"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// ReleaseOffer is the controller's Compiler.Offer (docs/04-security.md, "Over-the-air updates",
// step 3): the target release of the running rollout, for an agent whose rollout target is
// offered. Other agents, and every agent while the rollout is paused, get none.
func ReleaseOffer(ctx context.Context, tx *ent.Tx, a Agent) (*agentv1.ReleaseOffer, error) {
	t, err := tx.RolloutTarget.Query().
		Where(rollouttarget.AgentID(a.Identity.ID), rollouttarget.StateEQ(rollouttarget.StateOffered),
			rollouttarget.HasRolloutWith(rollout.StateEQ(rollout.StateRunning))).
		WithRollout(func(q *ent.RolloutQuery) { q.WithRelease() }).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Offer(t.Edges.Rollout.Edges.Release)
}

// Offer describes a recorded release as an offer: its version, its manifest's seq, and each of
// its files under /dl/<version>/ with size and SHA-256, the signed files from their recorded
// bytes and the artifacts from the manifest.
func Offer(rel *ent.Release) (*agentv1.ReleaseOffer, error) {
	var m release.Manifest
	if err := json.Unmarshal(rel.Manifest, &m); err != nil {
		return nil, fmt.Errorf("snapshot: the recorded manifest of %s: %w", rel.Version, err)
	}
	if m.Version != rel.Version {
		return nil, fmt.Errorf("snapshot: release %s records the manifest of %s", rel.Version, m.Version)
	}
	o := &agentv1.ReleaseOffer{Version: m.Version, Seq: m.Seq}
	signed := map[string][]byte{release.StatementFile: rel.SigningKeyStatement, release.StatementSigFile: rel.StatementSignature,
		release.ManifestFile: rel.Manifest, release.ManifestSigFile: rel.Signature}
	for _, name := range release.MetaFiles {
		sum := sha256.Sum256(signed[name])
		o.Files = append(o.Files, &agentv1.ReleaseFile{Name: name, Size: uint64(len(signed[name])), Sha256: sum[:]})
	}
	for _, a := range m.Artifacts {
		sum, err := hex.DecodeString(a.SHA256)
		if err != nil || len(sum) != sha256.Size || a.Size < 0 {
			return nil, fmt.Errorf("snapshot: the manifest of %s has a malformed artifact", m.Version)
		}
		o.Files = append(o.Files, &agentv1.ReleaseFile{Name: release.ArtifactName(m.Version, a), Size: uint64(a.Size), Sha256: sum})
	}
	return o, nil
}
