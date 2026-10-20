// SPDX-License-Identifier: Apache-2.0

// Package snapshot compiles the snapshots the controller sends its agents
// (docs/03-connections.md, "Configuration reconciliation", "Revisions and ordering"). Compilation
// is a deterministic function of the database at one revision, the agent and its capabilities, so
// every replica compiles the same bytes for the same agent and revision; snapshots travel as the
// signed bytes (R14), which package snapsig signs and agents verify.
package snapshot

import (
	"context"
	"fmt"
	"slices"
	"strings"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapsig"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Agent is what a snapshot is compiled for.
type Agent struct {
	Identity     pki.Identity
	Capabilities []string
}

// Has reports whether the agent announced capability c.
func (a Agent) Has(c string) bool { return slices.Contains(a.Capabilities, c) }

// Source adds the resources of one kind to a snapshot. It reads only through tx, the read snapshot
// of the revision, and must be deterministic.
type Source func(ctx context.Context, tx *ent.Tx, a Agent) ([]*agentv1.Resource, error)

// Compiler compiles snapshots from its sources, one per resource kind.
type Compiler struct {
	Sources []Source
	// Endpoints, if set, returns the controller endpoints at the revision tx reads, in the order
	// agents try them. Like a Source it reads only through tx, so that every replica compiles the
	// same snapshot.
	Endpoints func(ctx context.Context, tx *ent.Tx) ([]string, error)
}

// Compile reads one consistent snapshot of the database and returns the agent's snapshot at its
// revision: the resources of every source, sorted by ID, each with its content hash.
func (c *Compiler) Compile(ctx context.Context, db *store.DB, a Agent) (*agentv1.Snapshot, error) {
	var snap *agentv1.Snapshot
	err := store.ReadTx(ctx, db, func(tx *ent.Tx, rev store.Revision) error {
		var err error
		snap, err = c.compile(ctx, tx, rev, a)
		return err
	})
	return snap, err
}

func (c *Compiler) compile(ctx context.Context, tx *ent.Tx, rev store.Revision, a Agent) (*agentv1.Snapshot, error) {
	snap := &agentv1.Snapshot{
		Revision: &agentv1.Revision{DbEpoch: rev.DBEpoch, Seq: uint64(rev.Seq)}, //nolint:gosec // G115: revisions are positive
		Agent:    a.Identity.String(),
	}
	if c.Endpoints != nil {
		eps, err := c.Endpoints(ctx, tx)
		if err != nil {
			return nil, err
		}
		snap.ControllerEndpoints = slices.Clone(eps)
	}
	for _, src := range c.Sources {
		rs, err := src(ctx, tx, a)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			h, err := snapsig.ResourceHash(r)
			if err != nil {
				return nil, err
			}
			r.Hash = h
			snap.Resources = append(snap.Resources, r)
		}
	}
	slices.SortFunc(snap.Resources, func(x, y *agentv1.Resource) int { return strings.Compare(x.Id, y.Id) })
	for i := 1; i < len(snap.Resources); i++ {
		if snap.Resources[i].Id == snap.Resources[i-1].Id {
			return nil, fmt.Errorf("snapshot: resource %s twice", snap.Resources[i].Id)
		}
	}
	return snap, nil
}
