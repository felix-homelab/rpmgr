// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/compiledsnapshot"
)

// errNoItem is the answer for every item the caller may not fetch, whether or not it exists.
var errNoItem = status.Error(codes.NotFound, "no such item in your snapshots")

// FetchResource returns a large item of the caller's snapshots by its content hash
// (docs/03-connections.md, "Control session"): only an item that one of the caller's recent
// snapshots names with that hash, so an agent never fetches another agent's item.
func (s *Sessions) FetchResource(ctx context.Context, req *agentv1.FetchResourceRequest) (*agentv1.FetchResourceResponse, error) {
	a, ok := AgentFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "a client certificate is required")
	}
	if s.sealer == nil {
		return nil, errNoItem
	}
	var content []byte
	err := store.ReadTx(s.sys, s.db, func(tx *ent.Tx, _ store.Revision) error {
		snaps, err := tx.CompiledSnapshot.Query().Where(compiledsnapshot.AgentID(a.Identity.ID)).
			Order(ent.Desc(compiledsnapshot.FieldID)).Limit(keepCompiled).All(s.sys)
		if err != nil {
			return err
		}
		if !names(snaps, req.GetId(), req.GetHash()) {
			return errNoItem
		}
		c, err := tx.Certificate.Get(s.sys, req.GetId())
		if ent.IsNotFound(err) || err == nil && !bytes.Equal(c.ContentSha256, req.GetHash()) {
			return errNoItem
		}
		if err != nil {
			return err
		}
		content, err = certs.Item(c, s.sealer)
		return err
	})
	switch {
	case errors.Is(err, errNoItem):
		return nil, errNoItem
	case err != nil:
		s.log.Error("cannot serve a snapshot item", "agent", a.Identity.ID, "item", req.GetId(), "error", err)
		return nil, status.Error(codes.Unavailable, "the item cannot be read now")
	}
	return &agentv1.FetchResourceResponse{Content: content}, nil
}

// names reports whether one of the snapshots has an item with the ID and content hash.
func names(snaps []*ent.CompiledSnapshot, id string, hash []byte) bool {
	for _, cs := range snaps {
		var snap agentv1.Snapshot
		if proto.Unmarshal(cs.Payload, &snap) != nil {
			continue
		}
		for _, r := range snap.GetResources() {
			if r.GetId() == id && r.GetGatewayCertificate() != nil && bytes.Equal(r.GetGatewayCertificate().GetContentSha256(), hash) {
				return true
			}
		}
	}
	return false
}
