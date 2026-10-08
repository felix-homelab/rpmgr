// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/authz"
)

// WaitHeader asks a write to answer once its revision is applied, rejected or timed out, waiting
// at most the duration it names and MaxWait (docs/07-api.md, "Writes and apply status").
const WaitHeader = "Rpmgr-Wait-Applied"

// The wait for a write's revision.
const (
	MaxWait   = 30 * time.Second
	waitEvery = 250 * time.Millisecond
)

// ApplyStatusFunc derives the apply status of a revision over an org's agents.
type ApplyStatusFunc func(ctx context.Context, orgID string, rev *rpmgrv1.Revision) (*rpmgrv1.ApplyStatus, error)

// applyStatus fills the apply_status of a write's answer that carries a revision, after waiting
// for a final state if the request asks to. A status it cannot derive is left out: the write
// itself succeeded.
func (s *Server) applyStatus(ctx context.Context, header http.Header, resp connect.AnyResponse) {
	if s.o.ApplyStatus == nil || resp == nil {
		return
	}
	msg, ok := resp.Any().(proto.Message)
	if !ok {
		return
	}
	m := msg.ProtoReflect()
	revFD, statusFD := m.Descriptor().Fields().ByName("revision"), m.Descriptor().Fields().ByName("apply_status")
	if revFD == nil || statusFD == nil || !m.Has(revFD) {
		return
	}
	rev, ok := m.Get(revFD).Message().Interface().(*rpmgrv1.Revision)
	scope, inOrg := authz.FromContext(ctx)
	if !ok || !inOrg || scope.OrgID() == "" {
		return
	}
	wait, _ := time.ParseDuration(header.Get(WaitHeader))
	// Real time, not the injected clock: the wait is for agents, which answer in real time.
	timer := time.NewTimer(min(max(wait, 0), MaxWait))
	defer timer.Stop()
	for {
		st, err := s.o.ApplyStatus(ctx, scope.OrgID(), rev)
		if err != nil {
			s.o.Logger.Warn("cannot derive the apply status of a write", "error", err)
			return
		}
		if st.GetState() != rpmgrv1.ApplyState_APPLY_STATE_PENDING || wait <= 0 {
			m.Set(statusFD, protoreflect.ValueOfMessage(st.ProtoReflect()))
			return
		}
		select {
		case <-timer.C:
			m.Set(statusFD, protoreflect.ValueOfMessage(st.ProtoReflect()))
			return
		case <-ctx.Done():
			m.Set(statusFD, protoreflect.ValueOfMessage(st.ProtoReflect()))
			return
		case <-time.After(waitEvery):
		}
	}
}
