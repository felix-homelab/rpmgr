// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
)

// ErrNotConnected is returned for an operation on an agent without a control session here.
var ErrNotConnected = errors.New("controller: the agent has no control session on this replica")

// op is an operation sent to an agent and waiting for its OpResult.
type op struct {
	agent  string
	result chan *agentv1.OpResult
}

// Op sends an operation to an agent's current control session and waits for its OpResult
// (docs/03-connections.md, "Service sketch"); msg makes the message from the operation's ID. An
// OpResult with an error, a session that ends, or ctx ending fails it.
func (s *Sessions) Op(ctx context.Context, agentID string, msg func(opID string) *agentv1.ControllerMessage) error {
	r, err := s.ask(ctx, agentID, "", msg)
	if err == nil && r.GetError() != "" {
		err = fmt.Errorf("controller: agent %s: %s", agentID, r.GetError())
	}
	return err
}

// ProbeTarget implements apisvc.Prober: it asks a connector for the certificate a target presents
// (ADR-0018) and returns it, DER.
func (s *Sessions) ProbeTarget(ctx context.Context, connectorID string, p *agentv1.ProbeTarget) ([]byte, error) {
	r, err := s.ask(ctx, connectorID, agentproto.CapProbeTarget, func(opID string) *agentv1.ControllerMessage {
		q := proto.Clone(p).(*agentv1.ProbeTarget)
		q.OpId = opID
		return &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_ProbeTarget{ProbeTarget: q}}
	})
	switch {
	case errors.Is(err, ErrNotConnected):
		return nil, apisvc.ErrProbeNotConnected
	case errors.Is(err, errNoCapability):
		return nil, apisvc.ErrProbeUnsupported
	case err != nil:
		return nil, err
	case r.GetError() != "":
		return nil, &apisvc.ProbeFailed{Message: r.GetError()}
	}
	return r.GetCertificate(), nil
}

// errNoCapability is an operation the agent's version does not support.
var errNoCapability = errors.New("controller: the agent does not support the operation")

// ask sends an operation to an agent's current control session, if its Hello announced the
// capability need ("" for none), and returns its OpResult.
func (s *Sessions) ask(ctx context.Context, agentID, need string, msg func(opID string) *agentv1.ControllerMessage) (*agentv1.OpResult, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(b)
	o := &op{agent: agentID, result: make(chan *agentv1.OpResult, 1)}
	s.mu.Lock()
	sess := s.active[agentID]
	if sess != nil && (need == "" || slices.Contains(sess.caps, need)) {
		if s.ops == nil {
			s.ops = map[string]*op{}
		}
		s.ops[id] = o
	}
	s.mu.Unlock()
	switch {
	case sess == nil:
		return nil, ErrNotConnected
	case need != "" && !slices.Contains(sess.caps, need):
		return nil, errNoCapability
	}
	defer func() {
		s.mu.Lock()
		delete(s.ops, id)
		s.mu.Unlock()
	}()
	if !s.sendTo(agentID, sess.epoch, msg(id)) {
		return nil, fmt.Errorf("%w: the session ended or is full", ErrNotConnected)
	}
	select {
	case r := <-o.result:
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// opResult delivers an OpResult to its operation; one for another agent's operation, or for none,
// is ignored.
func (s *Sessions) opResult(sess *session, r *agentv1.OpResult) {
	s.mu.Lock()
	o := s.ops[r.GetOpId()]
	s.mu.Unlock()
	if o == nil || o.agent != sess.agent.Identity.ID {
		return
	}
	select {
	case o.result <- r:
	default:
	}
}
