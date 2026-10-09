// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
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
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	id := hex.EncodeToString(b)
	o := &op{agent: agentID, result: make(chan *agentv1.OpResult, 1)}
	s.mu.Lock()
	sess := s.active[agentID]
	if sess != nil {
		if s.ops == nil {
			s.ops = map[string]*op{}
		}
		s.ops[id] = o
	}
	s.mu.Unlock()
	if sess == nil {
		return ErrNotConnected
	}
	defer func() {
		s.mu.Lock()
		delete(s.ops, id)
		s.mu.Unlock()
	}()
	if !s.sendTo(agentID, sess.epoch, msg(id)) {
		return fmt.Errorf("%w: the session ended or is full", ErrNotConnected)
	}
	select {
	case r := <-o.result:
		if r.GetError() != "" {
			return fmt.Errorf("controller: agent %s: %s", agentID, r.GetError())
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
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
