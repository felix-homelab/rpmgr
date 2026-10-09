// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestOp: an operation reaches the agent's session and ends with its OpResult, an error in it
// fails it, an OpResult from another agent does not count, and an agent without a session or one
// that does not answer fails it.
func TestOp(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.1.0", 0)
		certA, a := e.agentCert(t)
		certB, _ := e.agentCert(t)
		stA, stB := e.open(t, testCtx(t), certA, hello("0.1.0")), e.open(t, testCtx(t), certB, hello("0.1.0"))
		recv(t, stA)
		recv(t, stB)
		challenge := func(id string) *agentv1.ControllerMessage {
			return &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_AcmeChallenge{AcmeChallenge: &agentv1.AcmeChallenge{OpId: id,
				Action: agentv1.AcmeAction_ACME_ACTION_ADD, Identifier: "app.example.test"}}}
		}
		answer := func(result func(opID string) []*agentv1.AgentMessage) chan error {
			done := make(chan error, 1)
			go func() {
				done <- e.sessions.Op(testCtx(t), a.ID, challenge)
			}()
			m := recv(t, stA)
			if m.GetAcmeChallenge() == nil {
				t.Fatalf("got %v, want the operation", m)
			}
			for _, r := range result(m.GetAcmeChallenge().GetOpId()) {
				send(t, stA, r)
			}
			return done
		}
		ok := func(id, errText string) *agentv1.AgentMessage {
			return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_OpResult{OpResult: &agentv1.OpResult{OpId: id, Error: errText}}}
		}
		if err := <-answer(func(id string) []*agentv1.AgentMessage { return []*agentv1.AgentMessage{ok(id, "")} }); err != nil {
			t.Fatalf("an acknowledged operation: %v", err)
		}
		if err := <-answer(func(id string) []*agentv1.AgentMessage { return []*agentv1.AgentMessage{ok(id, "refused")} }); err == nil {
			t.Fatal("an operation the agent refused succeeded")
		}
		// b answers a's operation: ignored; then a answers.
		done := answer(func(id string) []*agentv1.AgentMessage {
			send(t, stB, ok(id, ""))
			time.Sleep(100 * time.Millisecond)
			return []*agentv1.AgentMessage{ok("op_other", ""), ok(id, "from a")}
		})
		if err := <-done; err == nil || err.Error() == "" {
			t.Fatalf("the operation took another agent's or another operation's result: %v", err)
		}

		if err := e.sessions.Op(testCtx(t), "con_unknown", challenge); !errors.Is(err, controller.ErrNotConnected) {
			t.Fatalf("an agent without a session: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		go func() { _, _ = stA.Recv() }() // the operation arrives and is never answered
		if err := e.sessions.Op(ctx, a.ID, challenge); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("an unanswered operation: %v", err)
		}
	})
}
