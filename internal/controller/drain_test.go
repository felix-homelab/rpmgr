// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func draining(conns int64) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Draining: &agentv1.DrainingProcess{
		Active: true, Connections: conns, Flows: 3, Sessions: 2, Since: timestamppb.New(time.Unix(1000, 0)), Ends: timestamppb.New(time.Unix(1300, 0))}}}}
}

// TestDraining (D160): the old process an agent reports shows until the agent says it is gone or
// its session ends; ending the drain reaches an agent that announced "drain.end" and returns what
// the old process held, an agent's error is an error, and an agent of an earlier release, one
// without a session and one with no old process are refused before anything is sent.
func TestDraining(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.1.0", 0)
		certA, a := e.agentCert(t)
		certB, b := e.agentCert(t)
		withEnd := hello("0.1.0")
		withEnd.Capabilities = append(withEnd.Capabilities, agentproto.CapDrainEnd)
		stA, stB := e.open(t, testCtx(t), certA, withEnd), e.open(t, testCtx(t), certB, hello("0.1.0"))
		recv(t, stA)
		recv(t, stB)
		eventually := func(what string, ok func() bool) {
			t.Helper()
			for i := 0; i < 200; i++ {
				if ok() {
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
			t.Fatal(what)
		}

		if d := e.sessions.Draining(a.ID); d != nil {
			t.Fatalf("an agent that reported nothing shows %v", d)
		}
		if _, err := e.sessions.EndDrain(testCtx(t), a.ID); !errors.Is(err, apisvc.ErrNoDrain) {
			t.Fatalf("no old process: %v", err)
		}
		send(t, stA, draining(12))
		eventually("the report did not show", func() bool { return e.sessions.Draining(a.ID).GetConnections() == 12 })
		if d := e.sessions.Draining(a.ID); d.GetFlows() != 3 || d.GetSessions() != 2 || d.GetEnds().AsTime().Unix() != 1300 || d.GetSince().AsTime().Unix() != 1000 {
			t.Fatalf("the report shows %v", d)
		}
		send(t, stA, draining(7)) // the next report replaces it
		eventually("the next report did not replace it", func() bool { return e.sessions.Draining(a.ID).GetConnections() == 7 })
		if e.sessions.Draining(b.ID) != nil {
			t.Fatal("another agent shows A's old process")
		}

		end := func(result func(op string) *agentv1.OpResult) (int64, error) {
			type res struct {
				n   int64
				err error
			}
			done := make(chan res, 1)
			go func() {
				d, err := e.sessions.EndDrain(testCtx(t), a.ID)
				done <- res{d.GetConnections(), err}
			}()
			m := recv(t, stA).GetEndDrain()
			if m.GetOpId() == "" {
				t.Fatalf("the agent got %v", m)
			}
			send(t, stA, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_OpResult{OpResult: result(m.GetOpId())}})
			r := <-done
			return r.n, r.err
		}
		if _, err := end(func(op string) *agentv1.OpResult { return &agentv1.OpResult{OpId: op, Error: "no old process drains"} }); !errors.Is(err, apisvc.ErrNoDrain) {
			t.Fatalf("an agent that refuses: %v", err)
		}
		if n, err := end(func(op string) *agentv1.OpResult { return &agentv1.OpResult{OpId: op} }); err != nil || n != 7 {
			t.Fatalf("ending the drain: %d %v", n, err)
		}
		send(t, stA, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Draining: &agentv1.DrainingProcess{}}}})
		eventually("the old process still shows after the agent said it is gone", func() bool { return e.sessions.Draining(a.ID) == nil })

		// An agent of an earlier release announces no capability: it can report nothing to end.
		send(t, stB, draining(5))
		eventually("B's report did not show", func() bool { return e.sessions.Draining(b.ID) != nil })
		if _, err := e.sessions.EndDrain(testCtx(t), b.ID); !errors.Is(err, apisvc.ErrDrainUnsupported) {
			t.Fatalf("an agent without the capability: %v", err)
		}
		if _, err := e.sessions.EndDrain(testCtx(t), "con_unknown"); !errors.Is(err, apisvc.ErrDrainNotConnected) {
			t.Fatalf("an agent without a session: %v", err)
		}

		// A new session of the agent starts without the old session's report.
		stB2 := e.open(t, testCtx(t), certB, hello("0.1.0"))
		recv(t, stB2)
		eventually("the report outlived its session", func() bool { return e.sessions.Draining(b.ID) == nil })
	})
}
