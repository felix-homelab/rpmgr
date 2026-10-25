// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// attachStream is the agent's side of an Attach stream.
type attachStream = grpc.BidiStreamingClient[agentv1.AttachFrame, agentv1.AttachFrame]

// attach opens an Attach stream with cert and presents opID and ticket.
func (e *sessionEnv) attach(t *testing.T, ctx context.Context, cert tls.Certificate, opID string, ticket []byte) attachStream {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Root())
	cfg := pki.ClientConfig(cert, roots, "controller."+e.ca.TrustDomain(),
		pki.Expect{TrustDomain: e.ca.TrustDomain(), Kinds: []pki.Kind{pki.KindController}}, nil, nil)
	cc, err := grpc.NewClient("passthrough:///"+e.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	st, err := agentv1.NewControlClient(cc).Attach(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&agentv1.AttachFrame{Frame: &agentv1.AttachFrame_Hello{Hello: &agentv1.AttachHello{OpId: opID, Ticket: ticket}}}); err != nil {
		t.Fatal(err)
	}
	return st
}

// attachRefused reports whether an Attach stream was refused for its ticket.
func attachRefused(st attachStream) bool {
	_, err := st.Recv()
	return status.Code(err) == codes.PermissionDenied
}

// TestLiveLogs_TicketSingleUseAndBound (docs/12-testing-and-quality.md, "Security testing"): an
// operation reaches only an agent that announced its capability, as an Open with a fresh ticket
// and a deadline; the agent attaches with the ticket and its frames reach the operation, whose end
// reaches the agent. A ticket is used up by its first presentation; a used, unknown, expired,
// wrong or another agent's ticket is refused and fails the operation at once; an operation the
// agent refuses fails; and an operation ends at its deadline.
func TestLiveLogs_TicketSingleUseAndBound(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		var mu sync.Mutex
		now := time.Now()
		clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
		advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
		e := startSessionsWith(t, db, func(o *controller.SessionsOptions) { o.Version, o.Now = "0.1.0", clock })
		certA, a := e.agentCert(t)
		certB, b := e.agentCert(t)
		capable := hello("0.1.0")
		capable.Capabilities = append(capable.Capabilities, agentproto.CapLogsStream)
		stA, stB := e.open(t, testCtx(t), certA, capable), e.open(t, testCtx(t), certB, capable)
		recv(t, stA)
		recv(t, stB)

		// open starts an operation on a and returns its Open as a received it, and the result.
		type opened struct {
			op  *controller.Operation
			err error
		}
		open := func() (*agentv1.Open, chan opened) {
			t.Helper()
			done := make(chan opened, 1)
			go func() {
				op, err := e.sessions.Open(testCtx(t), a.ID, agentv1.OperationKind_OPERATION_KIND_LOGS,
					&agentv1.LogParams{Level: "debug", Filter: "route"})
				done <- opened{op, err}
			}()
			m := recv(t, stA).GetOpenOperation()
			if m == nil || len(m.GetTicket()) != 32 || m.GetKind() != agentv1.OperationKind_OPERATION_KIND_LOGS ||
				m.GetLogs().GetFilter() != "route" || !m.GetDeadline().AsTime().After(clock().Add(29*time.Minute)) {
				t.Fatalf("Open %v", m)
			}
			return m, done
		}
		wait := func(done chan opened) opened {
			t.Helper()
			select {
			case r := <-done:
				return r
			case <-time.After(10 * time.Second):
				t.Fatal("the operation neither started nor failed")
				return opened{}
			}
		}

		// The agent attaches; a line reaches the operation; its end reaches the agent.
		m, done := open()
		att := e.attach(t, testCtx(t), certA, m.GetOpId(), m.GetTicket())
		r := wait(done)
		if r.err != nil {
			t.Fatalf("an attached operation: %v", r.err)
		}
		if err := att.Send(&agentv1.AttachFrame{Frame: &agentv1.AttachFrame_Log{Log: &agentv1.LogLine{Level: "info", Text: "hello"}}}); err != nil {
			t.Fatal(err)
		}
		if f, err := r.op.Recv(); err != nil || f.GetLog().GetText() != "hello" {
			t.Fatalf("the agent's line: %v %v", f, err)
		}
		r.op.Close("viewer left")
		if f, err := att.Recv(); err != nil || f.GetEnd().GetReason() != "viewer left" {
			t.Fatalf("the end at the agent: %v %v", f, err)
		}
		// The same ticket again: used up.
		if !attachRefused(e.attach(t, testCtx(t), certA, m.GetOpId(), m.GetTicket())) {
			t.Error("a used ticket was accepted")
		}
		// An agent that ends the operation ends it for the controller too.
		m, done = open()
		att = e.attach(t, testCtx(t), certA, m.GetOpId(), m.GetTicket())
		r = wait(done)
		_ = att.Send(&agentv1.AttachFrame{Frame: &agentv1.AttachFrame_End{End: &agentv1.AttachEnd{}}})
		if _, err := r.op.Recv(); !errors.Is(err, io.EOF) {
			t.Fatalf("the agent's end: %v", err)
		}
		r.op.Close("")

		for name, attach := range map[string]func(m *agentv1.Open) attachStream{
			"another agent's ticket": func(m *agentv1.Open) attachStream {
				return e.attach(t, testCtx(t), certB, m.GetOpId(), m.GetTicket())
			},
			"a wrong ticket": func(m *agentv1.Open) attachStream {
				return e.attach(t, testCtx(t), certA, m.GetOpId(), make([]byte, 32))
			},
			"an expired ticket": func(m *agentv1.Open) attachStream {
				advance(31 * time.Second)
				return e.attach(t, testCtx(t), certA, m.GetOpId(), m.GetTicket())
			},
		} {
			m, done := open()
			if !attachRefused(attach(m)) {
				t.Errorf("%s was accepted", name)
			}
			if r := wait(done); !errors.Is(r.err, controller.ErrOperationRefused) {
				t.Errorf("%s: the operation %v, want it failed at once", name, r.err)
			}
			// Used up by the failed presentation.
			if !attachRefused(e.attach(t, testCtx(t), certA, m.GetOpId(), m.GetTicket())) {
				t.Errorf("%s: the ticket worked after a failed presentation", name)
			}
		}
		if !attachRefused(e.attach(t, testCtx(t), certA, "op_unknown", make([]byte, 32))) {
			t.Error("an Attach without an Open was accepted")
		}
		_ = b

		// The agent refuses: an OpResult with an error fails the operation.
		m, done = open()
		send(t, stA, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_OpResult{OpResult: &agentv1.OpResult{OpId: m.GetOpId(),
			Error: "this agent does not run the operation"}}})
		if r := wait(done); !errors.Is(r.err, controller.ErrOperationRefused) {
			t.Errorf("a refused operation: %v", r.err)
		}
		// Without the capability or a session, no Open is sent.
		certC, c := e.agentCert(t)
		stC := e.open(t, testCtx(t), certC, hello("0.1.0"))
		recv(t, stC)
		if _, err := e.sessions.Open(testCtx(t), c.ID, agentv1.OperationKind_OPERATION_KIND_LOGS, nil); err == nil {
			t.Error("an agent without logs.stream got an operation")
		}
		if _, err := e.sessions.Open(testCtx(t), "con_unknown", agentv1.OperationKind_OPERATION_KIND_LOGS, nil); !errors.Is(err, controller.ErrNotConnected) {
			t.Errorf("an agent without a session: %v", err)
		}
	})
}

// TestOperation_Deadline: an operation ends at its deadline, and the agent learns why; an agent
// that never attaches fails the operation once its ticket expires.
func TestOperation_Deadline(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		controller.SetOperationTimers(t, 300*time.Millisecond, 500*time.Millisecond)
		e := startSessions(t, db, "0.1.0", 0)
		cert, a := e.agentCert(t)
		h := hello("0.1.0")
		h.Capabilities = append(h.Capabilities, agentproto.CapLogsStream)
		st := e.open(t, testCtx(t), cert, h)
		recv(t, st)
		go func() {
			m := recv(t, st).GetOpenOperation()
			att := e.attach(t, testCtx(t), cert, m.GetOpId(), m.GetTicket())
			for {
				if _, err := att.Recv(); err != nil {
					return
				}
			}
		}()
		op, err := e.sessions.Open(testCtx(t), a.ID, agentv1.OperationKind_OPERATION_KIND_LOGS, nil)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := op.Recv(); err == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("the operation past its deadline: %v after %v", err, time.Since(start))
		}
		// An agent that never attaches.
		done := make(chan error, 1)
		go func() {
			_, err := e.sessions.Open(testCtx(t), a.ID, agentv1.OperationKind_OPERATION_KIND_LOGS, nil)
			done <- err
		}()
		recv(t, st) // the Open, never attached
		select {
		case err := <-done:
			if !errors.Is(err, controller.ErrOperationRefused) {
				t.Fatalf("an operation never attached: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("an operation never attached did not fail")
		}
	})
}

// TestOpenLogs_Unavailable: LogService learns that the live log of an agent without a session
// here, of one whose release runs no live logs and of one that refuses the operation is
// unavailable.
func TestOpenLogs_Unavailable(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.1.0", 0)
		capable := hello("0.1.0")
		capable.Capabilities = append(capable.Capabilities, agentproto.CapLogsStream)
		certA, a := e.agentCert(t)
		stA := e.open(t, testCtx(t), certA, capable)
		recv(t, stA)
		certB, b := e.agentCert(t)
		stB := e.open(t, testCtx(t), certB, hello("0.1.0"))
		recv(t, stB)
		done := make(chan error, 1)
		go func() {
			_, err := e.sessions.OpenLogs(testCtx(t), a.ID, &agentv1.LogParams{Level: "info"})
			done <- err
		}()
		m := recv(t, stA).GetOpenOperation()
		send(t, stA, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_OpResult{OpResult: &agentv1.OpResult{OpId: m.GetOpId(),
			Error: "this agent does not run the operation"}}})
		if err := <-done; !errors.Is(err, apisvc.ErrLogsUnavailable) {
			t.Errorf("a refused live log: %v", err)
		}
		if _, err := e.sessions.OpenLogs(testCtx(t), b.ID, nil); !errors.Is(err, apisvc.ErrLogsUnavailable) {
			t.Errorf("an agent without logs.stream: %v", err)
		}
		if _, err := e.sessions.OpenLogs(testCtx(t), "con_unknown", nil); !errors.Is(err, apisvc.ErrLogsUnavailable) {
			t.Errorf("an agent without a session: %v", err)
		}
	})
}
