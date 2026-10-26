// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
)

// The bounds of an imperative operation (docs/03-connections.md, "Timeouts, keepalive and
// backoff"): its ticket is valid for ticketValid, and it ends after operationDeadline. Variables
// only so that tests can shorten them.
var (
	ticketValid       = 30 * time.Second
	operationDeadline = 30 * time.Minute
)

// ErrOperationRefused is an operation the agent refused, or whose Attach failed its checks.
var ErrOperationRefused = errors.New("controller: the agent did not take the operation")

// capabilityOf is the capability an agent announces for each kind of operation.
var capabilityOf = map[agentv1.OperationKind]string{agentv1.OperationKind_OPERATION_KIND_LOGS: agentproto.CapLogsStream}

// attachStream is the server side of an Attach stream.
type attachStream = grpc.BidiStreamingServer[agentv1.AttachFrame, agentv1.AttachFrame]

// pendingOp is an operation sent with Open and waiting for its Attach: the ticket's hash, bound to
// the agent, valid until expires; kept only in memory, on the replica that holds the agent's
// control session (D145, E13).
type pendingOp struct {
	agent    string
	ticket   [sha256.Size]byte
	expires  time.Time
	deadline time.Time
	attached chan *Operation // the Attach that presented the ticket, handed over once
	failed   chan error      // an Attach that failed the checks
	gone     chan struct{}   // closed when Open no longer waits
	sess     *session        // the control session it was opened on, whose end ends it
}

// Operation is an imperative operation its agent attached (docs/03-connections.md, "Control
// session"). Recv reads the agent's frames; Close ends it. It also ends at its deadline, when the
// agent's control session ends, as when the agent is revoked, when the agent ends it or the
// agent's stream breaks.
type Operation struct {
	st   attachStream
	done chan struct{}
	once sync.Once
	why  string // the reason Close gave; read only once done is closed
}

// Recv returns the agent's next frame; io.EOF once the agent ended the operation, and once the
// controller ended it, an error with Close's reason.
func (o *Operation) Recv() (*agentv1.AttachFrame, error) {
	f, err := o.st.Recv()
	if err != nil {
		select {
		case <-o.done:
			return nil, o.ended(err)
		default:
			return nil, err
		}
	}
	if f.GetEnd() != nil {
		if r := f.GetEnd().GetReason(); r != "" {
			return nil, fmt.Errorf("controller: the agent ended the operation: %s", r)
		}
		return nil, io.EOF
	}
	return f, nil
}

// ended is the error of a Recv after Close, which err, the stream's, does not explain.
func (o *Operation) ended(err error) error {
	if o.why == "" {
		return err
	}
	return fmt.Errorf("controller: the operation ended: %s", o.why)
}

// Close ends the operation: the agent gets an AttachEnd with reason, and the stream closes.
func (o *Operation) Close(reason string) {
	o.once.Do(func() {
		o.why = reason
		_ = o.st.Send(&agentv1.AttachFrame{Frame: &agentv1.AttachFrame_End{End: &agentv1.AttachEnd{Reason: reason}}})
		close(o.done)
	})
}

// Open starts an operation of kind on an agent's current control session and waits until the
// agent attached it: the agent must have announced the kind's capability; it gets
// Open{op_id, kind, ticket, deadline, params} and attaches with the ticket within ticketValid. A
// refusal (an OpResult with an error), a session that ends, a ticket that expires or fails its
// checks, or ctx ending fails it.
func (s *Sessions) Open(ctx context.Context, agentID string, kind agentv1.OperationKind, logs *agentv1.LogParams) (*Operation, error) {
	need, ok := capabilityOf[kind]
	if !ok {
		return nil, fmt.Errorf("controller: unknown operation kind %s", kind)
	}
	ticket := make([]byte, 32)
	idb := make([]byte, 12)
	if _, err := rand.Read(ticket); err != nil {
		return nil, err
	}
	if _, err := rand.Read(idb); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idb)
	now := s.now()
	p := &pendingOp{agent: agentID, ticket: sha256.Sum256(ticket), expires: now.Add(ticketValid), deadline: now.Add(operationDeadline),
		attached: make(chan *Operation, 1), failed: make(chan error, 1), gone: make(chan struct{})}
	refused := &op{agent: agentID, result: make(chan *agentv1.OpResult, 1)}
	s.mu.Lock()
	sess := s.active[agentID]
	capable := sess != nil && slices.Contains(sess.caps, need)
	p.sess = sess
	if capable {
		if s.ops == nil {
			s.ops = map[string]*op{}
		}
		if s.pending == nil {
			s.pending = map[string]*pendingOp{}
		}
		s.ops[id], s.pending[id] = refused, p
	}
	s.mu.Unlock()
	switch {
	case sess == nil:
		return nil, ErrNotConnected
	case !capable:
		return nil, errNoCapability
	}
	handed := false
	defer func() {
		s.mu.Lock()
		delete(s.ops, id)
		delete(s.pending, id)
		s.mu.Unlock()
		if !handed {
			close(p.gone) // an Attach handed over after the caller gave up ends at once
		}
	}()
	open := &agentv1.Open{OpId: id, Kind: kind, Ticket: ticket, Deadline: timestamppb.New(p.deadline)}
	if logs != nil {
		open.Params = &agentv1.Open_Logs{Logs: logs}
	}
	if !s.sendTo(agentID, sess.epoch, &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_OpenOperation{OpenOperation: open}}) {
		return nil, fmt.Errorf("%w: the session ended or is full", ErrNotConnected)
	}
	expired := time.NewTimer(ticketValid)
	defer expired.Stop()
	select {
	case o := <-p.attached:
		handed = true
		return o, nil
	case err := <-p.failed:
		return nil, err
	case r := <-refused.result:
		return nil, fmt.Errorf("%w: %s", ErrOperationRefused, r.GetError())
	case <-expired.C:
		return nil, fmt.Errorf("%w: the agent did not attach in time", ErrOperationRefused)
	case <-sess.done:
		return nil, fmt.Errorf("%w: the session ended before the agent attached", ErrNotConnected)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Attach implements agentv1.ControlServer: the agent's first frame presents an operation's ticket
// within ticketValid. The ticket is used up by its first presentation; an unknown, used, expired
// or another agent's ticket is refused and fails the operation at once. The stream then belongs to
// the operation until it ends, at the latest at its deadline.
func (s *Sessions) Attach(st attachStream) error {
	agent, ok := AgentFrom(st.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "client certificate required")
	}
	first := make(chan *agentv1.AttachFrame, 1)
	go func() {
		f, err := st.Recv()
		if err != nil {
			f = nil
		}
		first <- f
	}()
	var hello *agentv1.AttachHello
	select {
	case f := <-first:
		hello = f.GetHello()
	case <-time.After(ticketValid):
	case <-st.Context().Done():
		return st.Context().Err()
	}
	if hello == nil {
		return status.Error(codes.InvalidArgument, "the first frame presents an operation's ticket")
	}
	s.mu.Lock()
	p := s.pending[hello.GetOpId()]
	delete(s.pending, hello.GetOpId()) // single use, whatever follows
	s.mu.Unlock()
	refuse := func(why string) error {
		if p != nil {
			p.failed <- fmt.Errorf("%w: %s", ErrOperationRefused, why)
		}
		s.log.Warn("refused an Attach", "agent", agent.Identity.ID, "op", hello.GetOpId(), "reason", why)
		return status.Error(codes.PermissionDenied, "the ticket is not valid for this operation")
	}
	sum := sha256.Sum256(hello.GetTicket())
	switch {
	case p == nil:
		return refuse("an unknown or used ticket")
	case p.agent != agent.Identity.ID:
		return refuse("the ticket of another agent")
	case !s.now().Before(p.expires):
		return refuse("an expired ticket")
	case subtle.ConstantTimeCompare(sum[:], p.ticket[:]) != 1:
		return refuse("a wrong ticket")
	}
	o := &Operation{st: st, done: make(chan struct{})}
	p.attached <- o
	deadline := time.NewTimer(time.Until(p.deadline))
	defer deadline.Stop()
	select {
	case <-o.done:
	case <-st.Context().Done():
	case <-p.gone:
		o.Close("the operation was given up")
	case <-p.sess.done:
		o.Close(p.sess.endReason())
	case <-deadline.C:
		o.Close("the operation reached its deadline")
	}
	return nil
}
