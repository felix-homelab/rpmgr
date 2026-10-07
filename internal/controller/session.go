// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/ratelimit"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The control session's timing (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	HelloTimeout     = 10 * time.Second // the first message must be Hello
	AdmissionPerSec  = 50               // new sessions per second and replica
	retryAfterMin    = time.Second      // an agent turned away retries after 1–10 s
	retryAfterSpread = 9 * time.Second
	sendQueue        = 16 // messages waiting for a session's writer
)

// Sessions is the controller side of the agents' control sessions (docs/03-connections.md,
// "Control session"): it admits sessions, answers Hello, keeps one session per agent and lets
// other parts of the controller send to it.
type Sessions struct {
	agentv1.UnimplementedControlServer

	db      *store.DB
	ca      *pki.CA
	signing [][]byte // DER of the config-signing certificates and their intermediates
	node    string   // this controller node's ID
	version string   // this controller's version
	now     func() time.Time
	admit   *ratelimit.Limiter
	sys     context.Context // the audited system scope of the session handlers
	push    *pusher         // nil without a compiler

	mu       sync.Mutex
	active   map[string]*session // by agent ID
	draining *time.Time
}

// SessionsOptions are the inputs of NewSessions.
type SessionsOptions struct {
	DB        *store.DB
	CA        *pki.CA
	Node      string
	Version   string
	Sys       context.Context // a context with the system scope, granted and audited by the caller
	Now       func() time.Time
	Admission int // sessions per second; 0 is AdmissionPerSec
	// Compiler compiles the agents' snapshots; nil sends none.
	Compiler *snapshot.Compiler
	// RevisionCheck is how often Run looks for a new revision; 0 is RevisionCheck.
	RevisionCheck time.Duration
	Logger        *slog.Logger
}

// NewSessions returns the control-session server.
func NewSessions(o SessionsOptions) *Sessions {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Admission == 0 {
		o.Admission = AdmissionPerSec
	}
	if o.RevisionCheck == 0 {
		o.RevisionCheck = RevisionCheck
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	signer := o.CA.ConfigSigner()
	s := &Sessions{
		db: o.DB, ca: o.CA, node: o.Node, version: o.Version, now: o.Now, sys: o.Sys,
		signing: [][]byte{signer.Cert.Raw, o.CA.Intermediate().Raw},
		admit:   ratelimit.New(time.Second/time.Duration(o.Admission), o.Admission, o.Now),
		active:  map[string]*session{},
	}
	if o.Compiler != nil {
		s.push = newPusher(s, o.Compiler, o.RevisionCheck, o.Logger)
	}
	return s
}

// Run pushes snapshots until ctx ends: to each agent whose session starts, and to every agent with
// a session here when the revision changes. Without a compiler it only waits for ctx.
func (s *Sessions) Run(ctx context.Context) {
	if s.push == nil {
		<-ctx.Done()
		return
	}
	s.push.run(ctx)
}

// session is one agent's control session.
type session struct {
	agent  Agent
	epoch  int64
	out    chan *agentv1.ControllerMessage
	cancel context.CancelFunc
}

// Session runs one control session: admission, Hello within HelloTimeout, the version check, a new
// session epoch, Welcome, and then the agent's messages until the session ends.
func (s *Sessions) Session(st grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ControllerMessage]) error {
	agent, ok := AgentFrom(st.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "client certificate required")
	}
	if s.isDraining() {
		return st.Send(goodbye(agentv1.GoodbyeReason_GOODBYE_REASON_SHUTDOWN, retryAfter()))
	}
	if !s.admit.Allow("") {
		return st.Send(goodbye(agentv1.GoodbyeReason_GOODBYE_REASON_OVERLOADED, retryAfter()))
	}
	hello, err := firstHello(st)
	if err != nil {
		return err
	}
	if min := MinAgentVersion(s.version); min != "" && olderThan(hello.GetVersion(), min) {
		return st.Send(goodbye(agentv1.GoodbyeReason_GOODBYE_REASON_UPGRADE_REQUIRED, 0))
	}
	epoch, dbEpoch, err := s.register(st.Context(), agent, hello)
	if err != nil {
		return status.Error(codes.Unavailable, "the controller cannot register sessions now")
	}
	ctx, cancel := context.WithCancel(st.Context())
	defer cancel()
	sess := &session{agent: agent, epoch: epoch, out: make(chan *agentv1.ControllerMessage, sendQueue), cancel: cancel}
	s.add(sess)
	defer s.remove(sess)
	welcome := &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Welcome{Welcome: &agentv1.Welcome{
		SessionEpoch: uint64(epoch), DbEpoch: dbEpoch, ServerTime: timestamppb.New(s.now()), //nolint:gosec // G115: epochs are positive
		MinAgentVersion: MinAgentVersion(s.version), SigningCertificates: s.signing}}}
	if err := st.Send(welcome); err != nil {
		return err
	}
	if d := s.drainDeadline(); d != nil {
		sess.out <- &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Drain{Drain: &agentv1.Drain{Deadline: timestamppb.New(*d)}}}
	}
	if s.push != nil {
		s.push.start(sess, hello)
		defer s.push.stop(sess)
	}
	recvErr := make(chan error, 1)
	go func() { recvErr <- s.receive(ctx, st, sess) }()
	for {
		select {
		case m := <-sess.out:
			if err := st.Send(m); err != nil {
				return err
			}
			if m.GetGoodbye() != nil {
				return nil
			}
		case err := <-recvErr:
			return err
		case <-ctx.Done():
			// Superseded or shut down: send what is queued, the Goodbye last.
			for {
				select {
				case m := <-sess.out:
					if err := st.Send(m); err != nil || m.GetGoodbye() != nil {
						return err
					}
				default:
					return nil
				}
			}
		}
	}
}

// receive reads the agent's messages until the session ends.
func (s *Sessions) receive(ctx context.Context, st grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ControllerMessage], sess *session) error {
	for {
		m, err := st.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch {
		case m.GetHello() != nil:
			return status.Error(codes.InvalidArgument, "Hello may come only first")
		case m.GetApplied() != nil && s.push != nil:
			s.push.applied(sess, m.GetApplied())
		case m.GetRejected() != nil && s.push != nil:
			s.push.rejected(sess, m.GetRejected())
		}
	}
}

// firstHello waits HelloTimeout for the session's first message, which must be Hello.
func firstHello(st grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ControllerMessage]) (*agentv1.Hello, error) {
	type result struct {
		m   *agentv1.AgentMessage
		err error
	}
	got := make(chan result, 1)
	go func() {
		m, err := st.Recv()
		got <- result{m, err}
	}()
	t := time.NewTimer(HelloTimeout)
	defer t.Stop()
	select {
	case r := <-got:
		if r.err != nil {
			return nil, r.err
		}
		if r.m.GetHello() == nil {
			return nil, status.Error(codes.InvalidArgument, "the first message must be Hello")
		}
		return r.m.GetHello(), nil
	case <-t.C:
		return nil, status.Error(codes.DeadlineExceeded, "no Hello in time")
	}
}

// register records the session with the next session epoch of the agent, in one statement, so
// two replicas never hand out the same epoch.
func (s *Sessions) register(ctx context.Context, agent Agent, hello *agentv1.Hello) (int64, string, error) {
	caps, err := json.Marshal(hello.GetCapabilities())
	if err != nil {
		return 0, "", err
	}
	addr := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		addr = p.Addr.String()
	}
	now := s.now().UTC()
	var epoch int64
	var dbEpoch string
	err = store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(s.sys, `INSERT INTO agent_sessions (agent_id, org_id, session_epoch,
			controller_node, remote_addr, agent_version, capabilities, connected_at, last_seen_at)
			VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $7)
			ON CONFLICT (agent_id) DO UPDATE SET session_epoch = agent_sessions.session_epoch + 1,
			controller_node = excluded.controller_node, remote_addr = excluded.remote_addr,
			agent_version = excluded.agent_version, capabilities = excluded.capabilities,
			connected_at = excluded.connected_at, last_seen_at = excluded.last_seen_at
			RETURNING session_epoch`,
			agent.Identity.ID, agent.Identity.Org, s.node, addr, hello.GetVersion(), string(caps), now)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		if !rows.Next() {
			return errors.New("controller: no session epoch")
		}
		if err := rows.Scan(&epoch); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		inst, err := tx.Instance.Get(s.sys, 1)
		if err != nil {
			return err
		}
		dbEpoch = inst.DbEpoch
		offset := int64(0)
		if hello.GetAgentTime() != nil {
			offset = hello.GetAgentTime().AsTime().Sub(now).Milliseconds()
		}
		return updateState(s.sys, tx, agent.Identity.Org, agent.Identity.ID, func(u *ent.AgentStateUpdateOne) {
			u.SetBootID(clip(hello.GetBootId())).SetClockOffsetMs(offset)
		})
	})
	return epoch, dbEpoch, err
}

// add makes sess the agent's session and supersedes an older one.
func (s *Sessions) add(sess *session) {
	s.mu.Lock()
	old := s.active[sess.agent.Identity.ID]
	s.active[sess.agent.Identity.ID] = sess
	s.mu.Unlock()
	if old != nil {
		old.end(agentv1.GoodbyeReason_GOODBYE_REASON_SUPERSEDED, 0)
	}
}

func (s *Sessions) remove(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[sess.agent.Identity.ID] == sess {
		delete(s.active, sess.agent.Identity.ID)
	}
}

// end queues a Goodbye and ends the session.
func (sess *session) end(reason agentv1.GoodbyeReason, retry time.Duration) {
	select {
	case sess.out <- goodbye(reason, retry):
	default: // a full queue: the session ends without its Goodbye
	}
	sess.cancel()
}

// Send queues m for the agent's current session; ok is false if the agent has none, or if its
// queue is full, in which case the session is ended so the agent reconnects and resynchronises.
func (s *Sessions) Send(agentID string, m *agentv1.ControllerMessage) bool {
	s.mu.Lock()
	sess := s.active[agentID]
	s.mu.Unlock()
	if sess == nil {
		return false
	}
	select {
	case sess.out <- m:
		return true
	default:
		sess.cancel()
		return false
	}
}

// sendTo is Send to the session with the given epoch only.
func (s *Sessions) sendTo(agentID string, epoch int64, m *agentv1.ControllerMessage) bool {
	s.mu.Lock()
	sess := s.active[agentID]
	s.mu.Unlock()
	if sess == nil || sess.epoch != epoch {
		return false
	}
	select {
	case sess.out <- m:
		return true
	default:
		sess.cancel()
		return false
	}
}

// Connected lists the agents with a session on this controller.
func (s *Sessions) Connected() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.active))
	for id := range s.active {
		out = append(out, id)
	}
	return out
}

// Drain asks every agent to reconnect to another endpoint before deadline, and every agent that
// connects from now on too; new sessions then get Goodbye{shutdown}.
func (s *Sessions) Drain(deadline time.Time) {
	s.mu.Lock()
	s.draining = &deadline
	sessions := make([]*session, 0, len(s.active))
	for _, sess := range s.active {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		select {
		case sess.out <- &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Drain{Drain: &agentv1.Drain{Deadline: timestamppb.New(deadline)}}}:
		default:
		}
	}
}

func (s *Sessions) isDraining() bool { return s.drainDeadline() != nil }

func (s *Sessions) drainDeadline() *time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining
}

func goodbye(reason agentv1.GoodbyeReason, retry time.Duration) *agentv1.ControllerMessage {
	g := &agentv1.Goodbye{Reason: reason}
	if retry > 0 {
		g.RetryAfter = durationpb.New(retry)
	}
	return &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Goodbye{Goodbye: g}}
}

// retryAfter spreads agents that were turned away over 1 to 10 seconds.
func retryAfter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(retryAfterSpread)))
	if err != nil {
		return retryAfterMin
	}
	return retryAfterMin + time.Duration(n.Int64())
}

// MinAgentVersion is the oldest agent version a controller of version v accepts: the previous
// minor release of the same major (docs/10-operations.md, "Upgrades and version skew"). A
// development build, whose version is no semantic version, accepts every agent.
func MinAgentVersion(v string) string {
	sv := semver.Canonical("v" + strings.TrimPrefix(v, "v"))
	if sv == "" {
		return ""
	}
	parts := strings.SplitN(strings.TrimPrefix(sv, "v"), ".", 3)
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return ""
	}
	return parts[0] + "." + strconv.Itoa(max(minor-1, 0)) + ".0"
}

// olderThan reports whether agent version v is older than min; an unparsable version is.
func olderThan(v, min string) bool {
	sv := "v" + strings.TrimPrefix(v, "v")
	if !semver.IsValid(sv) {
		return true
	}
	return semver.Compare(sv, "v"+min) < 0
}
