// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/compiledsnapshot"
)

// The snapshot push (docs/03-connections.md, "Configuration reconciliation", "Timeouts, keepalive
// and backoff").
const (
	ApplyTimeout  = snapshot.ApplyTimeout // an unacknowledged snapshot is apply_timeout after it
	RevisionCheck = time.Second           // how often the controller looks for a new revision
	keepCompiled  = 5                     // compiled snapshots kept per agent
	maxRejection  = 32                    // errors of a Rejected that are stored
	maxErrorText  = 512                   // bytes of an error's message and resource ID that are stored
)

// ApplyState is snapshot.ApplyState.
type ApplyState = snapshot.ApplyState

// The apply states.
const (
	ApplyPending  = snapshot.ApplyPending
	ApplyApplied  = snapshot.ApplyApplied
	ApplyRejected = snapshot.ApplyRejected
	ApplyTimedOut = snapshot.ApplyTimedOut
)

// ApplyStatus is snapshot.ApplyStatus.
var ApplyStatus = snapshot.ApplyStatus

// pusher sends every agent with a session here its snapshot: when the session starts and at every
// new revision. A snapshot equal to the one the agent runs, or to the one it was sent last, is not
// sent again.
type pusher struct {
	s        *Sessions
	compiler *snapshot.Compiler
	every    time.Duration
	log      *slog.Logger

	mu     sync.Mutex
	agents map[string]*pushState // by agent ID, for the agent's current session
	dirty  map[string]bool       // agents to compile for
	wake   chan struct{}
}

// pushState is what the pusher knows of one session.
type pushState struct {
	epoch    int64
	agent    snapshot.Agent
	applied  []byte // the snapshot the agent runs, from Hello or Applied
	sent     []sent // the snapshots sent in this session, the last keepCompiled
	pending  []byte // the snapshot sent last, until the agent answers
	sentAt   time.Time
	timedOut bool
	failing  bool
}

type sent struct {
	hash []byte
	rev  store.Revision
}

func newPusher(s *Sessions, c *snapshot.Compiler, every time.Duration, log *slog.Logger) *pusher {
	return &pusher{s: s, compiler: c, every: every, log: log,
		agents: map[string]*pushState{}, dirty: map[string]bool{}, wake: make(chan struct{}, 1)}
}

// start registers a session that has been welcomed and asks for its snapshot.
func (p *pusher) start(sess *session, hello *agentv1.Hello) {
	p.mu.Lock()
	p.agents[sess.agent.Identity.ID] = &pushState{epoch: sess.epoch, applied: hello.GetLastAppliedHash(),
		agent: snapshot.Agent{Identity: sess.agent.Identity, Capabilities: slices.Clone(hello.GetCapabilities())}}
	p.dirty[sess.agent.Identity.ID] = true
	p.mu.Unlock()
	p.poke()
}

// stop forgets a session that ended, unless a newer session of the agent replaced it.
func (p *pusher) stop(sess *session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.agents[sess.agent.Identity.ID]; st != nil && st.epoch == sess.epoch {
		delete(p.agents, sess.agent.Identity.ID)
	}
}

func (p *pusher) poke() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// run pushes until ctx ends. It checks the revision every p.every, so that it also pushes
// revisions another process wrote, such as an admin command.
func (p *pusher) run(ctx context.Context) {
	t := time.NewTicker(p.every)
	defer t.Stop()
	var last store.Revision
	var lastKey string
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		case <-t.C:
			// A new revision or a new signing key: every agent gets a new snapshot.
			key := snapshot.KeyID(p.s.ca.ConfigSigner().Cert)
			if rev, err := currentRevision(p.s); err == nil && (rev != last || key != lastKey) {
				last, lastKey = rev, key
				p.mu.Lock()
				for id := range p.agents {
					p.dirty[id] = true
				}
				p.mu.Unlock()
			}
			p.checkTimeouts()
		}
		p.mu.Lock()
		ids := slices.Sorted(maps.Keys(p.dirty))
		clear(p.dirty)
		p.mu.Unlock()
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			p.push(id)
		}
	}
}

func currentRevision(s *Sessions) (store.Revision, error) {
	var rev store.Revision
	err := store.ReadTx(s.sys, s.db, func(_ *ent.Tx, r store.Revision) error {
		rev = r
		return nil
	})
	return rev, err
}

// push compiles the agent's snapshot and sends it if it is new to the agent. A failure leaves the
// agent marked, so the next check tries again.
func (p *pusher) push(id string) {
	p.mu.Lock()
	st := p.agents[id]
	if st == nil {
		p.mu.Unlock()
		return
	}
	epoch, agent := st.epoch, st.agent
	p.mu.Unlock()

	snap, err := p.compiler.Compile(p.s.sys, p.s.db, agent)
	var signed *agentv1.Signed
	if err == nil {
		signer := p.s.ca.ConfigSigner()
		snap.SigningKeyId = snapshot.KeyID(signer.Cert)
		signed, err = snapshot.Sign(signer, snap)
	}
	p.mu.Lock()
	st = p.agents[id]
	if st == nil || st.epoch != epoch {
		p.mu.Unlock()
		return // the session ended; a newer one asks for its own snapshot
	}
	if err != nil {
		p.dirty[id] = true
		if !st.failing {
			p.log.Error("cannot compile a snapshot; retrying", "agent", id, "error", err)
		}
		st.failing = true
		p.mu.Unlock()
		return
	}
	st.failing = false
	hash := snapshot.Hash(signed)
	rev := store.Revision{DBEpoch: snap.GetRevision().GetDbEpoch(), Seq: int64(snap.GetRevision().GetSeq())} //nolint:gosec // G115: compiled from an int64
	inSync := bytes.Equal(hash, st.applied)
	if inSync || bytes.Equal(hash, st.pending) {
		p.mu.Unlock()
		if inSync {
			p.record(agent.Identity, func(u *ent.AgentStateUpdateOne) {
				u.SetPushedDbEpoch(rev.DBEpoch).SetPushedSeq(rev.Seq).SetPushedHash(hash).SetPushedAt(p.s.now()).
					SetAppliedDbEpoch(rev.DBEpoch).SetAppliedSeq(rev.Seq).SetAppliedHash(hash)
			})
		}
		return
	}
	st.pending, st.sentAt, st.timedOut = hash, p.s.now(), false
	st.sent = append(st.sent, sent{hash: hash, rev: rev})
	if len(st.sent) > keepCompiled {
		st.sent = st.sent[len(st.sent)-keepCompiled:]
	}
	p.mu.Unlock()

	// Record the push before sending it, so that an answer, which may come at once, never finds
	// agent_state without it. A push that cannot be sent stays pending; the next session pushes.
	err = store.WriteTx(p.s.sys, p.s.db, func(tx *ent.Tx) error {
		if err := tx.CompiledSnapshot.Create().SetOrgID(agent.Identity.Org).SetAgentID(id).
			SetDbEpoch(rev.DBEpoch).SetSeq(rev.Seq).SetHash(hash).SetSizeBytes(len(signed.GetPayload())).
			SetPayload(signed.GetPayload()).SetSignature(signed.GetSignature()).SetKeyID(signed.GetKeyId()).
			SetCreatedAt(p.s.now()).Exec(p.s.sys); err != nil {
			return err
		}
		old, err := tx.CompiledSnapshot.Query().Where(compiledsnapshot.AgentID(id)).
			Order(ent.Desc(compiledsnapshot.FieldID)).Offset(keepCompiled).Limit(1 << 20).IDs(p.s.sys)
		if err != nil {
			return err
		}
		if len(old) > 0 {
			if _, err := tx.CompiledSnapshot.Delete().Where(compiledsnapshot.IDIn(old...)).Exec(p.s.sys); err != nil {
				return err
			}
		}
		return updateState(p.s.sys, tx, agent.Identity.Org, id, func(u *ent.AgentStateUpdateOne) {
			u.SetPushedDbEpoch(rev.DBEpoch).SetPushedSeq(rev.Seq).SetPushedHash(hash).SetPushedAt(p.s.now())
		})
	})
	if err != nil {
		p.log.Error("cannot record a snapshot before sending it", "agent", id, "error", err)
	}
	// If the session ended or its queue was full, the agent reconnects and asks again.
	p.s.sendTo(id, epoch, &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: signed}})
}

// checkTimeouts reports snapshots that were not answered within ApplyTimeout, once each; their
// status is derived from agent_state (ApplyStatus).
func (p *pusher) checkTimeouts() {
	now := p.s.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, st := range p.agents {
		if st.pending != nil && !st.timedOut && now.Sub(st.sentAt) >= ApplyTimeout {
			st.timedOut = true
			p.log.Warn("an agent did not answer a snapshot in time", "agent", id, "after", ApplyTimeout)
		}
	}
}

// answer checks an agent's Applied or Rejected against what its session was sent and returns the
// revision of that snapshot; ok is false for a snapshot this session did not send.
func (p *pusher) answer(sess *session, hash []byte, applied bool) (rev store.Revision, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.agents[sess.agent.Identity.ID]
	if st == nil || st.epoch != sess.epoch {
		return rev, false
	}
	i := slices.IndexFunc(st.sent, func(s sent) bool { return bytes.Equal(s.hash, hash) })
	if i < 0 {
		return rev, false
	}
	if applied {
		st.applied = hash
	}
	if bytes.Equal(st.pending, hash) {
		st.pending = nil
	}
	return st.sent[i].rev, true
}

// applied records that the agent applied a snapshot.
func (p *pusher) applied(sess *session, a *agentv1.Applied) {
	rev, ok := p.answer(sess, a.GetHash(), true)
	if !ok {
		p.log.Warn("an agent acknowledged a snapshot it was not sent", "agent", sess.agent.Identity.ID)
		return
	}
	p.record(sess.agent.Identity, func(u *ent.AgentStateUpdateOne) {
		u.SetAppliedDbEpoch(rev.DBEpoch).SetAppliedSeq(rev.Seq).SetAppliedHash(a.GetHash()).SetLastAckAt(p.s.now())
	})
	p.s.readiness(sess.agent.Identity, a.GetNotReady(), true)
}

// rejected records that the agent rejected a snapshot, with a bounded copy of its reasons.
func (p *pusher) rejected(sess *session, r *agentv1.Rejected) {
	rev, ok := p.answer(sess, r.GetHash(), false)
	if !ok {
		p.log.Warn("an agent rejected a snapshot it was not sent", "agent", sess.agent.Identity.ID)
		return
	}
	reasons := make([]map[string]string, 0, min(len(r.GetErrors()), maxRejection))
	for _, e := range r.GetErrors()[:min(len(r.GetErrors()), maxRejection)] {
		reasons = append(reasons, map[string]string{"resource_id": clip(e.GetResourceId()), "message": clip(e.GetMessage())})
	}
	p.log.Warn("an agent rejected its snapshot", "agent", sess.agent.Identity.ID, "seq", rev.Seq, "errors", len(r.GetErrors()))
	p.record(sess.agent.Identity, func(u *ent.AgentStateUpdateOne) {
		u.SetRejectedDbEpoch(rev.DBEpoch).SetRejectedSeq(rev.Seq).SetRejectedHash(r.GetHash()).
			SetLastRejection(reasons).SetLastAckAt(p.s.now())
	})
}

// clip shortens agent-supplied text to maxErrorText bytes of valid UTF-8.
func clip(s string) string {
	return strings.ToValidUTF8(s[:min(len(s), maxErrorText)], "")
}

// record updates the agent's state in its own transaction.
func (p *pusher) record(id pki.Identity, set func(*ent.AgentStateUpdateOne)) {
	err := store.WriteTx(p.s.sys, p.s.db, func(tx *ent.Tx) error {
		return updateState(p.s.sys, tx, id.Org, id.ID, set)
	})
	if err != nil {
		p.log.Error("cannot record an agent's state", "agent", id.ID, "error", err)
	}
}

// updateState creates the agent's state row if there is none and applies set to it.
func updateState(ctx context.Context, tx *ent.Tx, org, id string, set func(*ent.AgentStateUpdateOne)) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_state (agent_id, org_id) VALUES ($1, $2)
		ON CONFLICT (agent_id) DO NOTHING`, id, org); err != nil {
		return err
	}
	u := tx.AgentState.UpdateOneID(id)
	set(u)
	return u.Exec(ctx)
}
