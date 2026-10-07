// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/compiledsnapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

type controlStream = grpc.BidiStreamingClient[agentv1.AgentMessage, agentv1.ControllerMessage]

// orgResources compiles one resource per org, a stand-in for the resource kinds of later slices.
func orgResources(ctx context.Context, tx *ent.Tx, _ snapshot.Agent) ([]*agentv1.Resource, error) {
	orgs, err := tx.Org.Query().Order(org.ByID()).All(ctx)
	if err != nil {
		return nil, err
	}
	var rs []*agentv1.Resource
	for _, o := range orgs {
		rs = append(rs, &agentv1.Resource{Id: o.ID, Kind: &agentv1.Resource_Reference{
			Reference: &agentv1.ResourceReference{Size: uint64(len(o.Name))}}})
	}
	return rs, nil
}

func pushEnv(t *testing.T, db *store.DB, sources ...snapshot.Source) *sessionEnv {
	t.Helper()
	if len(sources) == 0 {
		sources = []snapshot.Source{orgResources}
	}
	return startSessionsWith(t, db, func(o *controller.SessionsOptions) {
		o.Compiler = &snapshot.Compiler{Sources: sources, Endpoints: func() []string { return []string{"https://ctl.example"} }}
		o.RevisionCheck = 20 * time.Millisecond
	})
}

// recvSnapshot reads the next message, which must be a snapshot, and verifies it as an agent does.
func (e *sessionEnv) recvSnapshot(t *testing.T, st controlStream, id pki.Identity) (*agentv1.Signed, *agentv1.Snapshot) {
	t.Helper()
	m := recv(t, st)
	signed := m.GetSnapshot()
	if signed == nil {
		t.Fatalf("got %v, want a snapshot", m)
	}
	certs := []*x509.Certificate{e.ca.ConfigSigner().Cert, e.ca.Intermediate()}
	snap, err := snapshot.VerifySnapshot(signed, certs, e.ca.Root(), id.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return signed, snap
}

// expectQuiet fails if the controller sends anything within d.
func expectQuiet(t *testing.T, st controlStream, d time.Duration) {
	t.Helper()
	got := make(chan *agentv1.ControllerMessage, 1)
	go func() {
		m, err := st.Recv()
		if err == nil {
			got <- m
		}
	}()
	select {
	case m := <-got:
		t.Fatalf("unexpected message %v", m)
	case <-time.After(d):
	}
}

func send(t *testing.T, st controlStream, m *agentv1.AgentMessage) {
	t.Helper()
	if err := st.Send(m); err != nil {
		t.Fatal(err)
	}
}

func applied(signed *agentv1.Signed, rev *agentv1.Revision) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Applied{Applied: &agentv1.Applied{Revision: rev, Hash: snapshot.Hash(signed)}}}
}

// waitState polls the agent's state until ok accepts it.
func (e *sessionEnv) waitState(t *testing.T, id string, ok func(*ent.AgentState) bool) *ent.AgentState {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := e.db.Client().AgentState.Get(storetest.SystemCtx(t), id)
		if err == nil && ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent state %+v (%v) never matched", st, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPush_SessionRevisionAndAck: a new session gets its snapshot; Applied is recorded; a new
// revision is pushed with the hashes of unchanged resources kept; an agent that reconnects with
// the current snapshot gets none.
func TestPush_SessionRevisionAndAck(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := pushEnv(t, db)
		sys := storetest.SystemCtx(t)
		cert, id := e.agentCert(t)
		h := hello("0.1.0")
		h.AgentTime = nil
		st := e.open(t, testCtx(t), cert, h)
		if recv(t, st).GetWelcome() == nil {
			t.Fatal("no Welcome")
		}
		first, snap1 := e.recvSnapshot(t, st, id)
		if snap1.GetRevision().GetDbEpoch() != e.dbEpoch || len(snap1.GetResources()) != 1 ||
			len(snap1.GetControllerEndpoints()) != 1 {
			t.Fatalf("snapshot %v", snap1)
		}
		state := e.waitState(t, id.ID, func(s *ent.AgentState) bool { return s.PushedAt != nil })
		if !bytes.Equal(state.PushedHash, snapshot.Hash(first)) || state.BootID != "boot-1" ||
			controller.ApplyStatus(state, time.Now()) != controller.ApplyPending {
			t.Fatalf("state after the push: %+v", state)
		}
		rows := e.db.Client().CompiledSnapshot.Query().Where(compiledsnapshot.AgentID(id.ID)).AllX(sys)
		if len(rows) != 1 || !bytes.Equal(rows[0].Payload, first.GetPayload()) || rows[0].KeyID != first.GetKeyId() ||
			rows[0].SizeBytes != len(first.GetPayload()) || rows[0].OrgID != id.Org {
			t.Fatalf("compiled_snapshots: %+v", rows)
		}

		send(t, st, applied(first, snap1.GetRevision()))
		state = e.waitState(t, id.ID, func(s *ent.AgentState) bool { return s.LastAckAt != nil })
		if controller.ApplyStatus(state, time.Now()) != controller.ApplyApplied ||
			state.AppliedSeq != seqOf(snap1.GetRevision()) || state.AppliedDbEpoch != e.dbEpoch {
			t.Fatalf("state after Applied: %+v", state)
		}

		// A new revision, here an unrelated org, is pushed; the existing resource keeps its hash.
		if _, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
			o, err := tx.Org.Create().SetName("org-b").SetSlug("org-b").Save(sys)
			return []string{o.ID}, err
		}); err != nil {
			t.Fatal(err)
		}
		second, snap2 := e.recvSnapshot(t, st, id)
		if snap2.GetRevision().GetSeq() <= snap1.GetRevision().GetSeq() || len(snap2.GetResources()) != 2 {
			t.Fatalf("second snapshot %v", snap2)
		}
		if r := snap2.GetResources(); !bytes.Equal(find(r, e.org).GetHash(), snap1.GetResources()[0].GetHash()) {
			t.Fatal("an unrelated change changed a resource hash")
		}
		send(t, st, applied(second, snap2.GetRevision()))
		e.waitState(t, id.ID, func(s *ent.AgentState) bool { return bytes.Equal(s.AppliedHash, snapshot.Hash(second)) })

		// The agent reconnects with what it runs: no snapshot, and the state says applied.
		h = hello("0.1.0")
		h.LastApplied, h.LastAppliedHash = snap2.GetRevision(), snapshot.Hash(second)
		again := e.open(t, testCtx(t), cert, h)
		if recv(t, again).GetWelcome() == nil {
			t.Fatal("no Welcome")
		}
		expectQuiet(t, again, 300*time.Millisecond)
		state = e.db.Client().AgentState.GetX(sys, id.ID)
		if controller.ApplyStatus(state, time.Now()) != controller.ApplyApplied {
			t.Fatalf("state after a reconnect in sync: %+v", state)
		}
	})
}

// seqOf returns a revision's sequence number as agent_state stores it.
func seqOf(r *agentv1.Revision) int64 { return int64(r.GetSeq()) } //nolint:gosec // G115: test revisions are small

func find(rs []*agentv1.Resource, id string) *agentv1.Resource {
	for _, r := range rs {
		if r.GetId() == id {
			return r
		}
	}
	return nil
}

// TestPush_StaleHelloGetsSnapshot: an agent that reconnects with an older snapshot gets the
// current one.
func TestPush_StaleHelloGetsSnapshot(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := pushEnv(t, db)
	cert, id := e.agentCert(t)
	h := hello("0.1.0")
	h.LastApplied, h.LastAppliedHash = &agentv1.Revision{DbEpoch: e.dbEpoch, Seq: 0}, bytes.Repeat([]byte{1}, 32)
	st := e.open(t, testCtx(t), cert, h)
	recv(t, st)
	e.recvSnapshot(t, st, id)
}

// TestPush_Rejected: a rejection is recorded with a bounded copy of its reasons, and the status is
// rejected.
func TestPush_Rejected(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := pushEnv(t, db)
	cert, id := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, st)
	signed, snap := e.recvSnapshot(t, st, id)
	var errs []*agentv1.SnapshotError
	for range 40 {
		errs = append(errs, &agentv1.SnapshotError{ResourceId: "rt_1", Message: strings.Repeat("é", 400)})
	}
	send(t, st, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Rejected{Rejected: &agentv1.Rejected{
		Revision: snap.GetRevision(), Hash: snapshot.Hash(signed), Errors: errs}}})
	state := e.waitState(t, id.ID, func(s *ent.AgentState) bool { return len(s.RejectedHash) > 0 })
	if controller.ApplyStatus(state, time.Now()) != controller.ApplyRejected || state.RejectedSeq != seqOf(snap.GetRevision()) {
		t.Fatalf("state: %+v", state)
	}
	if len(state.LastRejection) != 32 {
		t.Fatalf("%d reasons stored, want 32", len(state.LastRejection))
	}
	for _, r := range state.LastRejection {
		if len(r["message"]) > 512 || !utf8.ValidString(r["message"]) || r["resource_id"] != "rt_1" {
			t.Fatalf("reason not bounded to 512 bytes of UTF-8: %d bytes", len(r["message"]))
		}
	}
	if len(state.AppliedHash) != 0 {
		t.Fatal("a rejection was recorded as applied")
	}
}

// TestPush_AnswerForUnsentSnapshotIgnored: Applied or Rejected with a hash the session was not
// sent changes nothing.
func TestPush_AnswerForUnsentSnapshotIgnored(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := pushEnv(t, db)
	cert, id := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, st)
	_, snap := e.recvSnapshot(t, st, id)
	before := e.waitState(t, id.ID, func(s *ent.AgentState) bool { return s.PushedAt != nil })
	forged := bytes.Repeat([]byte{7}, 32)
	send(t, st, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Applied{Applied: &agentv1.Applied{Revision: snap.GetRevision(), Hash: forged}}})
	send(t, st, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Rejected{Rejected: &agentv1.Rejected{Revision: snap.GetRevision(), Hash: forged}}})
	time.Sleep(200 * time.Millisecond)
	after := e.db.Client().AgentState.GetX(storetest.SystemCtx(t), id.ID)
	if len(after.AppliedHash) != 0 || len(after.RejectedHash) != 0 || after.LastAckAt != nil ||
		controller.ApplyStatus(after, time.Now()) != controller.ApplyStatus(before, time.Now()) {
		t.Fatalf("an answer for an unsent snapshot was recorded: %+v", after)
	}
}

// TestPush_KeepsLastFive: compiled_snapshots keeps the last five snapshots of an agent.
func TestPush_KeepsLastFive(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := pushEnv(t, db)
	sys := storetest.SystemCtx(t)
	cert, id := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, st)
	var last *agentv1.Snapshot
	_, last = e.recvSnapshot(t, st, id)
	for i := range 7 {
		if _, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
			return nil, tx.Org.UpdateOneID(e.org).SetName(strings.Repeat("n", i+1)).Exec(sys)
		}); err != nil {
			t.Fatal(err)
		}
		_, last = e.recvSnapshot(t, st, id)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows := e.db.Client().CompiledSnapshot.Query().Where(compiledsnapshot.AgentID(id.ID)).
			Order(ent.Asc(compiledsnapshot.FieldID)).AllX(sys)
		if len(rows) == 5 && rows[4].Seq == seqOf(last.GetRevision()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d compiled snapshots kept", len(rows))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPush_RetriesAfterCompileError: a snapshot that cannot be compiled is retried at the next
// revision check, without a new revision.
func TestPush_RetriesAfterCompileError(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	var fails atomic.Int32
	fails.Store(3)
	flaky := func(context.Context, *ent.Tx, snapshot.Agent) ([]*agentv1.Resource, error) {
		if fails.Add(-1) >= 0 {
			return nil, errors.New("flaky")
		}
		return nil, nil
	}
	e := pushEnv(t, db, orgResources, flaky)
	cert, id := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, st)
	e.recvSnapshot(t, st, id)
}

// TestPush_SupersededSessionGetsNothing: after a newer session of the agent took over, snapshots
// go to the newer session only.
func TestPush_SupersededSessionGetsNothing(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := pushEnv(t, db)
	cert, id := e.agentCert(t)
	old := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, old)
	e.recvSnapshot(t, old, id)
	cur := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, cur)
	e.recvSnapshot(t, cur, id)
	if g := recv(t, old).GetGoodbye(); g == nil {
		t.Fatal("the older session was not ended")
	}
}

// TestApplyStatus covers the derivation at the ApplyTimeout boundary.
func TestApplyStatus(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h1, h2 := []byte{1}, []byte{2}
	tests := []struct {
		name string
		st   ent.AgentState
		now  time.Time
		want controller.ApplyState
	}{
		{"nothing sent", ent.AgentState{}, at, controller.ApplyPending},
		{"sent", ent.AgentState{PushedHash: h1, PushedAt: &at}, at, controller.ApplyPending},
		{"just before the timeout", ent.AgentState{PushedHash: h1, PushedAt: &at}, at.Add(controller.ApplyTimeout - time.Nanosecond), controller.ApplyPending},
		{"at the timeout", ent.AgentState{PushedHash: h1, PushedAt: &at}, at.Add(controller.ApplyTimeout), controller.ApplyTimedOut},
		{"applied", ent.AgentState{PushedHash: h1, PushedAt: &at, AppliedHash: h1}, at.Add(time.Hour), controller.ApplyApplied},
		{"older applied", ent.AgentState{PushedHash: h2, PushedAt: &at, AppliedHash: h1}, at, controller.ApplyPending},
		{"rejected", ent.AgentState{PushedHash: h2, PushedAt: &at, AppliedHash: h1, RejectedHash: h2}, at.Add(time.Hour), controller.ApplyRejected},
		{"older rejected", ent.AgentState{PushedHash: h2, PushedAt: &at, RejectedHash: h1}, at.Add(time.Hour), controller.ApplyTimedOut},
	}
	for _, tt := range tests {
		if got := controller.ApplyStatus(&tt.st, tt.now); got != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, got, tt.want)
		}
	}
}
