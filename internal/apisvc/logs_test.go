// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/store/ent/session"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// fakeLogs opens live logs on the agents it knows: each streams its lines, a line ending in "…"
// marked as cut, then ends with the agent's error from ends, or else waits until the stream is
// closed; an unknown agent is unavailable.
type fakeLogs struct {
	mu     sync.Mutex
	lines  map[string][]string // by agent
	ends   map[string]error    // how the agent ends its stream after its lines, by agent
	onOpen func()              // runs as an operation opens, if set
	params []*agentv1.LogParams
	closed []string // the reasons streams were closed with
}

func (f *fakeLogs) OpenLogs(_ context.Context, agentID string, p *agentv1.LogParams) (apisvc.LogStream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lines, ok := f.lines[agentID]
	if !ok {
		return nil, apisvc.ErrLogsUnavailable
	}
	f.params = append(f.params, p)
	if f.onOpen != nil {
		f.onOpen()
	}
	return &fakeStream{f: f, lines: slices.Clone(lines), end: f.ends[agentID], done: make(chan struct{})}, nil
}

func (f *fakeLogs) reasons() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.closed)
}

type fakeStream struct {
	f     *fakeLogs
	lines []string
	end   error
	done  chan struct{}
	once  sync.Once
}

func (s *fakeStream) Recv() (*agentv1.AttachFrame, error) {
	if len(s.lines) > 0 {
		l := s.lines[0]
		s.lines = s.lines[1:]
		return &agentv1.AttachFrame{Frame: &agentv1.AttachFrame_Log{Log: &agentv1.LogLine{Level: "info", Text: l, DroppedBefore: 2,
			Truncated: strings.HasSuffix(l, "…")}}}, nil
	}
	if s.end != nil {
		return nil, s.end
	}
	<-s.done
	return nil, io.EOF
}

func (s *fakeStream) Close(reason string) {
	s.once.Do(func() {
		s.f.mu.Lock()
		s.f.closed = append(s.f.closed, reason)
		s.f.mu.Unlock()
		close(s.done)
	})
}

// TestLiveLogs_CrossOrgRefused (docs/12-testing-and-quality.md, "Security testing"): an Owner or
// Admin streams the live log of the org's connector or gateway, which is audited as
// agent.logs_open, and cancelling the stream ends it on the agent; an Operator, a Viewer and a
// token without agents.logs are refused; another org's agent is NOT_FOUND to them; an offline
// agent is UNAVAILABLE; a user's third stream and an agent's fifth are refused; and the lines a
// stream carries never reach the controller's own log (a clause of TestSecretsNeverLogged).
func TestLiveLogs_CrossOrgRefused(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	con := e.addConnector(t, org, "nas", nil).ID
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	conB := e.addConnector(t, orgB, "theirs", nil).ID
	const leaked = "a line text the controller must never log"
	e.logs.Secret(leaked)
	e.agents.lines = map[string][]string{con: {"first", leaked}, gw.GetId(): {"gateway line"}, conB: {"org b"}}

	// open streams an agent's log and returns its first n lines, and the stream's cancel.
	open := func(b *browser, agent string, n int) ([]*rpmgrv1.LogLine, context.CancelFunc, error) {
		sctx, cancel := context.WithCancel(ctx)
		st, err := b.logs.StreamLogs(sctx, connect.NewRequest(&rpmgrv1.StreamLogsRequest{AgentId: agent, Level: "debug", Filter: "x",
			RaiseToDebug: true}))
		if err != nil {
			cancel()
			return nil, nil, err
		}
		var got []*rpmgrv1.LogLine
		for len(got) < n && st.Receive() {
			if l := st.Msg().GetLine(); l != nil { // not a heartbeat
				got = append(got, l)
			}
		}
		if len(got) < n {
			cancel()
			return got, nil, st.Err()
		}
		return got, cancel, nil
	}
	lines, cancel, err := open(ada, con, 2)
	if err != nil || lines[0].GetText() != "first" || lines[1].GetText() != leaked || lines[0].GetDroppedBefore() != 2 {
		t.Fatalf("the Owner's stream: %v %v", lines, err)
	}
	if p := e.agents.params[0]; p.GetLevel() != "debug" || p.GetFilter() != "x" || !p.GetRaiseToDebug() {
		t.Errorf("the operation's parameters: %v", p)
	}
	cancel()
	waitUntil(t, "the cancel to reach the agent", func() bool { return slices.Contains(e.agents.reasons(), "the viewer left") })
	opened := e.db.Client().AuditEntry.Query().Where(auditentry.Action("agent.logs_open"), auditentry.TargetID(con)).AllX(e.sys)
	if len(opened) != 1 || opened[0].ActorID != e.ada || opened[0].OrgID == nil || *opened[0].OrgID != org ||
		opened[0].Reason != `level "debug", filter "x", raise to debug true` {
		t.Fatalf("the audit entries: %+v", opened)
	}
	if lines, cancel, err := open(ada, gw.GetId(), 1); err != nil || lines[0].GetText() != "gateway line" {
		t.Fatalf("a gateway's log: %v %v", lines, err)
	} else {
		cancel()
	}

	if err := ada.stepUp(pw, ""); err != nil { // inviting an Admin takes a step-up
		t.Fatal(err)
	}
	for role, want := range map[string]connect.Code{"admin": 0, "operator": connect.CodePermissionDenied, "viewer": connect.CodePermissionDenied} {
		b, _ := e.join(t, ada, org, role+"@example.com", role)
		_, cancel, err := open(b, con, 1)
		if codeOrOK(err) != want {
			t.Errorf("%s: %v, want %v", role, err, want)
		}
		if cancel != nil {
			cancel()
		}
	}
	// A token holds only the scopes it was given.
	for scopes, want := range map[string]connect.Code{"org.read": connect.CodePermissionDenied, "agents.logs": 0} {
		pat, err := ada.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "logs-" + scopes,
			Scopes: []string{scopes}}))
		if err != nil {
			t.Fatal(err)
		}
		bot := e.browser()
		bot.bearer = pat.Msg.GetToken()
		_, cancel, err := open(bot, con, 1)
		if cancel != nil {
			cancel()
		}
		if codeOrOK(err) != want {
			t.Errorf("a token with %s: %v", scopes, err)
		}
	}
	if _, _, err := open(bob, con, 1); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("another org's connector: %v", err)
	}
	if _, _, err := open(ada, conB, 1); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("Ada for org B's connector: %v", err)
	}
	offline := e.addConnector(t, org, "offline", nil).ID
	if _, _, err := open(ada, offline, 1); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("an offline connector: %v", err)
	}
	if _, _, err := open(ada, "rte_01JA3B5C7D9E1F2G3H4J5K6M7N", 1); err == nil {
		t.Error("a route's ID was taken for an agent")
	}

	// Limits: two streams per user, four per agent.
	var cancels []context.CancelFunc
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()
	for range 2 {
		_, c, err := open(ada, con, 1)
		if err != nil {
			t.Fatal(err)
		}
		cancels = append(cancels, c)
	}
	if _, _, err := open(ada, gw.GetId(), 1); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("a user's third stream: %v", err)
	}
	for _, email := range []string{"a2@example.com", "a3@example.com"} {
		b, _ := e.join(t, ada, org, email, "admin")
		_, c, err := open(b, con, 1)
		if err != nil {
			t.Fatal(err)
		}
		cancels = append(cancels, c)
	}
	a4, _ := e.join(t, ada, org, "a4@example.com", "admin")
	if _, _, err := open(a4, con, 1); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("an agent's fifth stream: %v", err)
	}
	for _, c := range cancels {
		c()
	}
	cancels = nil
	waitUntil(t, "the limits to free up", func() bool {
		_, c, err := open(a4, con, 1)
		if c != nil {
			c()
		}
		return err == nil
	})
	if errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// codeOrOK is err's code, or 0 without an error.
func codeOrOK(err error) connect.Code {
	if err == nil {
		return 0
	}
	return connect.CodeOf(err)
}

// waitUntil retries ok for up to 5 s.
func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal(what)
}

// TestStreamLogs_Heartbeat: a stream without lines sends empty messages, so that no proxy takes it
// for idle.
func TestStreamLogs_Heartbeat(t *testing.T) {
	apisvc.SetLogHeartbeat(t, 50*time.Millisecond)
	e, ada, org, _ := gatewayEnv(t)
	con := e.addConnector(t, org, "quiet", nil).ID
	e.agents.lines = map[string][]string{con: nil}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := ada.logs.StreamLogs(ctx, connect.NewRequest(&rpmgrv1.StreamLogsRequest{AgentId: con}))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if !st.Receive() || st.Msg().GetLine() != nil {
			t.Fatalf("a heartbeat: %v %v", st.Msg(), st.Err())
		}
	}
}

// TestStreamLogs_Ends: a stream ends without an error when the agent ends the operation or the
// operation reaches its deadline, and with UNAVAILABLE when the operation breaks off, as when the agent goes offline or
// is revoked; a cut line and the lines dropped before one reach the viewer; an agent_id that names
// no connector or gateway is INVALID_ARGUMENT.
func TestStreamLogs_Ends(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	done := e.addConnector(t, org, "done", nil).ID
	cut := e.addConnector(t, org, "cut", nil).ID
	late := e.addConnector(t, org, "late", nil).ID
	e.agents.lines = map[string][]string{done: {"a long line…"}, cut: {"before the cut"}, late: {"until the deadline"}}
	e.agents.ends = map[string]error{done: io.EOF, cut: errors.New("controller: the operation ended: the agent's control session ended: revoked"),
		late: fmt.Errorf("%w: controller: the operation reached its deadline", apisvc.ErrLogsDeadline)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	read := func(agent string) ([]*rpmgrv1.LogLine, error) {
		st, err := ada.logs.StreamLogs(ctx, connect.NewRequest(&rpmgrv1.StreamLogsRequest{AgentId: agent}))
		if err != nil {
			return nil, err
		}
		var got []*rpmgrv1.LogLine
		for st.Receive() {
			if l := st.Msg().GetLine(); l != nil {
				got = append(got, l)
			}
		}
		return got, st.Err()
	}
	if got, err := read(done); err != nil || len(got) != 1 || !got[0].GetTruncated() || got[0].GetDroppedBefore() != 2 {
		t.Errorf("a stream the agent ended: %v %v", got, err)
	}
	if got, err := read(late); err != nil || len(got) != 1 {
		t.Errorf("a stream at its deadline: %v %v", got, err)
	}
	if got, err := read(cut); connect.CodeOf(err) != connect.CodeUnavailable || !strings.Contains(err.Error(), "revoked") || len(got) != 1 ||
		got[0].GetTruncated() {
		t.Errorf("a stream that broke off: %v %v", got, err)
	}
	// An org's own ID passes the interceptor as its org, but names no agent.
	if _, err := read(org); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an org ID as the agent: %v", err)
	}
	waitUntil(t, "the streams to be closed", func() bool { return len(e.agents.reasons()) == 3 })
}

// TestStreamLogs_AccessRechecked: a stream admits its caller again while it runs: an Admin
// demoted to Viewer, or removed from the org, loses the stream with PERMISSION_DENIED, and a token
// that is revoked with UNAUTHENTICATED; each time the operation on the agent ends.
func TestStreamLogs_AccessRechecked(t *testing.T) {
	apisvc.SetLogRecheck(t, 50*time.Millisecond)
	e, ada, org, _ := gatewayEnv(t)
	con := e.addConnector(t, org, "nas", nil).ID
	e.agents.lines = map[string][]string{con: nil}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := ada.stepUp(pw, ""); err != nil { // inviting an Admin takes a step-up
		t.Fatal(err)
	}
	// follow streams the connector's log as b and returns the code it ends with; change runs once
	// the stream is open.
	follow := func(b *browser, change func()) connect.Code {
		st, err := b.logs.StreamLogs(ctx, connect.NewRequest(&rpmgrv1.StreamLogsRequest{AgentId: con}))
		if err != nil {
			t.Fatal(err)
		}
		change()
		for st.Receive() {
		}
		return connect.CodeOf(st.Err())
	}
	demoted, demotedID := e.join(t, ada, org, "demoted@example.com", "admin")
	if code := follow(demoted, func() {
		e.db.Client().Membership.Update().Where(membership.UserID(demotedID), membership.OrgID(org)).SetRole("viewer").ExecX(e.sys)
	}); code != connect.CodePermissionDenied {
		t.Errorf("a demoted Admin's stream ended with %v", code)
	}
	removed, removedID := e.join(t, ada, org, "removed@example.com", "admin")
	if code := follow(removed, func() {
		e.db.Client().Membership.Delete().Where(membership.UserID(removedID), membership.OrgID(org)).ExecX(e.sys)
	}); code != connect.CodePermissionDenied {
		t.Errorf("a removed Admin's stream ended with %v", code)
	}
	pat, err := ada.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "logs",
		Scopes: []string{"agents.logs"}}))
	if err != nil {
		t.Fatal(err)
	}
	bot := e.browser()
	bot.bearer = pat.Msg.GetToken()
	if code := follow(bot, func() {
		if _, err := ada.token.RevokeAPIToken(ctx, connect.NewRequest(&rpmgrv1.RevokeAPITokenRequest{OrgId: org,
			TokenId: pat.Msg.GetApiToken().GetId()})); err != nil {
			t.Fatal(err)
		}
	}); code != connect.CodeUnauthenticated {
		t.Errorf("a revoked token's stream ended with %v", code)
	}
	waitUntil(t, "the operations to end", func() bool { return len(e.agents.reasons()) == 3 })
}

// TestStreamLogs_AuditFailsClosed: a live log whose agent.logs_open entry cannot be written is not
// streamed: the open fails, no line reaches the viewer, and the operation on the agent ends.
func TestStreamLogs_AuditFailsClosed(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	con := e.addConnector(t, org, "nas", nil).ID
	e.agents.lines = map[string][]string{con: {"a line nobody may read unaudited"}}
	e.agents.onOpen = func() {
		if _, err := e.db.Writer.ExecContext(context.Background(),
			"CREATE TRIGGER no_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END"); err != nil {
			t.Error(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := ada.logs.StreamLogs(ctx, connect.NewRequest(&rpmgrv1.StreamLogsRequest{AgentId: con}))
	if err == nil {
		for st.Receive() {
			if l := st.Msg().GetLine(); l != nil {
				t.Fatalf("a line without its audit entry: %v", l)
			}
		}
		err = st.Err()
	}
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("an open whose audit failed: %v", err)
	}
	waitUntil(t, "the operation to end", func() bool { return len(e.agents.reasons()) == 1 })
}

// TestStreamLogs_RecheckIsNoActivity: the recheck of an open live log does not keep an idle web
// session alive: the session's idle expiry stays where the user's last request left it, and once
// it passes, the stream ends with UNAUTHENTICATED at the next recheck.
func TestStreamLogs_RecheckIsNoActivity(t *testing.T) {
	apisvc.SetLogRecheck(t, 50*time.Millisecond)
	e, ada, org, _ := gatewayEnv(t)
	con := e.addConnector(t, org, "nas", nil).ID
	e.agents.lines = map[string][]string{con: nil}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := ada.stepUp(pw, ""); err != nil { // inviting an Admin takes a step-up
		t.Fatal(err)
	}
	viewer, id := e.join(t, ada, org, "idle@example.com", "admin")
	st, err := viewer.logs.StreamLogs(ctx, connect.NewRequest(&rpmgrv1.StreamLogsRequest{AgentId: con}))
	if err != nil {
		t.Fatal(err)
	}
	// The session was last used long enough ago that a request would move its idle expiry on, and
	// it has a short while left.
	sess := e.db.Client().Session.Query().Where(session.UserID(id)).OnlyX(e.sys)
	seen, idle := e.clock.Add(-10*time.Minute), e.clock.Add(time.Minute)
	e.db.Client().Session.UpdateOneID(sess.ID).SetLastSeenAt(seen).SetIdleExpiresAt(idle).ExecX(e.sys)
	time.Sleep(300 * time.Millisecond) // several rechecks
	if got := e.db.Client().Session.GetX(e.sys, sess.ID); !got.LastSeenAt.Equal(seen) || !got.IdleExpiresAt.Equal(idle) {
		t.Fatalf("a recheck moved the session on: last seen %v, idle until %v", got.LastSeenAt, got.IdleExpiresAt)
	}
	// The idle expiry passes.
	e.db.Client().Session.UpdateOneID(sess.ID).SetIdleExpiresAt(e.clock).ExecX(e.sys)
	for st.Receive() {
	}
	if code := connect.CodeOf(st.Err()); code != connect.CodeUnauthenticated {
		t.Errorf("the stream of an expired session ended with %v", code)
	}
}
