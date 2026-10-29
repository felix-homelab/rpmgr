// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/handoff"
)

type pipeMsg struct{ typ, reason string }

// fakePipe is the new process's end of the status pipe as the old process reads it.
type fakePipe struct{ c chan pipeMsg }

func newFakePipe() *fakePipe { return &fakePipe{c: make(chan pipeMsg, 16)} }

func (p *fakePipe) recv() (string, string, error) {
	m, ok := <-p.c
	if !ok {
		return "", "", io.EOF
	}
	return m.typ, m.reason, nil
}

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

type followed struct {
	ended <-chan struct{}
	done  chan struct{}
}

func follow(t *testing.T, ctx context.Context, p *fakePipe, exited <-chan struct{}, m *gateway.Sessions, deadline time.Time, reload func()) *followed {
	t.Helper()
	return followCut(t, ctx, p, exited, m, deadline, reload, func(string) {})
}

func followCut(t *testing.T, ctx context.Context, p *fakePipe, exited <-chan struct{}, m *gateway.Sessions, deadline time.Time, reload func(), cut func(string)) *followed {
	t.Helper()
	f := &followed{done: make(chan struct{})}
	go func() {
		f.ended = gateway.FollowNew(ctx, p.recv, exited, m, deadline, reload, cut, quietLog())
		close(f.done)
	}()
	return f
}

func (f *followed) returned(t *testing.T) bool {
	t.Helper()
	select {
	case <-f.done:
		return true
	case <-time.After(300 * time.Millisecond):
		return false
	}
}

func twoConnectors(t *testing.T) (*gateway.Sessions, *connector, *connector) {
	t.Helper()
	a := &assignment{known: map[string]bool{cid("con_1"): true, cid("con_2"): true}, routes: map[string][]string{"r1": {cid("con_1"), cid("con_2")}}}
	m := newSessions(a, nil)
	return m, start(t, m, connectorID("con_1"), hello("r1")), start(t, m, connectorID("con_2"), hello("r1"))
}

// TestFollowNew_Moved: the sessions are drained with reason handoff and the old process stops
// accepting only once the new one reports a session of every connector it had.
func TestFollowNew_Moved(t *testing.T) {
	m, c1, c2 := twoConnectors(t)
	p := newFakePipe()
	f := follow(t, context.Background(), p, nil, m, time.Now().Add(time.Minute), func() {})
	for _, c := range []*connector{c1, c2} {
		msg := <-c.msgs
		if msg.GetDrain().GetReason() != "handoff" {
			t.Fatalf("got %v, want Drain with reason handoff", msg)
		}
	}
	p.c <- pipeMsg{gateway.MsgSession, cid("con_1")}
	if f.returned(t) {
		t.Fatal("stopped accepting while a connector had not moved")
	}
	p.c <- pipeMsg{gateway.MsgSession, "con_unknown"} // a connector the old process did not have changes nothing
	if f.returned(t) {
		t.Fatal("stopped accepting for an unknown connector")
	}
	p.c <- pipeMsg{gateway.MsgSession, cid("con_2")}
	if !f.returned(t) {
		t.Fatal("kept accepting although every connector moved")
	}
}

// TestFollowNew_StopsAnyway: a connector that never moves, such as one pinned to QUIC, keeps the
// old process accepting until the drain deadline, the new process exiting or ctx ending, and not
// beyond.
func TestFollowNew_StopsAnyway(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(cancel context.CancelFunc, exited chan struct{}) time.Time
	}{
		{"deadline", func(context.CancelFunc, chan struct{}) time.Time { return time.Now().Add(150 * time.Millisecond) }},
		{"new process exited", func(_ context.CancelFunc, e chan struct{}) time.Time { close(e); return time.Now().Add(time.Minute) }},
		{"context ended", func(c context.CancelFunc, _ chan struct{}) time.Time { c(); return time.Now().Add(time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := twoConnectors(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exited := make(chan struct{})
			deadline := tc.stop(cancel, exited)
			f := follow(t, ctx, newFakePipe(), exited, m, deadline, func() {})
			if !f.returned(t) {
				t.Fatal("kept accepting")
			}
		})
	}
}

// TestFollowNew_Messages: a revocation reloads the deny-list, a successor ends the drain, an
// unknown message is ignored and a closed pipe ends nothing.
func TestFollowNew_Messages(t *testing.T) {
	m, _, _ := twoConnectors(t)
	p := newFakePipe()
	var reloads atomic.Int32
	f := follow(t, context.Background(), p, nil, m, time.Now().Add(time.Minute), func() { reloads.Add(1) })
	p.c <- pipeMsg{gateway.MsgRevoked, ""}
	p.c <- pipeMsg{"bogus", "x"}
	eventually(t, "the deny-list was not reloaded", func() bool { return reloads.Load() == 1 })
	if f.returned(t) {
		t.Fatal("an unknown message stopped the old process")
	}
	p.c <- pipeMsg{gateway.MsgSuccessor, ""}
	if !f.returned(t) {
		t.Fatal("no stop after the successor message")
	}
	select {
	case <-f.ended:
	case <-time.After(time.Second):
		t.Fatal("the drain was not ended by the successor")
	}
}

// TestFollowNew_End: the new process asking to end the drain (D160) ends it at once, as a
// successor does, with every connector still not moved.
func TestFollowNew_End(t *testing.T) {
	m, _, _ := twoConnectors(t)
	p := newFakePipe()
	f := follow(t, context.Background(), p, nil, m, time.Now().Add(time.Minute), func() {})
	if f.returned(t) {
		t.Fatal("the wait for the connectors ended without a reason")
	}
	p.c <- pipeMsg{handoff.MsgEnd, ""}
	if !f.returned(t) {
		t.Fatal("no stop after the end message")
	}
	select {
	case <-f.ended:
	case <-time.After(time.Second):
		t.Fatal("the drain was not ended")
	}
}

func TestFollowNew_PipeClosed(t *testing.T) {
	m, _, _ := twoConnectors(t)
	p := newFakePipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := follow(t, ctx, p, nil, m, time.Now().Add(time.Minute), func() {})
	close(p.c)
	if f.returned(t) {
		t.Fatal("a closed pipe ended the wait; the new process exiting is Exited's business")
	}
}

// TestReportSessions: each connector with a session is reported once, also one that connects
// later; a pipe that fails ends the reporting.
func TestReportSessions(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_1"): true, cid("con_2"): true}, routes: map[string][]string{"r1": {cid("con_1"), cid("con_2")}}}
	m := newSessions(a, nil)
	start(t, m, connectorID("con_1"), hello("r1"))
	got := make(chan string, 8)
	var fail atomic.Bool
	send := func(typ, reason string) error {
		if fail.Load() {
			return errors.New("broken pipe")
		}
		if typ != gateway.MsgSession {
			t.Errorf("sent %q", typ)
		}
		got <- reason
		return nil
	}
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { gateway.ReportSessions(ctx, send, m, quietLog()); close(done) }()
	if c := <-got; c != cid("con_1") {
		t.Fatalf("reported %q", c)
	}
	start(t, m, connectorID("con_2"), hello("r1"))
	if c := <-got; c != cid("con_2") {
		t.Fatalf("reported %q", c)
	}
	select {
	case c := <-got:
		t.Fatalf("%q reported twice", c)
	case <-time.After(300 * time.Millisecond):
	}
	fail.Store(true)
	start(t, m, connectorID("con_1"), hello("r1")) // no news; the failing send is not reached
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reporting did not end")
	}
}

func TestReportSessions_BrokenPipe(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("con_1"): true}, routes: map[string][]string{"r1": {cid("con_1")}}}
	m := newSessions(a, nil)
	start(t, m, connectorID("con_1"), hello("r1"))
	done := make(chan struct{})
	go func() {
		gateway.ReportSessions(context.Background(), func(string, string) error { return errors.New("broken pipe") }, m, quietLog())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the old process is gone, but reporting went on")
	}
}

// TestFollowNew_PipeClosedPollsDenyList: after the pipe broke the old process reads the deny-list
// itself, so a revocation written meanwhile still takes effect, until the drain deadline.
func TestFollowNew_PipeClosedPollsDenyList(t *testing.T) {
	gateway.SetDenyPoll(t, 20*time.Millisecond)
	m, _, _ := twoConnectors(t)
	p := newFakePipe()
	var reloads atomic.Int32
	f := follow(t, context.Background(), p, nil, m, time.Now().Add(400*time.Millisecond), func() { reloads.Add(1) })
	close(p.c)
	eventually(t, "the deny-list was not read after the pipe closed", func() bool { return reloads.Load() >= 3 })
	f.returned(t)
	time.Sleep(500 * time.Millisecond)
	n := reloads.Load()
	time.Sleep(150 * time.Millisecond)
	if reloads.Load() != n {
		t.Fatal("the deny-list is still polled after the drain deadline")
	}
}

// TestFollowNew_Cut: a cut message of the new process resets the connections of its route in the
// old one, one per message.
func TestFollowNew_Cut(t *testing.T) {
	m, _, _ := twoConnectors(t)
	p := newFakePipe()
	var mu sync.Mutex
	var got []string
	followCut(t, context.Background(), p, nil, m, time.Now().Add(time.Minute), func() {}, func(id string) {
		mu.Lock()
		got = append(got, id)
		mu.Unlock()
	})
	p.c <- pipeMsg{gateway.MsgCut, "r1"}
	p.c <- pipeMsg{gateway.MsgCut, "r2"}
	eventually(t, "the cuts did not arrive", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Equal(got, []string{"r1", "r2"})
	})
}
