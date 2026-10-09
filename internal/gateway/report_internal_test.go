// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// fakeSession is a session with a transport and, for QUIC, a round-trip time.
type fakeSession struct {
	tunnel.Session
	transport string
	rtt       time.Duration
}

func (f fakeSession) Transport() string { return f.transport }

type rttSession struct{ fakeSession }

func (r rttSession) RTT() time.Duration { return r.rtt }

// TestReport: one entry per connector and transport, sorted, with the lowest round-trip time a
// session knows; none for h2, which does not measure it.
func TestReport(t *testing.T) {
	m := NewSessions(SessionsOptions{})
	for _, d := range []*dataSession{
		{connector: "con_b", s: rttSession{fakeSession{transport: "quic", rtt: 30 * time.Millisecond}}},
		{connector: "con_b", s: rttSession{fakeSession{transport: "quic", rtt: 0}}},
		{connector: "con_b", s: rttSession{fakeSession{transport: "quic", rtt: 20 * time.Millisecond}}},
		{connector: "con_a", s: fakeSession{transport: "h2"}},
		{connector: "con_a", s: fakeSession{transport: "h2"}},
		{connector: "con_a", s: rttSession{fakeSession{transport: "quic", rtt: 5 * time.Millisecond}}},
	} {
		m.add(d)
	}
	got := m.Report()
	want := []struct {
		con string
		tr  agentv1.Transport
		rtt time.Duration
	}{{"con_a", agentv1.Transport_TRANSPORT_QUIC, 5 * time.Millisecond}, {"con_a", agentv1.Transport_TRANSPORT_H2, 0},
		{"con_b", agentv1.Transport_TRANSPORT_QUIC, 20 * time.Millisecond}}
	if len(got) != len(want) {
		t.Fatalf("report %v", got)
	}
	for i, w := range want {
		if got[i].GetConnectorId() != w.con || got[i].GetTransport() != w.tr || got[i].GetRtt().AsDuration() != w.rtt ||
			w.rtt == 0 && got[i].GetRtt() != nil {
			t.Errorf("entry %d: %v, want %+v", i, got[i], w)
		}
	}
}

// TestReporter: a change is reported about a second later, several at once only once, and
// otherwise every interval; a cancelled context stops it.
func TestReporter(t *testing.T) {
	r := newReporter()
	sent := make(chan time.Time, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run(ctx, time.Hour, func(m *agentv1.AgentMessage) bool {
			if m.GetStatus() == nil {
				t.Error("a report that is not a Status")
			}
			sent <- time.Now()
			return true
		}, func() []*agentv1.DataSession { return nil })
	}()
	start := time.Now()
	r.change()
	r.change()
	r.change()
	select {
	case at := <-sent:
		if d := at.Sub(start); d < reportAfter-50*time.Millisecond || d > 3*reportAfter {
			t.Fatalf("the change was reported after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no report of the change")
	}
	select {
	case <-sent:
		t.Fatal("three changes made two reports")
	case <-time.After(2 * reportAfter):
	}
	cancel()
	<-done

	r = newReporter()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx, 50*time.Millisecond, func(*agentv1.AgentMessage) bool { sent <- time.Now(); return true },
		func() []*agentv1.DataSession { return nil })
	for range 3 {
		select {
		case <-sent:
		case <-time.After(5 * time.Second):
			t.Fatal("no periodic report")
		}
	}
}
