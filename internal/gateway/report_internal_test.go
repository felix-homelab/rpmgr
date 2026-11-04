// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
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

// TestReport: one entry per connector and transport, wss its own, sorted, with the lowest
// round-trip time a session knows; none for h2 and wss, which do not measure it.
func TestReport(t *testing.T) {
	m := NewSessions(SessionsOptions{})
	for _, d := range []*dataSession{
		{connector: "con_b", s: rttSession{fakeSession{transport: "quic", rtt: 30 * time.Millisecond}}},
		{connector: "con_b", s: rttSession{fakeSession{transport: "quic", rtt: 0}}},
		{connector: "con_b", s: rttSession{fakeSession{transport: "quic", rtt: 20 * time.Millisecond}}},
		{connector: "con_a", s: fakeSession{transport: "h2"}},
		{connector: "con_a", s: fakeSession{transport: "h2"}},
		{connector: "con_a", s: fakeSession{transport: "wss"}},
		{connector: "con_a", s: rttSession{fakeSession{transport: "quic", rtt: 5 * time.Millisecond}}},
	} {
		if err := m.add(d); err != nil {
			t.Fatal(err)
		}
	}
	got := m.Report()
	want := []struct {
		con string
		tr  agentv1.Transport
		rtt time.Duration
	}{{"con_a", agentv1.Transport_TRANSPORT_QUIC, 5 * time.Millisecond}, {"con_a", agentv1.Transport_TRANSPORT_H2, 0},
		{"con_a", agentv1.Transport_TRANSPORT_WSS, 0}, {"con_b", agentv1.Transport_TRANSPORT_QUIC, 20 * time.Millisecond}}
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

// TestReport_ReadyRoutes: a connector on auto with a QUIC and an HTTP/2 session reports each
// route on the transport of the sessions that have it ready; a route not ready is left out, and
// every entry says it names the routes.
func TestReport_ReadyRoutes(t *testing.T) {
	m := NewSessions(SessionsOptions{})
	for _, d := range []*dataSession{
		{connector: "con_a", s: fakeSession{transport: "quic"}, ready: map[string]bool{"rte_1": true, "rte_3": false}},
		{connector: "con_a", s: fakeSession{transport: "quic"}, ready: map[string]bool{"rte_4": true}},
		{connector: "con_a", s: fakeSession{transport: "h2"}, ready: map[string]bool{"rte_2": true}},
		{connector: "con_b", s: fakeSession{transport: "wss"}},
	} {
		if err := m.add(d); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string][]string{"con_a/1": {"rte_1", "rte_4"}, "con_a/2": {"rte_2"}, "con_b/3": nil}
	for _, d := range m.Report() {
		if !d.GetReadyRoutesKnown() {
			t.Errorf("%v does not say it names the routes", d)
		}
		k := d.GetConnectorId() + "/" + string(rune('0'+int(d.GetTransport()))) //nolint:gosec // G115: transports are single digits
		if got := d.GetReadyRoutes(); !slices.Equal(got, want[k]) {
			t.Errorf("%s: routes %v, want %v", k, got, want[k])
		}
		delete(want, k)
	}
	if len(want) != 0 {
		t.Errorf("not reported: %v", want)
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
		}, func() *agentv1.Status { return &agentv1.Status{} })
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
		func() *agentv1.Status { return &agentv1.Status{} })
	for range 3 {
		select {
		case <-sent:
		case <-time.After(5 * time.Second):
			t.Fatal("no periodic report")
		}
	}
}

// TestReporter_ChangeDuringWait: a change signalled while a report waits is in that report, so it
// makes no second one (#542); a change after the report makes the next.
func TestReporter_ChangeDuringWait(t *testing.T) {
	r := newReporter()
	sent := make(chan time.Time, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx, time.Hour, func(*agentv1.AgentMessage) bool { sent <- time.Now(); return true },
		func() *agentv1.Status { return &agentv1.Status{} })
	r.change()
	deadline := time.Now().Add(5 * time.Second)
	for len(r.changed) != 0 { // until the reporter has taken the signal and waits
		if time.Now().After(deadline) {
			t.Fatal("the reporter never took the change")
		}
		time.Sleep(time.Millisecond)
	}
	r.change()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("no report of the changes")
	}
	select {
	case <-sent:
		t.Fatal("a change made during the wait made a second report")
	case <-time.After(2 * reportAfter):
	}
	r.change()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("no report of a change after the report")
	}
}
