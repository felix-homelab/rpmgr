// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"sync"
	"testing"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// clock is a settable time for Sessions.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// count drains the streams a connector was asked to open and counts them.
func count(cs ...*connector) int {
	n := 0
	for _, c := range cs {
		for done := false; !done; {
			select {
			case <-c.opens:
				n++
			case <-time.After(50 * time.Millisecond):
				done = true
			}
		}
	}
	return n
}

// TestSessions_PassiveHealth (docs/03-connections.md, "Target health"): after 3 refused or timed
// out opens in a row, an entry is passed over for 10 s; then one stream tries it again, and a
// failure doubles the back-off, up to 60 s, while a success restores the entry. Other results,
// such as OVERLOADED, never mark an entry. An entry that is the last one left is still tried, and
// each gateway decides alone.
func TestSessions_PassiveHealth(t *testing.T) {
	a := &assignment{known: map[string]bool{cid("ph_1"): true, cid("ph_2"): true}, ranked: map[string][]gateway.RouteConnector{
		"r1": {{ID: cid("ph_1"), Weight: 1, Ranked: true}, {ID: cid("ph_2"), Priority: 5, Weight: 1, Ranked: true}}}}
	clk := &clock{now: time.Unix(1_800_000_000, 0)}
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: a, Now: clk.Now})
	primary, failover := start(t, m, connectorID("ph_1"), hello("r1")), start(t, m, connectorID("ph_2"), hello("r1"))
	open := func(m *gateway.Sessions) tunnelv1.ResultCode {
		t.Helper()
		st, code, err := m.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "r1"})
		if err != nil {
			t.Fatal(err)
		}
		if st != nil {
			_ = st.Close()
		}
		return code
	}
	opens := func(n int) {
		t.Helper()
		for range n {
			if code := open(m); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
				t.Fatalf("an open: %s, want the failover's stream", code)
			}
		}
	}

	// OVERLOADED is no failure of the target: the entry is tried by every open.
	primary.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_OVERLOADED))
	opens(5)
	if n := count(primary); n != 5 {
		t.Fatalf("%d opens tried an overloaded entry, want 5", n)
	}
	_ = count(failover)

	// Marked after the third refusal in a row: the fourth and fifth open go to the failover only.
	primary.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED))
	opens(5)
	if n, f := count(primary), count(failover); n != 3 || f != 5 {
		t.Fatalf("the refusing entry was tried %d times and the failover %d, want 3 and 5", n, f)
	}
	if p, ok := m.BestPriority("r1"); !ok || p != 5 {
		t.Fatalf("the best priority %d %v while the entry is marked, want 5", p, ok)
	}

	// After 10 s one stream tries it; it fails again, so 20 s pass before the next try.
	clk.advance(10 * time.Second)
	opens(3)
	if n := count(primary); n != 1 {
		t.Fatalf("%d tries after the back-off, want 1", n)
	}
	clk.advance(10 * time.Second)
	opens(1)
	if n := count(primary); n != 0 {
		t.Fatalf("%d tries 10 s into a 20 s back-off", n)
	}
	clk.advance(10 * time.Second)
	opens(1)
	if n := count(primary); n != 1 {
		t.Fatalf("%d tries after a 20 s back-off, want 1", n)
	}
	// The back-off doubles to at most 60 s: 40 s, then 60 s, then 60 s again.
	for _, wait := range []time.Duration{40 * time.Second, 60 * time.Second, 60 * time.Second} {
		clk.advance(wait - time.Second)
		opens(1)
		if n := count(primary); n != 0 {
			t.Fatalf("a try 1 s before the end of a %v back-off", wait)
		}
		clk.advance(time.Second)
		opens(1)
		if n := count(primary); n != 1 {
			t.Fatalf("%d tries after a %v back-off, want 1", n, wait)
		}
	}

	// A trial that succeeds restores the entry: the next streams go to it again.
	_ = count(failover)
	primary.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_NO_ERROR))
	clk.advance(60 * time.Second)
	opens(4)
	if n, f := count(primary), count(failover); n != 4 || f != 0 {
		t.Fatalf("after a successful try: %d streams on the entry and %d on the failover, want 4 and 0", n, f)
	}

	// Another gateway learnt nothing of this one's failures and tries the entry.
	m2 := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_02", Assignment: a, Now: clk.Now})
	other := start(t, m2, connectorID("ph_1"), hello("r1"))
	_ = start(t, m2, connectorID("ph_2"), hello("r1"))
	primary.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT))
	opens(3) // marks it on the first gateway
	_ = count(primary)
	other.answer.Store(int32(tunnelv1.ResultCode_RESULT_CODE_NO_ERROR))
	if code := open(m2); code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR || count(other) != 1 {
		t.Fatalf("the other gateway: %s", code)
	}
	opens(1)
	if n := count(primary); n != 0 {
		t.Fatalf("the first gateway tried its marked entry %d times", n)
	}

	// The route's only entry is tried though it is marked, rather than the route refused.
	a.mu.Lock()
	a.ranked["r1"] = a.ranked["r1"][:1]
	a.mu.Unlock()
	for range 2 {
		if code := open(m); code != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT {
			t.Fatalf("the last entry: %s, want its UPSTREAM_TIMEOUT", code)
		}
	}
	if n := count(primary); n != 2 {
		t.Fatalf("the last entry was tried %d times, want 2", n)
	}
}
