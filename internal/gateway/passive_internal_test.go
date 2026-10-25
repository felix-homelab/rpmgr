// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// TestPassive_OneTrial: once an entry's back-off ends, one open claims its trial and the others
// pass over it until the trial ends; a trial that ends without the entry failing, such as one
// whose stream could not be opened, lets the next open try it.
func TestPassive_OneTrial(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := NewSessions(SessionsOptions{Now: func() time.Time { return now }})
	k := entryKey{"r1", "con_1", 0}
	for range passiveFailures {
		m.passiveResult(k, false, false, true)
	}
	m.mu.Lock()
	if trial, ok := m.claim(k, now); trial || !ok {
		t.Fatalf("a claim during the back-off: %v %v, want an ordinary open of the last resort", trial, ok)
	}
	if !m.passive[k].marked(now) {
		t.Fatal("the entry is not marked after 3 failures")
	}
	later := now.Add(passiveBackoff)
	if trial, ok := m.claim(k, later); !trial || !ok {
		t.Fatalf("the first claim after the back-off: %v %v", trial, ok)
	}
	if _, ok := m.claim(k, later); ok {
		t.Fatal("a second open claimed the trial under way")
	}
	if !m.passive[k].marked(later) {
		t.Fatal("an entry under trial is not passed over")
	}
	m.mu.Unlock()
	m.passiveResult(k, true, false, false)
	m.mu.Lock()
	defer m.mu.Unlock()
	if trial, ok := m.claim(k, later); !trial || !ok {
		t.Fatalf("a claim after a trial that did not fail: %v %v", trial, ok)
	}
	if m.passive[k].backoff != passiveBackoff {
		t.Fatalf("a trial that did not fail changed the back-off to %v", m.passive[k].backoff)
	}
}

// TestPassive_Pruned: what the gateway learnt of an entry the snapshot dropped is forgotten.
func TestPassive_Pruned(t *testing.T) {
	m := NewSessions(SessionsOptions{Assignment: emptyAssignment{}})
	m.passiveResult(entryKey{"r1", "con_1", 0}, false, false, true)
	m.Recheck()
	if len(m.passive) != 0 {
		t.Fatalf("%d entries kept", len(m.passive))
	}
}

type emptyAssignment struct{}

func (emptyAssignment) Known(string) bool                  { return false }
func (emptyAssignment) Connectors(string) []RouteConnector { return nil }
