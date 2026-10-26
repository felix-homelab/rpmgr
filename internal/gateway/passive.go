// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"time"
)

// Passive health of a route's entries (docs/03-connections.md, "Target health"): each gateway
// passes over a (connector, priority) entry after passiveFailures refused or timed-out stream opens
// in a row, for a back-off from passiveBackoff doubling to passiveBackoffMax, after which one
// stream tries it again.
const (
	passiveFailures   = 3
	passiveBackoff    = 10 * time.Second
	passiveBackoffMax = 60 * time.Second
)

// entryKey names an entry of a route.
type entryKey struct {
	route, connector string
	priority         uint32
}

// entryHealth is what the gateway learnt of an entry from its stream opens.
type entryHealth struct {
	fails   int           // refused or timed-out opens in a row
	backoff time.Duration // the current back-off; 0 while the entry is not marked
	until   time.Time     // the end of the back-off
	trying  bool          // a half-open trial is under way
}

// marked reports whether the entry is passed over now: in its back-off, or past it while one
// stream already tries it.
func (h *entryHealth) marked(now time.Time) bool {
	return h != nil && h.backoff > 0 && (now.Before(h.until) || h.trying)
}

// passable keeps the candidates that passive health does not pass over. When it passes over every
// one, it keeps the entry whose back-off ends first as the last resort, so that the route is still
// tried rather than refused. Under m.mu.
func (m *Sessions) passable(route string, cands []rankedSessions, now time.Time) []rankedSessions {
	var out []rankedSessions
	last := -1
	for i, c := range cands {
		h := m.passive[entryKey{route, c.ID, c.Priority}]
		if !h.marked(now) {
			out = append(out, c)
		} else if last < 0 || h.until.Before(m.passive[entryKey{route, cands[last].ID, cands[last].Priority}].until) {
			last = i
		}
	}
	if len(out) == 0 && last >= 0 {
		c := cands[last]
		c.lastResort = true
		out = append(out, c)
	}
	return out
}

// claim starts the half-open trial of a marked entry whose back-off has ended, and reports
// whether the open may go ahead: false if another stream already tries it. An entry that is not
// marked needs no claim, nor does the last resort (passable). Under m.mu.
func (m *Sessions) claim(k entryKey, now time.Time) (trial, ok bool) {
	h := m.passive[k]
	switch {
	case h == nil || h.backoff == 0 || now.Before(h.until):
		return false, true
	case h.trying:
		return false, false
	}
	h.trying = true
	return true, true
}

// passiveResult records how an open of the entry ended: ok restores it; failed (refused or timed
// out) counts towards marking it, or doubles its back-off after a failed trial; neither only ends
// a trial, as the entry was not what failed.
func (m *Sessions) passiveResult(k entryKey, trial, ok, failed bool) {
	now := m.o.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.passive[k]
	switch {
	case ok:
		if h != nil && h.backoff > 0 {
			m.o.Logger.Info("a route entry answers again", "route", k.route, "connector", k.connector, "priority", k.priority)
		}
		delete(m.passive, k)
	case failed:
		if h == nil {
			h = &entryHealth{}
			m.passive[k] = h
		}
		h.fails++
		switch {
		case h.backoff == 0 && h.fails >= passiveFailures:
			h.backoff, h.until = passiveBackoff, now.Add(passiveBackoff)
			m.o.Logger.Warn("passing over a route entry whose target refuses or times out", "route", k.route,
				"connector", k.connector, "priority", k.priority, "for", h.backoff)
		case trial:
			h.backoff = min(2*h.backoff, passiveBackoffMax)
			h.until = now.Add(h.backoff)
		}
		if trial {
			h.trying = false
		}
	case trial && h != nil:
		h.trying = false
	}
}

// prunePassive forgets the entries the snapshot no longer has. Under m.mu.
func (m *Sessions) prunePassive() {
	for k := range m.passive {
		if !m.hasEntryLocked(k) {
			delete(m.passive, k)
		}
	}
}

func (m *Sessions) hasEntryLocked(k entryKey) bool {
	for _, c := range m.o.Assignment.Connectors(k.route) {
		if c.ID == k.connector && c.Priority == k.priority {
			return true
		}
	}
	return false
}
