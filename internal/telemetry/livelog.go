// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// The bounds of a live-log subscription (docs/03-connections.md, "Timeouts, keepalive and
// backoff"): a buffer of LiveLogBuffer lines, of which the oldest are dropped when the viewer
// reads too slowly, and lines cut at LiveLogLine bytes.
const (
	LiveLogBuffer = 256
	LiveLogLine   = 8 << 10
	// LiveLogBacklogLines and LiveLogBacklogBytes bound the backlog: the most recent lines the agent
	// keeps for the live logs that open later (D154), the oldest dropped past either bound.
	LiveLogBacklogLines = 200
	LiveLogBacklogBytes = 64 << 10
)

// LiveLog is an agent's log with live-log subscriptions (docs/03-connections.md, "Control
// session"): its logger writes as NewLogger's does, and also hands each record, as a redacted text
// line, to every subscription whose level it reaches. A subscription that raises the level to
// debug lets debug records reach the subscriptions, never the agent's own log (D140).
type LiveLog struct {
	base  slog.Level // the configured level of the agent's own log
	state *liveState
}

// liveState is what a LiveLog's handlers share.
type liveState struct {
	mu     sync.Mutex
	subs   map[*Subscription]struct{}
	min    slog.Level // the lowest level a subscription wants
	any    bool       // there are subscriptions
	textMu sync.Mutex
	buf    bytes.Buffer // the text handler writes each line here, under textMu
	// The backlog (D154): the latest redacted lines, whether or not a log is open, under mu.
	// A ring of LiveLogBacklogLines lines: the oldest is at head, backlogLen are held.
	backlog      [LiveLogBacklogLines]Line
	head         int
	backlogLen   int
	backlogBytes int
	evicted      int // lines the backlog dropped since the agent started
}

// Line is a live-log line: redacted, cut at LiveLogLine bytes.
type Line struct {
	Time      time.Time
	Level     slog.Level
	Text      string
	Truncated bool
}

// Subscription receives the lines of a LiveLog from its level up that contain its filter.
type Subscription struct {
	state   *liveState
	level   slog.Level
	filter  string
	ready   chan struct{} // signalled when lines wait
	mu      sync.Mutex
	lines   []Line
	dropped int
	// The backlog at the time of subscribing, from the level and filter up, and how many older
	// lines the agent no longer held; taken once.
	backlog        []Line
	backlogDropped int
}

// NewLiveLogger is NewLogger with live-log subscriptions.
func NewLiveLogger(w io.Writer, cfg LogConfig) (*slog.Logger, *LiveLog, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}
	base, err := NewLogger(w, cfg)
	if err != nil {
		return nil, nil, err
	}
	st := &liveState{subs: map[*Subscription]struct{}{}}
	// A line carries its time and level as fields of its own, so its text leaves them out.
	text := slog.NewTextHandler(&st.buf, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey) {
			return slog.Attr{}
		}
		return redact(groups, a)
	}})
	l := &LiveLog{base: level, state: st}
	return slog.New(&liveHandler{base: base.Handler(), text: text, level: level, state: st}), l, nil
}

// Subscribe returns a subscription to the lines from level up that contain filter ("" for every
// line); with debug, the debug lines too. Close ends it.
func (l *LiveLog) Subscribe(level slog.Level, filter string, debug bool) *Subscription {
	if debug {
		level = min(level, slog.LevelDebug)
	}
	s := &Subscription{state: l.state, level: level, filter: filter, ready: make(chan struct{}, 1)}
	l.state.mu.Lock()
	for i := range l.state.backlogLen {
		b := l.state.backlog[(l.state.head+i)%LiveLogBacklogLines]
		if b.Level >= level && (filter == "" || strings.Contains(b.Text, filter)) {
			s.backlog = append(s.backlog, b)
		}
	}
	s.backlogDropped = l.state.evicted
	l.state.subs[s] = struct{}{}
	l.state.updateLocked()
	l.state.mu.Unlock()
	return s
}

// Close ends the subscription.
func (s *Subscription) Close() {
	s.state.mu.Lock()
	delete(s.state.subs, s)
	s.state.updateLocked()
	s.state.mu.Unlock()
}

// Ready is signalled when lines wait to be taken.
func (s *Subscription) Ready() <-chan struct{} { return s.ready }

// Backlog returns the lines the agent kept from before the subscription, oldest first, that pass
// its level and filter, and how many older lines the agent no longer held; it returns them once.
func (s *Subscription) Backlog() ([]Line, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lines, dropped := s.backlog, s.backlogDropped
	s.backlog, s.backlogDropped = nil, 0
	return lines, dropped
}

// Take returns the waiting lines, and how many were dropped before the first of them since the
// last Take.
func (s *Subscription) Take() ([]Line, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lines, dropped := s.lines, s.dropped
	s.lines, s.dropped = nil, 0
	return lines, dropped
}

// add queues a line, dropping the oldest when the buffer is full.
func (s *Subscription) add(l Line) {
	if s.filter != "" && !strings.Contains(l.Text, s.filter) {
		return
	}
	s.mu.Lock()
	if len(s.lines) == LiveLogBuffer {
		s.lines = s.lines[1:]
		s.dropped++
	}
	s.lines = append(s.lines, l)
	s.mu.Unlock()
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// keepLocked adds a line to the backlog, dropping the oldest past the bounds. Under mu. Every line
// at or above the base level reaches it, formatted and redacted whether or not a viewer is open:
// that is inherent to keeping a backlog (D154).
func (st *liveState) keepLocked(l Line) {
	if st.backlogLen == LiveLogBacklogLines {
		st.dropOldestLocked()
	}
	st.backlog[(st.head+st.backlogLen)%LiveLogBacklogLines] = l
	st.backlogLen++
	st.backlogBytes += len(l.Text)
	for st.backlogLen > 1 && st.backlogBytes > LiveLogBacklogBytes {
		st.dropOldestLocked()
	}
}

// dropOldestLocked drops the oldest backlog line and counts it. Under mu.
func (st *liveState) dropOldestLocked() {
	st.backlogBytes -= len(st.backlog[st.head].Text)
	st.backlog[st.head] = Line{}
	st.head = (st.head + 1) % LiveLogBacklogLines
	st.backlogLen--
	st.evicted++
}

// updateLocked recomputes the lowest level a subscription wants. Under mu.
func (st *liveState) updateLocked() {
	st.any = len(st.subs) > 0
	st.min = slog.LevelError + 1
	for s := range st.subs {
		st.min = min(st.min, s.level)
	}
}

// liveHandler writes records to the agent's own log handler from its level up, and hands them to
// the subscriptions as text lines.
type liveHandler struct {
	base  slog.Handler
	text  slog.Handler
	level slog.Level
	state *liveState
}

func (h *liveHandler) wanted(level slog.Level) bool {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	return h.state.any && level >= h.state.min
}

func (h *liveHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level || h.wanted(level)
}

func (h *liveHandler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if r.Level >= h.level {
		err = h.base.Handle(ctx, r)
	}
	h.state.textMu.Lock()
	h.state.buf.Reset()
	_ = h.text.Handle(ctx, r)
	text := strings.TrimSuffix(h.state.buf.String(), "\n")
	h.state.textMu.Unlock()
	line := Line{Time: r.Time, Level: r.Level, Text: RedactText(text)}
	if len(line.Text) > LiveLogLine {
		line.Text, line.Truncated = strings.ToValidUTF8(line.Text[:LiveLogLine], ""), true
	}
	h.state.mu.Lock()
	h.state.keepLocked(line)
	subs := make([]*Subscription, 0, len(h.state.subs))
	for s := range h.state.subs {
		if r.Level >= s.level {
			subs = append(subs, s)
		}
	}
	h.state.mu.Unlock()
	for _, s := range subs {
		s.add(line)
	}
	return err
}

func (h *liveHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &liveHandler{base: h.base.WithAttrs(attrs), text: h.text.WithAttrs(attrs), level: h.level, state: h.state}
}

func (h *liveHandler) WithGroup(name string) slog.Handler {
	return &liveHandler{base: h.base.WithGroup(name), text: h.text.WithGroup(name), level: h.level, state: h.state}
}

// The text pass of live-log redaction (docs/04-security.md, "Secrets at rest and in logs"): what a
// message's text may quote that no attribute key marked.
var (
	tokenText  = regexp.MustCompile(`\b(rpmgr_[a-z]{2,8}_)[A-Za-z0-9_\-]{8,}`)
	pemText    = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----(?s:.*?)(-----END [A-Z0-9 ]+-----|$)`)
	headerText = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie)(\\?["']?\s*[:=]\s*)([^\r\n"\\]*)`)
	pairText   = regexp.MustCompile(`(?i)\b(password|passwd|secret|token)(\s*[:=]\s*)("[^"]*"|[^\s"&,;]+)`)
	jwtText    = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*`)
)

// RedactText replaces in s what may be a secret: a token after its rpmgr_ prefix, PEM blocks, the
// values of Authorization, Proxy-Authorization, Cookie and Set-Cookie, of password=, secret= and
// token= pairs, and strings shaped like a JWT.
func RedactText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	// Each pattern runs only on a line that holds its marker, as most lines hold none.
	lower := strings.ToLower(s)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(lower, w) {
				return true
			}
		}
		return false
	}
	if has("-----begin ") {
		s = pemText.ReplaceAllString(s, secret.Redacted)
	}
	if has("rpmgr_") {
		s = tokenText.ReplaceAllString(s, "${1}"+secret.Redacted)
	}
	if strings.Contains(s, "eyJ") {
		s = jwtText.ReplaceAllString(s, secret.Redacted)
	}
	if has("authorization", "cookie") {
		s = headerText.ReplaceAllString(s, "${1}${2}"+secret.Redacted)
	}
	if !has("password", "passwd", "secret", "token") {
		return s
	}
	s = pairText.ReplaceAllStringFunc(s, func(m string) string {
		p := pairText.FindStringSubmatch(m)
		if p[3] == secret.Redacted {
			return m
		}
		return p[1] + p[2] + secret.Redacted
	})
	return s
}
