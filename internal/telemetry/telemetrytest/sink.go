// SPDX-License-Identifier: Apache-2.0

// Package telemetrytest checks what tests log: a Sink fails its test when a line holds a secret
// (docs/12-testing-and-quality.md, "Security testing", TestSecretsNeverLogged).
package telemetrytest

import (
	"bytes"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// leaked matches what a log line must never hold: a token of any rpmgr kind, of which the 20
// characters after the prefix are already a secret, or a PEM private key. A token's stored display
// prefix (the kind and 4 characters) may be logged.
var leaked = regexp.MustCompile(`rpmgr_(enr|pat|sat|ses|prs|inv)_[0-9A-Za-z]{20,}|PRIVATE KEY-----`)

// Reporter is what a Sink reports to; a *testing.T is one.
type Reporter interface {
	Helper()
	Errorf(format string, args ...any)
	Cleanup(func())
}

// Sink is a log destination that fails its test when a line holds a secret: a token, a private
// key, or a value registered with Secret. It checks the lines a debug-level production logger
// writes, redaction included, and reports at the end of the test, so that a component still
// logging afterwards cannot panic the test.
type Sink struct {
	mu       sync.Mutex
	secrets  []string
	lines    int
	findings []string
	partial  []byte
}

// NewSink returns a Sink reporting to r when its test ends.
func NewSink(r Reporter) *Sink {
	s := &Sink{}
	r.Cleanup(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.partial) > 0 {
			s.check(string(s.partial))
			s.partial = nil
		}
		for _, f := range s.findings {
			r.Errorf("a secret was logged: %s", f)
		}
	})
	return s
}

// Logger returns a test's logger: a sink's production logger at the debug level.
func Logger(t testing.TB) *slog.Logger { return NewSink(t).Logger() }

// Logger returns the production logger, at the debug level, writing to s.
func (s *Sink) Logger() *slog.Logger {
	l, err := telemetry.NewLogger(s, telemetry.LogConfig{Level: "debug", Format: "json"})
	if err != nil {
		panic(err)
	}
	return l
}

// Secret registers values no line may hold; values shorter than 8 bytes are too common to check.
func (s *Sink) Secret(values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range values {
		if len(v) >= 8 {
			s.secrets = append(s.secrets, v)
		}
	}
}

// Lines returns how many lines were written.
func (s *Sink) Lines() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lines
}

// Write checks every complete line of p.
func (s *Sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.partial = append(s.partial, p...)
	for {
		i := bytes.IndexByte(s.partial, '\n')
		if i < 0 {
			return len(p), nil
		}
		s.check(string(s.partial[:i]))
		s.partial = s.partial[i+1:]
	}
}

// check notes a finding in line, which it names without repeating the secret.
func (s *Sink) check(line string) {
	s.lines++
	what := ""
	if m := leaked.FindString(line); m != "" {
		what = "a token or a private key (" + m[:min(len(m), 10)] + "…)"
	}
	for i, v := range s.secrets {
		if strings.Contains(line, v) {
			what = fmt.Sprintf("registered secret %d", i+1)
		}
	}
	if what != "" {
		s.findings = append(s.findings, fmt.Sprintf("%s in a line of %d bytes: %.200s", what, len(line), redact(line, s.secrets)))
	}
}

// redact hides the secrets in a line for the report.
func redact(line string, secrets []string) string {
	line = leaked.ReplaceAllString(line, "[SECRET]")
	for _, v := range secrets {
		line = strings.ReplaceAll(line, v, "[SECRET]")
	}
	return line
}
