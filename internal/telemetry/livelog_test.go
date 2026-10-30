// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestRedactText (docs/04-security.md, "Secrets at rest and in logs"): the text pass replaces a
// token after its prefix, PEM blocks, header values, password, secret and token pairs and JWTs,
// and leaves other text as it is.
func TestRedactText(t *testing.T) {
	tok := "rpmgr_" + "pat_AbCdEf0123456789xyz" // made at run time, so no secret scanner takes it for a leak
	for in, want := range map[string]string{    //nolint:gosec // G101: made-up secrets the pass must hide
		"used " + tok + " now": "used rpmgr_pat_" + secret.Redacted + " now",
		"key -----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY----- done": "key " + secret.Redacted + " done",
		"cut -----BEGIN CERTIFICATE-----\nMIIB":                                       "cut " + secret.Redacted,
		`msg="Authorization: Bearer abc.def ghi" x=1`:                                 `msg="Authorization: ` + secret.Redacted + `" x=1`,
		"Cookie=session=1; theme=dark":                                                "Cookie=" + secret.Redacted,
		"login password=hunter2 user=ada":                                             "login password=" + secret.Redacted + " user=ada",
		`secret: "very long secret" kept`:                                             `secret: ` + secret.Redacted + ` kept`,
		"bearer eyJhbGciOiJ.eyJzdWIiOiIxMjM.SflKxwRJSMeKKF2QT4":                       "bearer " + secret.Redacted,
		"route rte_01 ready on con_01, 3 targets":                                     "route rte_01 ready on con_01, 3 targets",
		"token_id=atk_123 tokens=4":                                                   "token_id=atk_123 tokens=4",
	} {
		if got := telemetry.RedactText(in); got != want {
			t.Errorf("RedactText(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLiveLog: a subscription gets the redacted lines from its level up that contain its filter;
// raised to debug it gets debug lines, which the agent's own log never shows; a full buffer drops
// the oldest lines and counts them; a long line is cut and marked; a closed subscription gets
// nothing more, and the agent's log is as before.
func TestLiveLog(t *testing.T) {
	var own bytes.Buffer
	logger, live, err := telemetry.NewLiveLogger(&own, telemetry.LogConfig{Level: "info", Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	info := live.Subscribe(slog.LevelInfo, "route", false)
	debug := live.Subscribe(slog.LevelWarn, "", true)
	logger.Debug("dialing", "route", "rte_1")
	logger.Info("route ready", "token", "rpmgr_"+"pat_secretsecret", "password", "hunter2")
	logger.Info("unrelated")
	if strings.Contains(own.String(), "dialing") || strings.Count(own.String(), "\n") != 2 {
		t.Fatalf("the agent's own log: %s", own.String())
	}
	lines, dropped := info.Take()
	if len(lines) != 1 || dropped != 0 || !strings.Contains(lines[0].Text, "route ready") ||
		strings.Contains(lines[0].Text, "hunter2") || strings.Contains(lines[0].Text, "secretsecret") {
		t.Fatalf("an info subscription with a filter: %+v", lines)
	}
	if lines, _ := debug.Take(); len(lines) != 3 || lines[0].Level != slog.LevelDebug || lines[0].Text != `msg=dialing route=rte_1` {
		t.Fatalf("a subscription raised to debug: %+v", lines)
	}
	for range telemetry.LiveLogBuffer + 10 {
		logger.Warn("busy")
	}
	logger.Warn(strings.Repeat("x", telemetry.LiveLogLine+100))
	lines, dropped = debug.Take()
	if len(lines) != telemetry.LiveLogBuffer || dropped != 11 {
		t.Fatalf("a full buffer: %d lines, %d dropped", len(lines), dropped)
	}
	if last := lines[len(lines)-1]; !last.Truncated || len(last.Text) != telemetry.LiveLogLine {
		t.Fatalf("a long line: %d bytes, truncated %v", len(last.Text), last.Truncated)
	}
	debug.Close()
	info.Close()
	own.Reset()
	logger.Debug("after")
	logger.Info("after")
	if lines, _ := debug.Take(); len(lines) != 0 || strings.Count(own.String(), "\n") != 1 {
		t.Fatalf("after Close: %v, own %q", lines, own.String())
	}
	if logger.Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("debug stayed enabled after the raising subscription closed")
	}
}

func newLive(t *testing.T, level string) (*slog.Logger, *telemetry.LiveLog) {
	t.Helper()
	logger, live, err := telemetry.NewLiveLogger(&bytes.Buffer{}, telemetry.LogConfig{Level: level})
	if err != nil {
		t.Fatal(err)
	}
	return logger, live
}

func texts(ls []telemetry.Line) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l.Text)
	}
	return out
}

// TestLiveLogBacklog (D154): a subscription gets the lines logged before it opened, oldest first,
// redacted, from its level up and matching its filter, once; lines logged after it come through
// Take, never twice.
func TestLiveLogBacklog(t *testing.T) {
	logger, live := newLive(t, "info")
	tok := "rpmgr_" + "pat_0123456789abcdefgh" // made at run time, so no secret scanner takes the test for a leak
	logger.Info("first")
	logger.Debug("never logged: below the agent's level")
	logger.Warn("second " + tok + " password=hunter2")
	logger.Info("third", "token", tok)

	sub := live.Subscribe(slog.LevelInfo, "", false)
	defer sub.Close()
	logger.Info("after")
	got, dropped := sub.Backlog()
	if dropped != 0 || len(got) != 3 || got[0].Text != "msg=first" || !strings.Contains(got[1].Text, "second") || got[2].Text != "msg=third token=[REDACTED]" {
		t.Fatalf("backlog: %q dropped %d", texts(got), dropped)
	}
	for _, l := range got {
		if strings.Contains(l.Text, tok) || strings.Contains(l.Text, "hunter2") {
			t.Errorf("the backlog holds a secret: %q", l.Text)
		}
	}
	if again, _ := sub.Backlog(); len(again) != 0 {
		t.Errorf("the backlog came twice: %q", texts(again))
	}
	if lines, _ := sub.Take(); len(lines) != 1 || lines[0].Text != "msg=after" {
		t.Errorf("new lines: %q", texts(lines))
	}

	warn := live.Subscribe(slog.LevelWarn, "", false)
	defer warn.Close()
	if got, _ := warn.Backlog(); len(got) != 1 || !strings.Contains(got[0].Text, "second") {
		t.Errorf("the level did not apply to the backlog: %q", texts(got))
	}
	// The filter matches the redacted text, so it cannot find a secret.
	byTok := live.Subscribe(slog.LevelInfo, "hunter2", false)
	defer byTok.Close()
	if got, _ := byTok.Backlog(); len(got) != 0 {
		t.Errorf("a filter found a secret in the backlog: %q", texts(got))
	}
	byText := live.Subscribe(slog.LevelInfo, "third", false)
	defer byText.Close()
	if got, _ := byText.Backlog(); len(got) != 1 {
		t.Errorf("the filter did not apply to the backlog: %q", texts(got))
	}
}

// TestLiveLogBacklog_Debug (D140, D154): debug lines are in the backlog only if a viewer raised
// the level when they were logged, and a viewer at info does not get them.
func TestLiveLogBacklog_Debug(t *testing.T) {
	logger, live := newLive(t, "info")
	logger.Debug("unseen")
	raised := live.Subscribe(slog.LevelInfo, "", true)
	logger.Debug("seen")
	raised.Close()
	late := live.Subscribe(slog.LevelInfo, "", false)
	defer late.Close()
	if got, _ := late.Backlog(); len(got) != 0 {
		t.Errorf("an info viewer got debug lines: %q", texts(got))
	}
	debug := live.Subscribe(slog.LevelDebug, "", false)
	defer debug.Close()
	if got, _ := debug.Backlog(); len(got) != 1 || got[0].Text != "msg=seen" {
		t.Errorf("the debug line logged while raised: %q", texts(got))
	}
}

// TestLiveLogBacklog_Bounds: the backlog keeps the last LiveLogBacklogLines lines and
// LiveLogBacklogBytes bytes, the oldest dropped and counted, and an empty backlog says nothing.
func TestLiveLogBacklog_Bounds(t *testing.T) {
	logger, live := newLive(t, "info")
	if got, dropped := live.Subscribe(slog.LevelInfo, "", false).Backlog(); len(got) != 0 || dropped != 0 {
		t.Fatalf("an empty backlog: %q %d", texts(got), dropped)
	}
	const total = telemetry.LiveLogBacklogLines + 50
	for i := range total {
		logger.Info("n", "i", i)
	}
	sub := live.Subscribe(slog.LevelInfo, "", false)
	defer sub.Close()
	got, dropped := sub.Backlog()
	if len(got) != telemetry.LiveLogBacklogLines || dropped != 50 {
		t.Fatalf("lines: %d dropped %d", len(got), dropped)
	}
	if got[0].Text != "msg=n i=50" || got[len(got)-1].Text != "msg=n i=249" {
		t.Errorf("the oldest went first: %q ... %q", got[0].Text, got[len(got)-1].Text)
	}

	// By bytes: long lines leave room for fewer than the line bound.
	logger, live = newLive(t, "info")
	long := strings.Repeat("x", 4<<10)
	for range 40 {
		logger.Info(long)
	}
	sub2 := live.Subscribe(slog.LevelInfo, "", false)
	defer sub2.Close()
	got, dropped = sub2.Backlog()
	size := 0
	for _, l := range got {
		size += len(l.Text)
	}
	if size > telemetry.LiveLogBacklogBytes || len(got) == 0 || len(got)+dropped != 40 {
		t.Errorf("bytes: %d bytes in %d lines, dropped %d", size, len(got), dropped)
	}
	// A single line above the bound is still kept, alone.
	logger.Info(strings.Repeat("y", telemetry.LiveLogLine))
	if got, _ := live.Subscribe(slog.LevelInfo, "", false).Backlog(); len(got) == 0 {
		t.Error("the newest line was dropped")
	}
}
