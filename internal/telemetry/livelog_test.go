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
	if lines, _ := debug.Take(); len(lines) != 3 || lines[0].Level != slog.LevelDebug {
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
