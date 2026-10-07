// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

func TestNewLoggerConfig(t *testing.T) {
	for _, tt := range []struct {
		cfg     LogConfig
		wantErr bool
		json    bool
	}{
		{LogConfig{}, false, true},
		{LogConfig{Level: "debug", Format: "text"}, false, false},
		{LogConfig{Level: "warn", Format: "json"}, false, true},
		{LogConfig{Level: "error"}, false, true},
		{LogConfig{Level: "verbose"}, true, false},
		{LogConfig{Level: "INFO"}, true, false},
		{LogConfig{Format: "xml"}, true, false},
	} {
		var buf bytes.Buffer
		l, err := NewLogger(&buf, tt.cfg)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewLogger(%+v) error = %v, want error %v", tt.cfg, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		l.Error("hello")
		if got := json.Valid(bytes.TrimSpace(buf.Bytes())); got != tt.json {
			t.Errorf("NewLogger(%+v): JSON output %v, want %v: %q", tt.cfg, got, tt.json, buf.String())
		}
	}
}

func TestLevelFilters(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(&buf, LogConfig{Level: "warn"})
	if err != nil {
		t.Fatal(err)
	}
	l.Info("hidden")
	l.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Errorf("level warn wrote %q", buf.String())
	}
}

func TestRedaction(t *testing.T) {
	const plain = "s3cr3t-value-123"
	for _, format := range []string{"json", "text"} {
		var buf bytes.Buffer
		l, err := NewLogger(&buf, LogConfig{Format: format})
		if err != nil {
			t.Fatal(err)
		}
		l.Info("event",
			"token", plain, "api_token", plain, "Session-Token", plain, "PASSWORD", plain,
			"client_secret", plain, "Authorization", plain, "cookie", plain, "private_key", plain,
			"value", secret.New(plain),
			slog.Group("req", "auth", slog.GroupValue(slog.String("authorization", plain)), "password_hash", plain),
		)
		l.With("refresh_token", plain).Info("bound")
		out := buf.String()
		if strings.Contains(out, plain) {
			t.Errorf("%s output leaks a secret:\n%s", format, out)
		}
		if n := strings.Count(out, secret.Redacted); n < 12 {
			t.Errorf("%s output has %d redactions, want at least 12:\n%s", format, n, out)
		}
	}
}

func TestOrdinaryKeysKept(t *testing.T) {
	var buf bytes.Buffer
	l, _ := NewLogger(&buf, LogConfig{})
	l.Info("event", "route", "rte_1", "user", "alice", "bytes", 42)
	for _, want := range []string{`"route":"rte_1"`, `"user":"alice"`, `"bytes":42`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output %q lacks %s", buf.String(), want)
		}
	}
}
