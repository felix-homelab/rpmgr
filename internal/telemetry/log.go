// SPDX-License-Identifier: Apache-2.0

// Package telemetry sets up rpmgr's logs, metrics and traces (docs/10-operations.md,
// "Observability").
package telemetry

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// LogConfig is the `log` section of a boot file (docs/10-operations.md, "Boot files").
type LogConfig struct {
	Level  string // debug, info, warn or error; empty means info
	Format string // json or text; empty means json
}

// deniedKeys are parts of attribute keys whose values are always redacted, whatever their type
// (docs/04-security.md, "Secrets at rest and in logs"). Keys are compared in lower case with "-"
// and "_" removed, so "Private-Key" and "api_token" match too. A false match only hides a value.
var deniedKeys = []string{"token", "secret", "password", "authorization", "cookie", "privatekey"}

// NewLogger returns a structured logger that writes to w. Values of type secret.Value and values
// of attributes whose key contains a denied word are written as secret.Redacted.
func NewLogger(w io.Writer, cfg LogConfig) (*slog.Logger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: redact}
	switch cfg.Format {
	case "", "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("log format %q: want json or text", cfg.Format)
	}
}

func parseLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("log level %q: want debug, info, warn or error", s)
	}
}

func redact(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		return a
	}
	if deniedKey(a.Key) {
		return slog.String(a.Key, secret.Redacted)
	}
	return a
}

func deniedKey(key string) bool {
	k := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key))
	for _, d := range deniedKeys {
		if strings.Contains(k, d) {
			return true
		}
	}
	return false
}
