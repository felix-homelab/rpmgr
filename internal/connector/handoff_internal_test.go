// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/handoff"
)

func TestHandoffFrom(t *testing.T) {
	started := handoff.NewLink(&handoff.Handoff{}, nil, nil)
	plain := handoff.NewLink(nil, nil, nil)
	env := func(v string) func(string) string {
		return func(k string) string {
			if k != HandoffFromEnv {
				t.Fatalf("read %s", k)
			}
			return v
		}
	}
	for _, c := range []struct {
		name string
		link *handoff.Link
		v    string
		want string
	}{
		{"started by a hand-off", started, "0a1b2c", "0a1b2c"},
		{"plain start ignores it", plain, "0a1b2c", ""},
		{"no link", nil, "0a1b2c", ""},
		{"empty", started, "", ""},
		{"not hex", started, "zz", ""},
		{"upper case", started, "0A", ""},
		{"too long", started, strings.Repeat("a", 65), ""},
		{"longest", started, strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"injection", started, "ab\nX=1", ""},
	} {
		if got := handoffFrom(c.link, env(c.v)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHandoffEnv(t *testing.T) {
	t.Setenv(HandoffFromEnv, "old")
	env := handoffEnv("new")
	n := 0
	for _, e := range env {
		if strings.HasPrefix(e, HandoffFromEnv+"=") {
			n++
			if e != HandoffFromEnv+"=new" {
				t.Errorf("got %q", e)
			}
		}
	}
	if n != 1 || len(env) < len(os.Environ()) {
		t.Fatalf("%d entries of %s, %d variables", n, HandoffFromEnv, len(env))
	}
}

// TestReportReady: a plain start reports ready at once; a process a hand-off started waits for the
// control plane and the sessions, and reports nothing if it ends first.
func TestReportReady(t *testing.T) {
	var began bool
	plain := handoff.NewLink(nil, func(string) string { return "" }, func() { began = true })
	never := func(context.Context) error { return os.ErrClosed }
	if err := reportReady(context.Background(), plain, never, func() bool { return false }); err != nil || !began {
		t.Fatalf("plain start: %v, began %v", err, began)
	}

	started := handoff.NewLink(&handoff.Handoff{}, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for name, c := range map[string]struct {
		ctl     func(context.Context) error
		settled func() bool
	}{
		"no control session":   {never, func() bool { return true }},
		"sessions not settled": {func(context.Context) error { return nil }, func() bool { return false }},
	} {
		if err := reportReady(ctx, started, c.ctl, c.settled); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ctx.Err() == nil {
		t.Fatal("returned before the context ended")
	}
}
