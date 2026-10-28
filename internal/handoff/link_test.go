// SPDX-License-Identifier: Apache-2.0

//go:build linux

package handoff

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func notifyEnv(sock string) func(string) string {
	return func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return sock
		}
		return ""
	}
}

// TestLink_Handoff: a hand-off is refused until the role says how it starts its successor, then
// runs what it says, and its error is the trigger's outcome.
func TestLink_Handoff(t *testing.T) {
	l := NewLink(nil, nil, nil)
	if _, err := l.Handoff(context.Background()); !errors.Is(err, ErrRefused) {
		t.Fatalf("before Serve: %v", err)
	}
	boom := errors.New("boom")
	l.Serve(func(context.Context) (*Child, error) { return nil, boom })
	if _, err := l.Handoff(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("after Serve: %v", err)
	}
	l.Serve(func(context.Context) (*Child, error) { return &Child{Pid: 5, Generation: 2}, nil })
	if c, err := l.Handoff(context.Background()); err != nil || c.Pid != 5 {
		t.Fatalf("a hand-off: %v, %v", c, err)
	}
}

// TestLink_Generation: the first process is generation 1.
func TestLink_Generation(t *testing.T) {
	if g := NewLink(nil, nil, nil).Generation(); g != 1 {
		t.Errorf("generation %d", g)
	}
	if g := NewLink(&Handoff{Manifest: Manifest{Generation: 4}}, nil, nil).Generation(); g != 4 {
		t.Errorf("generation %d", g)
	}
}

// TestLink_ReadyOnce: after a plain start Ready tells systemd and begins the trigger, once; a
// failed notification is returned and does not begin it.
func TestLink_ReadyOnce(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify")
	srv, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	begun := 0
	l := NewLink(nil, notifyEnv(sock), func() { begun++ })
	for range 3 {
		if err := l.Ready(); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 64)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _, err := srv.ReadFrom(buf); err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("notification %q, %v", buf[:n], err)
	}
	_ = srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := srv.ReadFrom(buf); err == nil {
		t.Error("a second notification")
	}
	if begun != 1 {
		t.Errorf("begun %d times", begun)
	}

	bad := NewLink(nil, notifyEnv(filepath.Join(t.TempDir(), "gone")), func() { t.Error("begun after a failure") })
	if err := bad.Ready(); err == nil {
		t.Error("a failed notification was not reported")
	}
}

// TestLink_Context: a role finds the Link of its command, and none in a bare context.
func TestLink_Context(t *testing.T) {
	if LinkFrom(context.Background()) != nil {
		t.Error("a Link out of nowhere")
	}
	l := NewLink(nil, nil, nil)
	if LinkFrom(WithLink(context.Background(), l)) != l {
		t.Error("the Link was not found")
	}
}

// TestLink_FinishPlain: ending after a plain start, ready or not, tells nobody.
func TestLink_FinishPlain(t *testing.T) {
	NewLink(nil, nil, nil).Finish(errors.New("failed"))
}
