// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/itest"
)

// fast is a backoff for tests: the real shape, small numbers.
func fast() *agent.Backoff {
	return &agent.Backoff{Base: 20 * time.Millisecond, Cap: 200 * time.Millisecond, ResetAfter: time.Minute}
}

// syncBuffer is a log sink that tests read while the client writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// run starts a client and returns it, a log of it, and a stop function that reports how long Run
// took to return.
func run(t *testing.T, o agent.ClientOptions) (*agent.Client, *syncBuffer, func() (time.Duration, error)) {
	t.Helper()
	logs := &syncBuffer{}
	o.Logger = slog.New(slog.NewTextHandler(logs, nil))
	if o.Backoff == nil {
		o.Backoff = fast()
	}
	c := agent.NewClient(o)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	stopped := false
	stop := func() (time.Duration, error) {
		if stopped {
			return 0, nil
		}
		stopped = true
		start := time.Now()
		cancel()
		select {
		case err := <-done:
			return time.Since(start), err
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return after cancel")
			return 0, nil
		}
	}
	t.Cleanup(func() { _, _ = stop() })
	return c, logs, stop
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func welcomes(c *agent.Client) int { n, _, _ := c.Stats(); return n }

// TestControlSession_ConnectAndCancel: an enrolled agent gets a session; cancelling ends both sides
// quickly.
func TestControlSession_ConnectAndCancel(t *testing.T) {
	ctl := itest.StartController(t, itest.Options{})
	id := ctl.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	c, _, stop := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{ctl.URL}, Version: "0.1.0", BootID: "b1"})
	waitFor(t, "a Welcome", func() bool { return welcomes(c) == 1 })
	waitFor(t, "the session on the controller", func() bool { return slices.Contains(ctl.Sessions.Connected(), id.AgentID) })
	if s := c.Skew(); s > time.Second || s < -time.Second {
		t.Errorf("skew %v against a controller with the same clock", s)
	}
	took, err := stop()
	if err != nil || took > time.Second {
		t.Fatalf("Run returned after %v: %v", took, err)
	}
	waitFor(t, "the controller to drop the session", func() bool { return len(ctl.Sessions.Connected()) == 0 })
}

// TestControlSession_SkewReported: a controller clock 45 s ahead is reported as skew.
func TestControlSession_SkewReported(t *testing.T) {
	ctl := itest.StartController(t, itest.Options{Now: func() time.Time { return time.Now().Add(45 * time.Second) }})
	id := ctl.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	c, logs, _ := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{ctl.URL}, Version: "0.1.0"})
	waitFor(t, "a Welcome", func() bool { return welcomes(c) == 1 })
	if s := c.Skew(); s < 40*time.Second || s > 50*time.Second {
		t.Errorf("skew %v, want about 45 s", s)
	}
	waitFor(t, "the skew warning", func() bool { return bytes.Contains([]byte(logs.String()), []byte("clock skew")) })
}

// TestControlSession_Failover: an unreachable first endpoint is skipped, and a Drain moves the
// agent to the next replica, where its session epoch continues.
func TestControlSession_Failover(t *testing.T) {
	ctl := itest.StartController(t, itest.Options{})
	second, secondSessions := ctl.StartReplica(t)
	id := ctl.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	c, _, _ := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{"https://127.0.0.1:1", ctl.URL, second}, Version: "0.1.0"})
	waitFor(t, "a session on the first live replica", func() bool { return slices.Contains(ctl.Sessions.Connected(), id.AgentID) })
	ctl.Sessions.Drain(time.Now().Add(time.Minute))
	waitFor(t, "the move to the second replica", func() bool { return slices.Contains(secondSessions.Connected(), id.AgentID) })
	if _, _, ep := c.Stats(); ep != second {
		t.Errorf("last endpoint %s, want %s", ep, second)
	}
	row := ctl.DB.Client().AgentSession.GetX(ctl.Sys, id.AgentID)
	if row.SessionEpoch != 2 {
		t.Errorf("session epoch %d after moving, want 2", row.SessionEpoch)
	}
}

// TestRejectsUnpinnedCA (control sessions): an agent never opens a session with a controller whose
// certificate chains to another root than the one it enrolled with.
func TestRejectsUnpinnedCA(t *testing.T) {
	home := itest.StartController(t, itest.Options{})
	other := itest.StartController(t, itest.Options{})
	id := home.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	c, logs, _ := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{other.URL}, Version: "0.1.0"})
	waitFor(t, "a refused handshake", func() bool { return bytes.Contains([]byte(logs.String()), []byte("certificate")) })
	if welcomes(c) != 0 || len(other.Sessions.Connected()) != 0 {
		t.Fatal("a session with a controller of another root")
	}
}

// TestControlSession_Goodbyes: an agent below min_agent_version is told to upgrade and keeps
// trying; a revoked agent stops.
func TestControlSession_Goodbyes(t *testing.T) {
	ctl := itest.StartController(t, itest.Options{Version: "0.5.0"})
	id := ctl.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	c, _, _ := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{ctl.URL}, Version: "0.1.0"})
	waitFor(t, "two upgrade_required", func() bool {
		_, g, _ := c.Stats()
		return g[agentv1.GoodbyeReason_GOODBYE_REASON_UPGRADE_REQUIRED] >= 2
	})

	revoked := itest.StartController(t, itest.Options{})
	rid := revoked.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	rc := agent.NewClient(agent.ClientOptions{Identity: rid, Endpoints: []string{revoked.URL}, Version: "0.1.0", Backoff: fast()})
	done := make(chan error, 1)
	go func() { done <- rc.Run(context.Background()) }()
	waitFor(t, "the session", func() bool { return slices.Contains(revoked.Sessions.Connected(), rid.AgentID) })
	revoked.Sessions.Send(rid.AgentID, &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Goodbye{
		Goodbye: &agentv1.Goodbye{Reason: agentv1.GoodbyeReason_GOODBYE_REASON_REVOKED}}})
	select {
	case err := <-done:
		if !errors.Is(err, agent.ErrRevoked) {
			t.Fatalf("Run after Goodbye{revoked}: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a revoked agent keeps running")
	}
}

// TestControlSession_TurnedAwayHonoursRetryAfter: an agent turned away at admission reads the
// Goodbye, even when the controller ended the stream before the agent sent Hello, and waits at
// least its retry_after of 1–10 s.
func TestControlSession_TurnedAwayHonoursRetryAfter(t *testing.T) {
	ctl := itest.StartController(t, itest.Options{Admission: 1})
	id := ctl.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	other := ctl.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	first, _, _ := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{ctl.URL}, Version: "0.1.0"})
	waitFor(t, "the first session", func() bool { return welcomes(first) == 1 })
	second, _, _ := run(t, agent.ClientOptions{Identity: other, Endpoints: []string{ctl.URL}, Version: "0.1.0"})
	start := time.Now()
	waitFor(t, "a Goodbye{overloaded}", func() bool {
		_, g, _ := second.Stats()
		return g[agentv1.GoodbyeReason_GOODBYE_REASON_OVERLOADED] >= 1
	})
	waitFor(t, "the second session after retry_after", func() bool { return welcomes(second) == 1 })
	if d := time.Since(start); d < time.Second {
		t.Errorf("reconnected after %v, before the minimum retry_after of 1 s", d)
	}
}
