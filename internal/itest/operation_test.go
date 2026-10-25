// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestOperation_ThroughAgent (docs/03-connections.md, "Control session"): an agent that runs
// operations attaches the controller's Open on its control session's connection and streams its
// frames until the controller ends the operation, which ends it on the agent; an error of the
// agent's handler ends the operation with its reason; an agent that announces the capability but
// runs no operations refuses it.
func TestOperation_ThroughAgent(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	runs := c.EnrollConnector(t, filepath.Join(dir, "runs", "identity"))
	refuses := c.EnrollConnector(t, filepath.Join(dir, "refuses", "identity"))
	var ended atomic.Int32
	handler := func(ctx context.Context, open *agentv1.Open, send func(*agentv1.AttachFrame) error) error {
		if open.GetLogs().GetFilter() == "fail" {
			return errors.New("cannot read the logs")
		}
		defer ended.Add(1)
		for i := 0; ; i++ {
			if err := send(&agentv1.AttachFrame{Frame: &agentv1.AttachFrame_Log{Log: &agentv1.LogLine{Level: "info", Text: "line"}}}); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	startOperationAgent(t, c, runs, filepath.Join(dir, "runs", "state"), handler)
	startOperationAgent(t, c, refuses, filepath.Join(dir, "refuses", "state"), nil)

	open := func(agentID, filter string) (*controller.Operation, error) {
		var op *controller.Operation
		var err error
		waitFor(t, "the agent's control session", func() bool {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			op, err = c.Sessions.Open(ctx, agentID, agentv1.OperationKind_OPERATION_KIND_LOGS, &agentv1.LogParams{Filter: filter})
			return !errors.Is(err, controller.ErrNotConnected)
		})
		return op, err
	}
	op, err := open(runs.AgentID, "")
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if f, err := op.Recv(); err != nil || f.GetLog().GetText() != "line" {
			t.Fatalf("a line: %v %v", f, err)
		}
	}
	op.Close("viewer left")
	waitFor(t, "the operation to end on the agent", func() bool { return ended.Load() == 1 })

	op, err = open(runs.AgentID, "fail")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Recv(); err == nil || !strings.Contains(err.Error(), "cannot read the logs") {
		t.Fatalf("a failing handler: %v", err)
	}
	op.Close("")

	if _, err := open(refuses.AgentID, ""); !errors.Is(err, controller.ErrOperationRefused) ||
		!strings.Contains(err.Error(), agent.ErrUnsupportedOperation.Error()) {
		t.Fatalf("an agent that runs no operations: %v", err)
	}
}

// startOperationAgent runs a connector's control session that announces logs.stream and runs
// operations with handler.
func startOperationAgent(t *testing.T, c *itest.Controller, id agent.Loaded, state string,
	handler func(context.Context, *agentv1.Open, func(*agentv1.AttachFrame) error) error) {
	t.Helper()
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
			Applier: &offerRecorder{}, Backoff: fast(), Logger: c.Logs.Logger(), Capabilities: []string{agentproto.CapLogsStream},
			OnOperation: handler})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// TestLiveLogs_ThroughAgent (docs/03-connections.md, "Control session"): an agent with a live log
// announces logs.stream by itself and streams its log lines, redacted, at the operation's level
// and filter, raised to debug for the operation only.
func TestLiveLogs_ThroughAgent(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	id := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	var own strings.Builder
	logger, live, err := telemetry.NewLiveLogger(&lockedWriter{w: &own}, telemetry.LogConfig{Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
			Applier: &offerRecorder{}, Backoff: fast(), Logger: c.Logs.Logger(), LiveLog: live})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })

	var op *controller.Operation
	waitFor(t, "the agent's control session", func() bool {
		octx, ocancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer ocancel()
		op, err = c.Sessions.Open(octx, id.AgentID, agentv1.OperationKind_OPERATION_KIND_LOGS,
			&agentv1.LogParams{Level: "info", Filter: "probe", RaiseToDebug: true})
		return !errors.Is(err, controller.ErrNotConnected)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close("")
	stop := make(chan struct{})
	defer close(stop)
	go func() { // log until the line arrives, as the subscription starts after the attach
		for {
			logger.Debug("probe dialing with Authorization: Bearer opaque-value")
			logger.Info("unrelated line")
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	f, err := op.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if l := f.GetLog(); l.GetLevel() != "debug" || !strings.Contains(l.GetText(), "probe dialing") ||
		strings.Contains(l.GetText(), "opaque-value") || strings.Contains(l.GetText(), "unrelated") {
		t.Fatalf("the line: %v", l)
	}
}

// lockedWriter serialises writes to w.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
