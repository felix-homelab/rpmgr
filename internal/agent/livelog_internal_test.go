// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestLiveLogs_RedactedOnAgent (docs/12-testing-and-quality.md, "Security testing"): what a
// live-log operation sends never holds a secret its records carry, in an attribute or in the
// message's text, also raised to debug; a viewer that reads slowly loses lines, counted, and never
// slows the agent's logging; a long line arrives cut and marked.
func TestLiveLogs_RedactedOnAgent(t *testing.T) {
	var own bytes.Buffer
	logger, live, err := telemetry.NewLiveLogger(&own, telemetry.LogConfig{Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []*agentv1.LogLine
	slow := make(chan struct{})
	send := func(f *agentv1.AttachFrame) error {
		<-slow // the controller reads only when the test lets it
		mu.Lock()
		got = append(got, f.GetLog())
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serveLogs(ctx, live, &agentv1.LogParams{Level: "info", RaiseToDebug: true}, send) }()
	time.Sleep(50 * time.Millisecond) // subscribed

	tok := "rpmgr_" + "pat_0123456789abcdefgh" // made at run time, so no secret scanner takes the test for a leak
	secrets := []string{tok, "hunter2", "MHcCAQEEIOG", "Bearer opaque-value", "eyJhbGciOiJ.eyJzdWIiOiIx.c2ln"}
	logger.Debug("dial with Authorization: Bearer opaque-value", "token", tok)
	logger.Info("enrolled with " + tok + ", password=hunter2")
	logger.Info("key -----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIOG\n-----END EC PRIVATE KEY-----")
	logger.Warn("assertion eyJhbGciOiJ.eyJzdWIiOiIx.c2ln refused")
	// A slow viewer: thousands of lines while it reads nothing must not block the logger.
	logged := make(chan struct{})
	go func() {
		for range 5000 {
			logger.Info("busy")
		}
		close(logged)
	}()
	select {
	case <-logged:
	case <-time.After(30 * time.Second): // a logger the viewer blocked would never get here
		t.Fatal("a stalled viewer blocked the agent's logging")
	}
	close(slow)
	waitLines := func(ok func([]*agentv1.LogLine) bool) []*agentv1.LogLine {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			mu.Lock()
			lines := append([]*agentv1.LogLine(nil), got...)
			mu.Unlock()
			if ok(lines) {
				return lines
			}
		}
		t.Fatal("the lines never arrived")
		return nil
	}
	// Once the backlog is through and the rate refilled, a long line arrives cut.
	waitLines(func(l []*agentv1.LogLine) bool {
		return len(l) > 0 && strings.HasSuffix(l[len(l)-1].GetText(), "msg=busy")
	})
	time.Sleep(1100 * time.Millisecond)
	logger.Info(strings.Repeat("y", telemetry.LiveLogLine*2))
	lines := waitLines(func(l []*agentv1.LogLine) bool { return len(l) > 0 && l[len(l)-1].GetTruncated() })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	dropped := uint32(0)
	for _, l := range lines {
		all.WriteString(l.GetText() + "\n")
		dropped += l.GetDroppedBefore()
	}
	for _, s := range secrets {
		if strings.Contains(all.String(), s) {
			t.Errorf("a live log line holds %q:\n%s", s, all.String()[:min(all.Len(), 2000)])
		}
	}
	if lines[0].GetLevel() != "debug" || !strings.Contains(lines[0].GetText(), "dial with") {
		t.Errorf("the raised debug line: %v", lines[0])
	}
	if dropped == 0 {
		t.Error("a slow viewer lost no lines, or they were not counted")
	}
	if last := lines[len(lines)-1]; len(last.GetText()) != telemetry.LiveLogLine {
		t.Errorf("a long line of %d bytes", len(last.GetText()))
	}
	if strings.Contains(own.String(), "dial with") {
		t.Error("the raise reached the agent's own log")
	}
}

// TestServeLogs_BadLevel: an operation with a level the agent does not know ends with an error.
func TestServeLogs_BadLevel(t *testing.T) {
	_, live, _ := telemetry.NewLiveLogger(&bytes.Buffer{}, telemetry.LogConfig{})
	if err := serveLogs(t.Context(), live, &agentv1.LogParams{Level: "trace"}, nil); err == nil {
		t.Fatal("a level of trace was accepted")
	}
}
