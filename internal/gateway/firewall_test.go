// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/firewall"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

type fwEnv struct {
	dir, status string
	now         time.Time
	fw          *gateway.Firewall
	reports     []*agentv1.FirewallState
}

func newFwEnv(t *testing.T) *fwEnv {
	t.Helper()
	e := &fwEnv{dir: filepath.Join(t.TempDir(), "firewall"), status: filepath.Join(t.TempDir(), "status.json"),
		now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	if err := os.Mkdir(e.dir, 0o750); err != nil {
		t.Fatal(err)
	}
	e.fw = gateway.NewFirewall(gateway.FirewallOptions{Dir: e.dir, Status: e.status, Now: func() time.Time { return e.now },
		Report: func(s *agentv1.FirewallState) { e.reports = append(e.reports, s) }})
	return e
}

func pool(proto string, from, to uint32) *agentv1.GatewayPortPool {
	return &agentv1.GatewayPortPool{Protocol: proto, PortFrom: from, PortTo: to}
}

// desired parses the desired file as the helper does.
func (e *fwEnv) desired(t *testing.T) firewall.Desired {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.dir, gateway.DesiredFile))
	if err != nil {
		t.Fatal(err)
	}
	d, err := firewall.ParseDesired(raw)
	if err != nil {
		t.Fatalf("the helper cannot parse the desired file %q: %v", raw, err)
	}
	return d
}

// helper writes a status file as the helper does, at the environment's time.
func (e *fwEnv) helper(t *testing.T, st firewall.Status) {
	t.Helper()
	st.At = e.now
	raw, _ := json.Marshal(st)
	if err := os.WriteFile(e.status, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *fwEnv) last(t *testing.T) *agentv1.FirewallState {
	t.Helper()
	if len(e.reports) == 0 {
		t.Fatal("nothing was reported")
	}
	return e.reports[len(e.reports)-1]
}

// TestFirewall_GatewayWritesRangesOnly (docs/12-testing-and-quality.md, "Security testing"): the
// gateway's firewall output is the desired file with the ranges of its group's pools and nothing
// else: no other file, no range that no pool names, no command.
func TestFirewall_GatewayWritesRangesOnly(t *testing.T) {
	e := newFwEnv(t)
	e.fw.Set([]*agentv1.GatewayPortPool{pool("udp", 30000, 30010), pool("tcp", 20500, 20999), pool("tcp", 20000, 20499)})
	e.fw.Step()
	d := e.desired(t)
	want := []firewall.Range{{Protocol: "tcp", From: 20000, To: 20999}, {Protocol: "udp", From: 30000, To: 30010}}
	if d.Version != 1 || !slices.Equal(d.Ranges, want) {
		t.Errorf("desired %+v, want the pools' ranges %v merged", d, want)
	}
	entries, err := os.ReadDir(e.dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != gateway.DesiredFile {
		t.Errorf("the firewall directory holds %v (%v), want only %s", entries, err, gateway.DesiredFile)
	}
	if fi, err := os.Stat(filepath.Join(e.dir, gateway.DesiredFile)); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("desired file mode %v, %v; the helper reads it as root and needs no more than 0644", fi, err)
	}
	// The gateway runs no command: its firewall code imports nothing that could.
	f, err := parser.ParseFile(token.NewFileSet(), "firewall.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		if p := strings.Trim(imp.Path.Value, `"`); p == "os/exec" || p == "syscall" || strings.HasPrefix(p, "golang.org/x/sys") {
			t.Errorf("firewall.go imports %s: the gateway must only write a file", p)
		}
	}
}

func TestFirewallNoPoolsWritesNoRanges(t *testing.T) {
	e := newFwEnv(t)
	e.fw.Set(nil) // a group without pools; a tcp or udp route adds nothing
	e.fw.Step()
	if d := e.desired(t); len(d.Ranges) != 0 {
		t.Errorf("ranges %v for a group without pools", d.Ranges)
	}
	if raw, _ := os.ReadFile(filepath.Join(e.dir, gateway.DesiredFile)); !strings.Contains(string(raw), `"ranges":[]`) {
		t.Errorf("file %q: no ranges must be an empty list, not null", raw)
	}
}

func TestFirewallRoutesAddNoRange(t *testing.T) {
	e := newFwEnv(t)
	a, _ := gateway.NewApplier()
	a.Bind(gateway.Served{Firewall: e.fw})
	snap := gatewaySnapshot(1, tcpResource("rt_1", 20500, "con_1"), udpResource("rt_2", 30001, "con_1"),
		&agentv1.Resource{Id: "pp_1", Kind: &agentv1.Resource_GatewayPortPool{GatewayPortPool: pool("tcp", 20000, 20999)}})
	if errs := a.Validate(snap); len(errs) != 0 {
		t.Fatal(errs)
	}
	a.Apply(context.Background(), snap, agent.Changes{})
	e.fw.Step()
	if d := e.desired(t); !slices.Equal(d.Ranges, []firewall.Range{{Protocol: "tcp", From: 20000, To: 20999}}) {
		t.Errorf("desired %v: only the pool, not the routes' ports", d.Ranges)
	}
}

func TestFirewallPoolResizedAndDeleted(t *testing.T) {
	e := newFwEnv(t)
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20999)})
	e.fw.Step()
	e.now = e.now.Add(gateway.FirewallEvery)
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20499)}) // resized
	e.fw.Step()
	if d := e.desired(t); !slices.Equal(d.Ranges, []firewall.Range{{Protocol: "tcp", From: 20000, To: 20499}}) {
		t.Errorf("after the resize: %v", d.Ranges)
	}
	e.now = e.now.Add(gateway.FirewallEvery)
	e.fw.Set(nil) // deleted
	e.fw.Step()
	if d := e.desired(t); len(d.Ranges) != 0 {
		t.Errorf("after the deletion: %v", d.Ranges)
	}
}

// The desired file is written at most once per FirewallEvery, and only when it changed.
func TestFirewallWritesAtMostEveryFiveSecondsAndOnlyOnChange(t *testing.T) {
	e := newFwEnv(t)
	path := filepath.Join(e.dir, gateway.DesiredFile)
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20099)})
	e.fw.Step()
	first, _ := os.Stat(path)
	// A burst of edits inside the interval: nothing is written yet.
	for i := range uint32(3) {
		e.now = e.now.Add(time.Second)
		e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20100+i)})
		e.fw.Step()
	}
	if d := e.desired(t); d.Ranges[0].To != 20099 {
		t.Errorf("written again within %v: %v", gateway.FirewallEvery, d.Ranges)
	}
	e.now = e.now.Add(gateway.FirewallEvery)
	e.fw.Step()
	if d := e.desired(t); d.Ranges[0].To != 20102 {
		t.Errorf("the last edit of the burst was not written after the interval: %v", d.Ranges)
	}
	// Nothing changed: not rewritten, so the helper's path unit is not triggered.
	second, _ := os.Stat(path)
	e.now = e.now.Add(time.Minute)
	e.fw.Step()
	if third, _ := os.Stat(path); !third.ModTime().Equal(second.ModTime()) || first.ModTime().After(second.ModTime()) {
		t.Error("an unchanged desired file was written again")
	}
}

func TestFirewallFindsTheSameFileAlreadyThere(t *testing.T) {
	e := newFwEnv(t)
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20099)})
	e.fw.Step()
	path := filepath.Join(e.dir, gateway.DesiredFile)
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	// A new process of a hand-off: the same ranges are no change.
	fw := gateway.NewFirewall(gateway.FirewallOptions{Dir: e.dir, Status: e.status, Now: func() time.Time { return e.now }})
	fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20099)})
	fw.Step()
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Error("a new process rewrote an identical desired file")
	}
}

func TestFirewallUnwritableDesiredFileIsReported(t *testing.T) {
	e := newFwEnv(t)
	if err := os.Remove(e.dir); err != nil { // the directory setup makes is missing
		t.Fatal(err)
	}
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20099)})
	e.fw.Step()
	s := e.last(t)
	if s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_FAILED || !strings.Contains(s.GetReason(), "cannot write") {
		t.Errorf("state %v, want failed with the write error", s)
	}
	// Once the directory is there, the next step writes and the failure clears with the helper's answer.
	if err := os.Mkdir(e.dir, 0o750); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(gateway.FirewallEvery)
	e.fw.Step()
	e.helper(t, firewall.Status{State: firewall.Applied, Rules: []string{"20000:20099/tcp"}})
	e.fw.Step()
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED {
		t.Errorf("state %v after the directory came back", s)
	}
}

func TestFirewallTooManyRangesIsReportedNotWritten(t *testing.T) {
	e := newFwEnv(t)
	var pools []*agentv1.GatewayPortPool
	for i := range uint32(firewall.MaxRanges + 1) {
		pools = append(pools, pool("tcp", 1000+2*i, 1000+2*i)) // never adjacent
	}
	e.fw.Set(pools)
	e.fw.Step()
	if _, err := os.Stat(filepath.Join(e.dir, gateway.DesiredFile)); err == nil {
		t.Error("a file the helper would refuse was written")
	}
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_FAILED || !strings.Contains(s.GetReason(), "more than") {
		t.Errorf("state %v", s)
	}
}

// A failed write is forgotten once the wanted ranges are the ones already written again.
func TestFirewallRevertToTheWrittenRangesClearsAFailedWrite(t *testing.T) {
	e := newFwEnv(t)
	a := []*agentv1.GatewayPortPool{pool("tcp", 2000, 2010)}
	e.fw.Set(a)
	e.fw.Step()
	e.helper(t, firewall.Status{State: firewall.Applied, Rules: []string{"2000:2010/tcp"}})
	e.now = e.now.Add(gateway.FirewallEvery)
	e.fw.Step()
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED {
		t.Fatalf("before the failure: %v", s)
	}
	var tooMany []*agentv1.GatewayPortPool
	for i := range uint32(firewall.MaxRanges + 1) {
		tooMany = append(tooMany, pool("tcp", 3000+2*i, 3000+2*i))
	}
	e.fw.Set(tooMany)
	e.now = e.now.Add(gateway.FirewallEvery)
	e.fw.Step()
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_FAILED {
		t.Fatalf("too many ranges: %v", s)
	}
	e.fw.Set(a)
	e.now = e.now.Add(gateway.FirewallEvery)
	e.helper(t, firewall.Status{State: firewall.Applied, Rules: []string{"2000:2010/tcp"}})
	e.fw.Step()
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED {
		t.Errorf("after the revert to the written ranges the state stays %v", s)
	}
}

func TestFirewallReportsTheHelpersStates(t *testing.T) {
	e := newFwEnv(t)
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20099)})
	e.fw.Step()
	for _, tc := range []struct {
		name  string
		st    firewall.Status
		phase agentv1.FirewallPhase
		want  string
	}{
		{"applied", firewall.Status{State: firewall.Applied, Rules: []string{"80/tcp", "20000:20099/tcp"}}, agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED, ""},
		{"off", firewall.Status{State: firewall.Off, Reason: "switched off; ufw is not installed"}, agentv1.FirewallPhase_FIREWALL_PHASE_OFF, "not installed"},
		{"failed", firewall.Status{State: firewall.Failed, Reason: "ufw is inactive; nothing was changed"}, agentv1.FirewallPhase_FIREWALL_PHASE_FAILED, "inactive"},
		{"failed with refused ports", firewall.Status{State: firewall.Failed, Reason: "outside the bounds", Refused: []string{"22/tcp"}}, agentv1.FirewallPhase_FIREWALL_PHASE_FAILED, "outside"},
		{"an unknown state", firewall.Status{State: "sideways"}, agentv1.FirewallPhase_FIREWALL_PHASE_FAILED, "unknown state"},
	} {
		e.now = e.now.Add(time.Second)
		e.helper(t, tc.st)
		e.fw.Step()
		s := e.last(t)
		if s.GetPhase() != tc.phase || !strings.Contains(s.GetReason(), tc.want) || !slices.Equal(s.GetRefused(), tc.st.Refused) {
			t.Errorf("%s: reported %v", tc.name, s)
		}
	}
	// The same state again is no news.
	n := len(e.reports)
	e.now = e.now.Add(time.Second)
	e.helper(t, firewall.Status{State: firewall.Failed, Reason: "outside the bounds", Refused: []string{"22/tcp"}})
	e.fw.Step()
	e.fw.Step()
	if len(e.reports) != n+1 {
		t.Errorf("%d reports for a changed state seen twice, want one more than before", len(e.reports)-n)
	}
}

func TestFirewallGarbledStatusFileIsFailed(t *testing.T) {
	e := newFwEnv(t)
	for name, content := range map[string]string{"garbage": "{not json", "empty": "", "huge": strings.Repeat("x", firewall.MaxDesired+1)} {
		if err := os.WriteFile(e.status, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		e.reports = nil
		e.fw = gateway.NewFirewall(gateway.FirewallOptions{Dir: e.dir, Status: e.status, Now: func() time.Time { return e.now },
			Report: func(s *agentv1.FirewallState) { e.reports = append(e.reports, s) }})
		e.fw.Step()
		if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_FAILED || !strings.Contains(s.GetReason(), "cannot be read") {
			t.Errorf("%s: reported %v", name, s)
		}
	}
}

func TestFirewallMissingStatusFileHasAGracePeriod(t *testing.T) {
	e := newFwEnv(t)
	e.fw.Set(nil)
	e.fw.Step()
	if len(e.reports) != 0 {
		t.Fatalf("reported %v before the helper had a chance to run", e.reports)
	}
	e.now = e.now.Add(gateway.FirewallGrace + time.Second)
	e.fw.Step()
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_FAILED || !strings.Contains(s.GetReason(), "rpmgr-firewall.path") {
		t.Errorf("reported %v, want failed naming the path unit", s)
	}
}

// A status older than the desired file the gateway wrote is no answer to it.
func TestFirewallStaleStatusFileIsFailedAfterTheGrace(t *testing.T) {
	e := newFwEnv(t)
	e.helper(t, firewall.Status{State: firewall.Applied, Rules: []string{"80/tcp"}}) // an earlier run
	e.now = e.now.Add(time.Hour)
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20099)})
	e.fw.Step()
	e.now = e.now.Add(10 * time.Second)
	e.fw.Step()
	if len(e.reports) != 0 {
		t.Fatalf("reported %v while the helper still has its grace period", e.reports)
	}
	e.now = e.now.Add(gateway.FirewallGrace)
	e.fw.Step()
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_FAILED || !strings.Contains(s.GetReason(), "has not answered") {
		t.Errorf("reported %v, want failed: the helper did not answer", s)
	}
	e.helper(t, firewall.Status{State: firewall.Applied, Rules: []string{"80/tcp", "20000:20099/tcp"}})
	e.fw.Step()
	if s := e.last(t); s.GetPhase() != agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED {
		t.Errorf("reported %v after the helper answered", s)
	}
}

func TestFirewallRunStopsWithItsContext(t *testing.T) {
	e := newFwEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.fw.Run(ctx); close(done) }()
	e.fw.Set([]*agentv1.GatewayPortPool{pool("tcp", 20000, 20099)})
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(e.dir, gateway.DesiredFile)); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run never wrote the desired file after Set")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

func TestApplierValidatesPortPools(t *testing.T) {
	a, _ := gateway.NewApplier()
	res := func(proto string, from, to uint32) *agentv1.Snapshot {
		return gatewaySnapshot(1, &agentv1.Resource{Id: "pp_1", Kind: &agentv1.Resource_GatewayPortPool{GatewayPortPool: pool(proto, from, to)}})
	}
	if errs := a.Validate(res("tcp", 1, 65535)); len(errs) != 0 {
		t.Fatalf("a valid pool: %v", errs)
	}
	for name, snap := range map[string]*agentv1.Snapshot{"protocol": res("sctp", 20000, 20010), "port 0": res("tcp", 0, 10),
		"above 65535": res("udp", 20000, 65536), "reversed": res("tcp", 30, 20)} {
		if errs := a.Validate(snap); len(errs) == 0 {
			t.Errorf("%s: a pool the helper would refuse was accepted", name)
		}
	}
}
