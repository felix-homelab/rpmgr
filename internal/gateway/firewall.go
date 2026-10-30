// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/firewall"
)

// The host firewall helper's timers (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	FirewallEvery = 5 * time.Second // the desired file is written at most this often, and the status read
	FirewallGrace = time.Minute     // how long the helper may take to answer before the gateway reports it failed
)

// The files of the helper (docs/10-operations.md, "Host firewall helper"). The helper's status is
// always where its unit puts it.
const (
	DesiredFile = "desired.json"
	StatusFile  = "/run/rpmgr-firewall/status.json"
)

// FirewallOptions configure a Firewall.
type FirewallOptions struct {
	// Dir is the directory of the desired file, which the service user owns.
	Dir string
	// Status is the helper's status file; empty is StatusFile.
	Status string
	// Report is called with the state each time it changes.
	Report func(*agentv1.FirewallState)
	Now    func() time.Time
	Logger *slog.Logger
}

// Firewall is the gateway's side of the host firewall helper (docs/04-security.md, "Host firewall
// for port pools"; D152): it writes the ranges of the group's port pools to the desired file, the
// only thing it ever writes for the helper, and reads the helper's status file back, to report it.
// The gateway stays unprivileged: it runs no command and opens no port itself.
type Firewall struct {
	o       FirewallOptions
	started time.Time

	mu       sync.Mutex
	wanted   *firewall.Desired // nil until the first snapshot
	written  []byte            // the desired file's content as last written, or found equal
	wroteAt  time.Time
	writeErr error
	reported *agentv1.FirewallState
	signal   chan struct{}
}

// NewFirewall returns a Firewall that has not written or reported anything yet.
func NewFirewall(o FirewallOptions) *Firewall {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Status == "" {
		o.Status = StatusFile
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Firewall{o: o, started: o.Now(), signal: make(chan struct{}, 1)}
}

// Set takes the port pools of the applied snapshot, all of them each time, and the desired file is
// written at the next step. The ranges are merged and sorted; a pool the snapshot no longer holds
// is gone from the file, so the helper closes its range.
func (f *Firewall) Set(pools []*agentv1.GatewayPortPool) {
	d := desiredOf(pools)
	f.mu.Lock()
	f.wanted = &d
	f.mu.Unlock()
	select {
	case f.signal <- struct{}{}:
	default:
	}
}

// desiredOf is the desired file for pools, in the form the helper parses: its ranges merged where
// they overlap or touch, tcp before udp.
func desiredOf(pools []*agentv1.GatewayPortPool) firewall.Desired {
	rs := make([]firewall.Range, 0, len(pools))
	for _, p := range pools {
		rs = append(rs, firewall.Range{Protocol: p.GetProtocol(), From: int(p.GetPortFrom()), To: int(p.GetPortTo())})
	}
	slices.SortFunc(rs, func(a, b firewall.Range) int {
		return cmp.Or(strings.Compare(a.Protocol, b.Protocol), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	out := []firewall.Range{}
	for _, r := range rs {
		if n := len(out); n > 0 && out[n-1].Protocol == r.Protocol && r.From <= out[n-1].To+1 {
			out[n-1].To = max(out[n-1].To, r.To)
			continue
		}
		out = append(out, r)
	}
	return firewall.Desired{Version: 1, Ranges: out}
}

// Run steps every FirewallEvery until ctx ends or the signal of Set asks for one earlier; the
// write itself still waits out FirewallEvery since the last.
func (f *Firewall) Run(ctx context.Context) {
	t := time.NewTicker(FirewallEvery)
	defer t.Stop()
	for {
		f.Step()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-f.signal:
		}
	}
}

// Step writes the desired file if its content changed and FirewallEvery has passed since the last
// write, then reads the helper's status and reports it if it changed.
func (f *Firewall) Step() {
	now := f.o.Now()
	f.write(now)
	st := f.state(now)
	f.mu.Lock()
	changed := st != nil && !sameState(f.reported, st)
	if changed {
		f.reported = st
	}
	f.mu.Unlock()
	if changed && f.o.Report != nil {
		f.o.Report(st)
	}
}

// write writes the desired file, atomically, when the ranges changed since the last write or the
// file's content differs from them, and not more often than FirewallEvery. A failure is kept for
// the state and retried at the next step.
func (f *Firewall) write(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wanted == nil {
		return
	}
	raw, err := json.Marshal(f.wanted)
	if err != nil {
		f.writeErr = err
		return
	}
	raw = append(raw, '\n')
	if bytes.Equal(raw, f.written) {
		return
	}
	if len(f.wanted.Ranges) > firewall.MaxRanges {
		f.writeErr = fmt.Errorf("the group's port pools make %d ranges, more than the %d the helper reads", len(f.wanted.Ranges), firewall.MaxRanges)
		return
	}
	path := filepath.Join(f.o.Dir, DesiredFile)
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, raw) { //nolint:gosec // G304: the gateway's own file
		f.written, f.writeErr = raw, nil // an earlier process wrote it already: the helper has nothing to do
		return
	}
	if !f.wroteAt.IsZero() && now.Sub(f.wroteAt) < FirewallEvery {
		return
	}
	f.wroteAt = now
	if err := writeAtomic(path, raw); err != nil {
		f.writeErr = err
		f.o.Logger.Warn("cannot write the firewall helper's desired file", "path", path, "error", err)
		return
	}
	f.written, f.writeErr = raw, nil
}

// writeAtomic writes path through a new file in its directory, renamed over it, readable by the
// helper.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // a no-op after the rename
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	return err
}

// state is what the gateway reports now: a failed write first, then the helper's status. nil says
// there is nothing to report yet: the helper has a grace period to answer for the first time and
// after each change of the desired file.
func (f *Firewall) state(now time.Time) *agentv1.FirewallState {
	f.mu.Lock()
	wroteAt, werr, wrote := f.wroteAt, f.writeErr, f.written != nil
	f.mu.Unlock()
	failed := func(format string, args ...any) *agentv1.FirewallState {
		return &agentv1.FirewallState{Phase: agentv1.FirewallPhase_FIREWALL_PHASE_FAILED, Reason: fmt.Sprintf(format, args...),
			Reported: timestamppb.New(now)}
	}
	if werr != nil {
		return failed("the gateway cannot write the ranges it wants open to %s: %v", filepath.Join(f.o.Dir, DesiredFile), werr)
	}
	st, err := firewall.ReadStatus(f.o.Status)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if now.Sub(f.started) < FirewallGrace {
			return nil
		}
		return failed("the firewall helper has not reported: is rpmgr-firewall.path enabled? (systemctl status rpmgr-firewall.path)")
	case err != nil:
		return failed("the firewall helper's status cannot be read: %v", err)
	}
	// A status older than the last desired file is no answer to it.
	if wrote && st.At.Before(wroteAt.Truncate(time.Second)) {
		if now.Sub(wroteAt) < FirewallGrace {
			return nil
		}
		return failed("the firewall helper has not answered the ranges written at %s; is rpmgr-firewall.path running?",
			wroteAt.UTC().Format(time.RFC3339))
	}
	out := &agentv1.FirewallState{Reason: st.Reason, Rules: st.Rules, Refused: st.Refused, Reported: timestamppb.New(st.At)}
	switch st.State {
	case firewall.Off:
		out.Phase = agentv1.FirewallPhase_FIREWALL_PHASE_OFF
	case firewall.Applied:
		out.Phase = agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED
	case firewall.Failed:
		out.Phase = agentv1.FirewallPhase_FIREWALL_PHASE_FAILED
	default:
		return failed("the firewall helper reported the unknown state %q", st.State)
	}
	return out
}

// sameState reports whether two states say the same to the operator; the time they were reported
// at is not part of it.
func sameState(a, b *agentv1.FirewallState) bool {
	return a != nil && b != nil && a.GetPhase() == b.GetPhase() && a.GetReason() == b.GetReason() &&
		slices.Equal(a.GetRules(), b.GetRules()) && slices.Equal(a.GetRefused(), b.GetRefused())
}
