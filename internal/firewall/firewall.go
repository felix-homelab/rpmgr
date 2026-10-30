// SPDX-License-Identifier: Apache-2.0

// Package firewall is the root-owned helper that applies a gateway's port-pool ranges to the
// host's ufw (docs/04-security.md, "Host firewall for port pools"; D152). The gateway only writes
// the ranges it wants to a file; the helper opens only ports inside the bounds a root-owned file
// sets, adds rules that carry its marker and deletes only those.
package firewall

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The limits of docs/03-connections.md, "Timeouts, keepalive and backoff".
const (
	MaxDesired     = 64 << 10 // bytes of the desired file
	MaxBounds      = 16 << 10 // bytes of the bounds file
	MaxRanges      = 256      // ranges in the desired file
	MaxListeners   = 16       // listeners in the bounds file
	CommandTimeout = 30 * time.Second
	RunTimeout     = 5 * time.Minute
)

// Marker is the comment on every ufw rule the helper adds, and the only rules it deletes.
const Marker = "rpmgr"

// The states of Status.
const (
	Off     = "off"     // switched off; the helper holds no rule
	Applied = "applied" // every rule is in place
	Failed  = "failed"  // something is wrong; Reason says what
)

// Range is a range of ports of one protocol, both ends included.
type Range struct {
	Protocol string `json:"protocol"`
	From     int    `json:"from"`
	To       int    `json:"to"`
}

func (r Range) String() string {
	if r.From == r.To {
		return fmt.Sprintf("%d/%s", r.From, r.Protocol)
	}
	return fmt.Sprintf("%d:%d/%s", r.From, r.To, r.Protocol)
}

func (r Range) valid() error {
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("protocol %q is neither tcp nor udp", r.Protocol)
	}
	if r.From < 1 || r.To > 65535 || r.From > r.To {
		return fmt.Errorf("ports %d to %d are not within 1 to 65535 in order", r.From, r.To)
	}
	return nil
}

// Desired is the file the gateway writes: the ranges it wants open.
type Desired struct {
	Version int     `json:"version"`
	Ranges  []Range `json:"ranges"`
}

// Listener is a port the gateway itself listens on.
type Listener struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// PortRange is the operator's maximum range for pools, for both protocols.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Bounds is the root-owned file that limits what the helper opens.
type Bounds struct {
	Version   int        `json:"version"`
	Backend   string     `json:"backend"` // "ufw"; "" or "off" switches the helper off
	Listeners []Listener `json:"listeners"`
	MaxRange  *PortRange `json:"max_range,omitempty"`
}

// Status is the helper's outcome, which the gateway reads and reports.
type Status struct {
	State   string    `json:"state"`
	Reason  string    `json:"reason,omitempty"`
	Rules   []string  `json:"rules,omitempty"`   // the rules the helper holds, as `ufw` names them
	Refused []string  `json:"refused,omitempty"` // desired ports outside the bounds, never opened
	At      time.Time `json:"at"`
}

// Applier is one run of the helper.
type Applier struct {
	Desired, Bounds, StatusFile string
	// Ufw runs ufw; nil means the installed ufw.
	Ufw Runner
	// RootUID is the owner the bounds file must have; tests set their own.
	RootUID uint32
	Now     func() time.Time
}

// Apply reads the bounds and the desired file, makes ufw hold the rules they allow and writes the
// outcome to the status file. It returns the status; an error means the state is Failed or the
// status could not be written.
func (a *Applier) Apply(ctx context.Context) (Status, error) {
	st := a.run(ctx)
	if a.Now != nil {
		st.At = a.Now()
	} else {
		st.At = time.Now()
	}
	st.At = st.At.UTC().Truncate(time.Second)
	if err := writeStatus(a.StatusFile, st); err != nil {
		return st, err
	}
	if st.State == Failed {
		return st, errors.New(st.Reason)
	}
	return st, nil
}

func (a *Applier) run(ctx context.Context) Status {
	fail := func(format string, args ...any) Status {
		return Status{State: Failed, Reason: fmt.Sprintf(format, args...)}
	}
	var b Bounds
	switch raw, err := readChecked(a.Bounds, MaxBounds, true, a.RootUID); {
	case errors.Is(err, os.ErrNotExist):
		b.Backend = "" // no bounds file: switched off
	case err != nil:
		return fail("the bounds file is refused, so nothing was changed: %v", err)
	default:
		if err := parseStrict(raw, &b); err != nil {
			return fail("the bounds file is refused, so nothing was changed: %v", err)
		}
		if err := b.check(); err != nil {
			return fail("the bounds file is refused, so nothing was changed: %v", err)
		}
	}
	u := a.Ufw
	if u == nil {
		u = &execRunner{}
	}
	switch err := ufwActive(ctx, u); {
	case errors.Is(err, ErrNotInstalled), errors.Is(err, errInactive):
		if b.Backend == "ufw" {
			return fail("%v; nothing was changed", err)
		}
		return Status{State: Off, Reason: "switched off; " + err.Error()}
	case err != nil:
		return fail("asking ufw for its state: %v", err)
	}
	if b.Backend != "ufw" {
		if err := converge(ctx, u, nil); err != nil {
			return fail("removing the rules of rpmgr: %v", err)
		}
		return Status{State: Off, Reason: "switched off; the rules of rpmgr are removed"}
	}
	var d Desired
	switch raw, err := readChecked(a.Desired, MaxDesired, false, 0); {
	case errors.Is(err, os.ErrNotExist):
		d.Version = 1 // nothing asked for yet: only the listeners
	case err != nil:
		return fail("the desired file is refused, so nothing was changed: %v", err)
	default:
		if err := parseStrict(raw, &d); err != nil {
			return fail("the desired file is refused, so nothing was changed: %v", err)
		}
		if err := d.check(); err != nil {
			return fail("the desired file is refused, so nothing was changed: %v", err)
		}
	}
	want, refused := plan(b, d)
	if err := converge(ctx, u, want); err != nil {
		return fail("%v", err)
	}
	st := Status{State: Applied}
	for _, r := range want {
		st.Rules = append(st.Rules, r.String())
	}
	if len(refused) > 0 {
		st.State, st.Refused = Failed, refused
		st.Reason = "outside the bounds, so never opened: " + strings.Join(refused, ", ") + "; the rest was applied"
	}
	return st
}

func (b Bounds) check() error {
	switch {
	case b.Version != 1:
		return fmt.Errorf("version %d is not 1", b.Version)
	case b.Backend != "" && b.Backend != "off" && b.Backend != "ufw":
		return fmt.Errorf("backend %q is not ufw or off", b.Backend)
	case len(b.Listeners) > MaxListeners:
		return fmt.Errorf("more than %d listeners", MaxListeners)
	}
	for _, l := range b.Listeners {
		if err := (Range{l.Protocol, l.Port, l.Port}).valid(); err != nil {
			return fmt.Errorf("listener: %w", err)
		}
	}
	if m := b.MaxRange; m != nil {
		if err := (Range{"tcp", m.From, m.To}).valid(); err != nil {
			return fmt.Errorf("max_range: %w", err)
		}
	}
	return nil
}

func (d Desired) check() error {
	if d.Version != 1 {
		return fmt.Errorf("version %d is not 1", d.Version)
	}
	if len(d.Ranges) > MaxRanges {
		return fmt.Errorf("%d ranges, more than %d", len(d.Ranges), MaxRanges)
	}
	for _, r := range d.Ranges {
		if err := r.valid(); err != nil {
			return err
		}
	}
	return nil
}

// parseStrict decodes exactly one JSON value, refusing unknown fields and anything after it.
func parseStrict(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("more than one JSON value")
	}
	return nil
}

// plan returns the ranges the helper should hold, merged, and the desired ports outside the
// bounds, which it never opens: a port is inside if the gateway listens on it or it lies in the
// maximum range.
func plan(b Bounds, d Desired) (want []Range, refused []string) {
	var outside []Range
	for _, proto := range []string{"tcp", "udp"} {
		var allowed, open []Range
		for _, l := range b.Listeners {
			if l.Protocol == proto {
				allowed, open = append(allowed, Range{proto, l.Port, l.Port}), append(open, Range{proto, l.Port, l.Port})
			}
		}
		if m := b.MaxRange; m != nil {
			allowed = append(allowed, Range{proto, m.From, m.To})
		}
		allowed = merge(allowed)
		for _, r := range d.Ranges {
			if r.Protocol != proto {
				continue
			}
			in, out := split(r, allowed)
			open = append(open, in...)
			outside = append(outside, out...)
		}
		want = append(want, merge(open)...)
	}
	slices.SortFunc(outside, func(a, b Range) int { return cmp.Or(strings.Compare(a.Protocol, b.Protocol), a.From-b.From, a.To-b.To) })
	for _, o := range slices.Compact(outside) {
		refused = append(refused, o.String())
	}
	return want, refused
}

// merge sorts ranges of one protocol and joins those that overlap or touch.
func merge(rs []Range) []Range {
	slices.SortFunc(rs, func(a, b Range) int { return a.From - b.From })
	var out []Range
	for _, r := range rs {
		if n := len(out); n > 0 && r.From <= out[n-1].To+1 {
			out[n-1].To = max(out[n-1].To, r.To)
			continue
		}
		out = append(out, r)
	}
	return out
}

// split divides r into the parts inside the merged ranges allowed and the parts outside.
func split(r Range, allowed []Range) (in, out []Range) {
	next := r.From
	for _, a := range allowed {
		if a.To < next || a.From > r.To {
			continue
		}
		if a.From > next {
			out = append(out, Range{r.Protocol, next, a.From - 1})
		}
		in = append(in, Range{r.Protocol, max(a.From, next), min(a.To, r.To)})
		next = min(a.To, r.To) + 1
	}
	if next <= r.To {
		out = append(out, Range{r.Protocol, next, r.To})
	}
	return in, out
}

func writeStatus(path string, st Status) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: the status is read by the gateway
		return fmt.Errorf("firewall: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".status-*")
	if err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("firewall: writing the status: %w", err)
	}
	return nil
}

// ReadStatus reads the status file, which the gateway reports.
func ReadStatus(path string) (Status, error) {
	raw, err := readChecked(path, MaxDesired, false, 0)
	if err != nil {
		return Status{}, err
	}
	var st Status
	return st, json.Unmarshal(raw, &st)
}
