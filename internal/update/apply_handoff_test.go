// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/units"
	"github.com/felix-homelab/rpmgr/internal/update"
)

var bothNotify = map[string]bool{"rpmgr-gateway.service": true, "rpmgr-connector.service": true}

// TestApplyHandoff: the updater hands a gateway and a connector over to the new binary instead of
// restarting them, from the installed path, when both releases have the hand-off and the unit is
// Type=notify; otherwise it restarts (slice 17.7, D155).
func TestApplyHandoff(t *testing.T) {
	t.Run("both roles are handed over from the installed path, not restarted", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"gateway", "connector"}, nil)
		i.svc.notify = bothNotify
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatalf("Apply = %v", err)
		}
		if got := i.svc.restarted(); len(got) != 0 {
			t.Errorf("restarted %v; want a hand-off only", got)
		}
		if want := []string{i.bin + " connector", i.bin + " gateway"}; !slices.Equal(i.svc.handoffs, want) {
			t.Errorf("hand-offs %v; want %v", i.svc.handoffs, want)
		}
		if st := i.status(update.Updated); !slices.Equal(st.HandedOff, []string{"connector", "gateway"}) {
			t.Errorf("status %+v; want the handed-off roles", st)
		}
	})

	for name, tc := range map[string]struct {
		previous string
		notify   map[string]bool
	}{
		"the running release has none":    {"0.2.0", bothNotify},
		"the running release is unknown":  {"dev", bothNotify},
		"the unit is not Type=notify yet": {"1.1.0", nil},
	} {
		t.Run("restarted: "+name, func(t *testing.T) {
			i := newInstalled(t, hostOpts{}, tc.previous, []string{"gateway"}, nil)
			i.svc.notify = tc.notify
			i.stage(rel{version: "1.2.0", seq: 6})
			if err := i.a.Apply(context.Background()); err != nil {
				t.Fatalf("Apply = %v", err)
			}
			if len(i.svc.handoffs) != 0 || len(i.svc.restarted()) != 1 {
				t.Errorf("hand-offs %v, restarts %v; want one restart", i.svc.handoffs, i.svc.restarted())
			}
			if st := i.status(update.Updated); len(st.HandedOff) != 0 {
				t.Errorf("status %+v lists a hand-off", st)
			}
			// The drop-in is there for the next update, and the restart ran under it.
			if _, err := os.Stat(filepath.Join(i.a.Units, "rpmgr-gateway.service.d", units.DropIn)); err != nil {
				t.Errorf("no drop-in written for a release with the hand-off: %v", err)
			}
		})
	}

	t.Run("an installed release without the hand-off writes no drop-in", func(t *testing.T) {
		i := newInstalled(t, hostOpts{state: `{"seq":5,"floor":"0.1.0"}`}, "0.1.0", []string{"gateway"}, nil)
		i.stage(rel{version: "0.2.0", seq: 6, floor: "0.1.0"})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatalf("Apply = %v", err)
		}
		if _, err := os.Stat(filepath.Join(i.a.Units, "rpmgr-gateway.service.d", units.DropIn)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a drop-in for a release without the hand-off: %v", err)
		}
	})

	for name, tc := range map[string]struct {
		fails     string
		restarted []string // the roles the rollback restarts: those already handed over
		handoffs  int
		handedOff []string
	}{
		"the first":  {"connector", nil, 1, nil},
		"the second": {"gateway", []string{"rpmgr-connector.service"}, 2, []string{"connector"}},
	} {
		t.Run("a hand-off that fails ("+name+"): the old process serves, rolled back", func(t *testing.T) {
			i := newInstalled(t, hostOpts{}, "1.1.0", []string{"gateway", "connector"}, nil)
			i.svc.notify = bothNotify
			i.svc.handoffErr = map[string]error{tc.fails: errors.New("not ready within the window")}
			i.stage(rel{version: "1.2.0", seq: 6})
			err := i.a.Apply(context.Background())
			if !errors.Is(err, update.ErrRolledBack) || !strings.Contains(err.Error(), "the old process serves on") {
				t.Fatalf("Apply = %v; want rolled back, the old process serving", err)
			}
			i.runs("1.1.0") // .prev is back
			if got := i.svc.restarted(); !slices.Equal(got, tc.restarted) {
				t.Errorf("restarted %v; want %v: the process of a failed hand-off still serves", got, tc.restarted)
			}
			if len(i.svc.handoffs) != tc.handoffs {
				t.Errorf("hand-offs %v; want %d: the first failure stops the rest", i.svc.handoffs, tc.handoffs)
			}
			st := i.status(update.RolledBack)
			if !strings.Contains(st.Reason, "not ready within the window") || !slices.Equal(st.HandedOff, tc.handedOff) {
				t.Errorf("status %+v; want the hand-off's reason and the roles handed over", st)
			}
			i.leftovers()
		})
	}

	t.Run("a role handed over that is not ready: rolled back with a restart, no signal to an older process", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"gateway"}, notReady("1.2.0"))
		i.svc.notify = bothNotify
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("Apply = %v; want rolled back", err)
		}
		if len(i.svc.handoffs) != 1 || len(i.svc.restarted()) != 1 {
			t.Errorf("hand-offs %v, restarts %v; the rollback restarts and does not hand off again", i.svc.handoffs, i.svc.restarted())
		}
		if st := i.status(update.RolledBack); !slices.Equal(st.HandedOff, []string{"gateway"}) {
			t.Errorf("status %+v; want the hand-off recorded", st)
		}
	})

	t.Run("services without a hand-off restart", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"gateway"}, nil)
		svc := restartOnly{i.svc}
		i.a.Services = svc
		i.svc.notify = bothNotify
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); err != nil || len(i.svc.restarted()) != 1 {
			t.Fatalf("Apply = %v, restarts %v; want one restart", err, i.svc.restarted())
		}
	})

	t.Run("a drop-in that cannot be written is an error, and the rollback, which removes it, reports its own", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "0.2.0", []string{"gateway"}, nil)
		writeAll(t, filepath.Join(i.a.Units, "rpmgr-gateway.service.d"), "a file where the directory belongs")
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRollbackFailed) {
			t.Fatalf("Apply = %v; want the install to fail and the rollback with it", err)
		}
	})
}

// restartOnly hides a services' Handoff.
type restartOnly struct{ *services }

func (restartOnly) Handoff() {}
