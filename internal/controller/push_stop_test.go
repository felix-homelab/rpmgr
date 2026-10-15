// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// pushStopEnv is a push environment whose system scope the test stops and whose warnings it reads.
func pushStopEnv(t *testing.T, sys context.Context, w *warnings, sources ...snapshot.Source) *sessionEnv {
	t.Helper()
	return startSessionsWith(t, storetest.Migrated(t, store.SQLite), func(o *controller.SessionsOptions) {
		o.Sys = sys
		o.Logger = slog.New(w)
		o.Compiler = &snapshot.Compiler{Sources: sources, Endpoints: func() []string { return []string{"https://ctl.example"} }}
		o.RevisionCheck = 20 * time.Millisecond
	})
}

// newRevision writes a revision, so that the pusher compiles every agent's snapshot again.
func newRevision(t *testing.T, db *store.DB, name string) {
	t.Helper()
	sys := storetest.SystemCtx(t)
	if _, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
		o, err := tx.Org.Create().SetName(name).SetSlug(name).Save(sys)
		return []string{o.ID}, err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestPush_StopDuringPush (#548): a controller that stops while it pushes, which fails the compile
// or the record under way, logs no warning or error and sends no snapshot; the agent asks its next
// session for it.
func TestPush_StopDuringPush(t *testing.T) {
	sys, stop := context.WithCancel(storetest.SystemCtx(t))
	defer stop()
	var stopNow atomic.Bool
	// The source stops the controller in the middle of the compile, as a stop does at any moment.
	stopping := func(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
		if stopNow.Load() {
			stop()
			return []*agentv1.Resource{{Id: "late", Kind: &agentv1.Resource_Reference{
				Reference: &agentv1.ResourceReference{Size: 1}}}}, nil
		}
		return orgResources(ctx, tx, a)
	}
	w := &warnings{}
	e := pushStopEnv(t, sys, w, stopping)
	cert, id := e.agentCert(t)
	ctx, cancel := context.WithCancel(testCtx(t))
	defer cancel()
	st := e.open(t, ctx, cert, hello("0.1.0"))
	if recv(t, st).GetWelcome() == nil {
		t.Fatal("no Welcome")
	}
	e.recvSnapshot(t, st, id)

	stopNow.Store(true)
	newRevision(t, e.db, "org-b")
	select {
	case <-sys.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the pusher never compiled the new revision")
	}
	// Whatever the stream still carries, it is no snapshot.
	msgs := make(chan *agentv1.ControllerMessage, 16)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				return
			}
			msgs <- m
		}
	}()
	deadline := time.After(time.Second)
	for done := false; !done; {
		select {
		case m := <-msgs:
			if m.GetSnapshot() != nil {
				t.Fatal("a stopping controller sent a snapshot")
			}
		case <-deadline:
			done = true
		}
	}
	if got := slices.DeleteFunc(w.all(), func(l string) bool {
		return !strings.Contains(l, "snapshot") && !strings.Contains(l, "agent's state")
	}); len(got) != 0 {
		t.Fatalf("a stop during a push logged:\n%s", strings.Join(got, "\n"))
	}
}

// TestPush_CompileErrorWhileRunning: a compile that fails while the controller runs is still an
// error, logged once.
func TestPush_CompileErrorWhileRunning(t *testing.T) {
	var fails atomic.Int32
	fails.Store(1)
	flaky := func(context.Context, *ent.Tx, snapshot.Agent) ([]*agentv1.Resource, error) {
		if fails.Add(-1) >= 0 {
			return nil, errors.New("flaky")
		}
		return nil, nil
	}
	w := &warnings{}
	e := pushStopEnv(t, storetest.SystemCtx(t), w, orgResources, flaky)
	cert, id := e.agentCert(t)
	st := e.open(t, testCtx(t), cert, hello("0.1.0"))
	recv(t, st)
	e.recvSnapshot(t, st, id)
	if got := w.all(); !slices.ContainsFunc(got, func(l string) bool {
		return strings.Contains(l, "cannot compile a snapshot; retrying")
	}) {
		t.Fatalf("a failing compile logged %q", got)
	}
}
