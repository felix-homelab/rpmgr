// SPDX-License-Identifier: Apache-2.0

//go:build linux

package allinone_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/handoff"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// holdsDatabase reports whether this process has the controller's database open.
func holdsDatabase(t *testing.T) bool {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if to, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil && strings.Contains(to, "controller.db") {
			return true
		}
	}
	return false
}

// runWith runs the installation with link and returns what Run returns, and a stop function.
func (h *host) runWith(t *testing.T, link *handoff.Link) (done chan error, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() {
		done <- allinone.Run(ctx, allinone.RunOptions{Config: h.cfg, Version: "0.1.0", Getenv: func(string) string { return "" },
			DrainPeriod: 200 * time.Millisecond, Handoff: link})
	}()
	t.Cleanup(cancel)
	return done, cancel
}

func (h *host) servesTheWebUI() bool {
	resp, err := h.web.Get(h.publicURL + "/.well-known/rpmgr/trust-bundle")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestAllInOne_ReleaseClosesTheDatabaseAndResumeOpensItAgain: the old process lets go of the
// database before the new one may open it, stops answering the controller's connections while it
// has none, and a failed hand-over (Resume) brings the controller back, built-in agents included.
func TestAllInOne_ReleaseClosesTheDatabaseAndResumeOpensItAgain(t *testing.T) {
	h := newHost(t)
	h.init(t)
	link := handoff.NewLink(nil, func(string) string { return "" }, nil)
	done, stop := h.runWith(t, link)
	waitFor(t, "not ready", h.ready)
	if !holdsDatabase(t) || !h.servesTheWebUI() {
		t.Fatal("the controller does not run")
	}
	if link.Release == nil || link.Resume == nil {
		t.Fatal("Run set no Release and Resume on the link")
	}

	if err := link.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if holdsDatabase(t) {
		t.Fatalf("the database is still open after Release: the new process could write at the same time: %v", openDatabaseFiles())
	}
	if h.servesTheWebUI() {
		t.Fatal("the controller answers after Release")
	}

	link.Resume()
	if !holdsDatabase(t) {
		t.Fatal("the database is not open after Resume")
	}
	// The gateway and the connector reconnect, and the public URL serves again.
	waitFor(t, "the built-in agents did not reconnect after Resume", func() bool { return h.ready() && h.servesTheWebUI() })
	stop()
	if err := <-done; err != nil {
		t.Errorf("Run ended with %v", err)
	}
}

// TestAllInOne_ResumeThatCannotOpenTheDatabaseEndsRun: with no controller and none that can
// start, Run ends with an error, so that the service manager restarts the unit.
func TestAllInOne_ResumeThatCannotOpenTheDatabaseEndsRun(t *testing.T) {
	h := newHost(t)
	h.init(t)
	link := handoff.NewLink(nil, func(string) string { return "" }, nil)
	done, _ := h.runWith(t, link)
	waitFor(t, "not ready", h.ready)
	if err := link.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := os.WriteFile(h.cfg.Database.DSN, []byte("this is not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	link.Resume()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "cannot resume after a failed hand-over") {
			t.Fatalf("Run ended with %v, want the resume failure", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not end although the controller cannot resume")
	}
}

func openDatabaseFiles() []string {
	var out []string
	fds, _ := os.ReadDir("/proc/self/fd")
	for _, fd := range fds {
		if to, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil && strings.Contains(to, "controller.db") {
			out = append(out, fd.Name()+" "+to)
		}
	}
	return out
}

// TestAllInOne_ResumeRefusesASchemaTheNewProcessMigrated: if the new process had already migrated,
// the old one's controller refuses the newer schema and Run ends, so that the operator restores
// the backup.
func TestAllInOne_ResumeRefusesASchemaTheNewProcessMigrated(t *testing.T) {
	h := newHost(t)
	h.init(t)
	link := handoff.NewLink(nil, func(string) string { return "" }, nil)
	done, _ := h.runWith(t, link)
	waitFor(t, "not ready", h.ready)
	if err := link.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	db, err := sql.Open("sqlite", h.cfg.Database.DSN)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO ` + store.RevisionTable + ` (version, description, type, applied, total, executed_at,
  execution_time, error, error_stmt, hash, partial_hashes, operator_version)
  VALUES ('99991231000000', 'newer', 2, 1, 1, '2999-01-01T00:00:00Z', 0, '', '', 'x', '[]', '')`)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	link.Resume()
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrUnknownMigration) {
			t.Fatalf("Run ended with %v, want ErrUnknownMigration", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not end although the schema is newer")
	}
}
