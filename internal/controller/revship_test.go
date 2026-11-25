// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// TestRevocationShipperStalled: the alert follows the time since the last successful round, so a
// sink that never answers alerts although no entry is known to be unshipped.
func TestRevocationShipperStalled(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "revocations.log")
	if _, err := revlog.Open(logPath, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	sink := filepath.Join(t.TempDir(), "share") // not mounted
	r := &controller.RevocationShipper{Path: logPath, Sink: sink, Replica: "ctn_a", Now: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := r.Ship(); err == nil {
		t.Fatal("shipped to an unmounted sink")
	}
	if r.Status().Alerting(now.Add(revlog.OffHostAlert)) || !r.Status().Alerting(now.Add(revlog.OffHostAlert+time.Second)) {
		t.Error("a failing round does not alert after 5 min, or alerts earlier")
	}
	if err := os.Mkdir(sink, 0o750); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := r.Ship(); err != nil {
		t.Fatal(err)
	}
	if r.Status().Alerting(now.Add(revlog.OffHostAlert)) {
		t.Error("alert right after a successful round")
	}
}
