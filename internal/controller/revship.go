// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// RevocationShipEvery is how often a controller ships its revocation log to the sink.
const RevocationShipEvery = 10 * time.Second

// RevocationShipper ships a controller's revocation log to the filesystem sink of its boot file,
// and keeps where the log stands for the UI and the metrics (docs/10-operations.md, "Backup and
// restore"). A revocation never waits for it: entries are appended and enforced first.
type RevocationShipper struct {
	Path    string // the local revocations.log
	Sink    string // the sink directory; empty for none
	Replica string // this controller's node ID
	Logger  *slog.Logger

	mu      sync.Mutex
	status  revlog.Status
	lastErr string
}

// Ship runs one round and returns its error; without a sink there is nothing to ship.
func (r *RevocationShipper) Ship() error {
	if r.Sink == "" {
		return nil
	}
	left, err := revlog.Sink{Dir: r.Sink}.Ship(r.Path, r.Replica)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = revlog.StatusOf(true, left)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	switch {
	case msg != "" && msg != r.lastErr:
		r.Logger.Warn("revocation log: the sink takes no entries; revocations are still enforced", "sink", r.Sink, "unshipped", len(left), "error", err)
	case msg == "" && r.lastErr != "":
		r.Logger.Info("revocation log: the sink takes entries again", "sink", r.Sink)
	}
	r.lastErr = msg
	return err
}

// Run ships at once and then every RevocationShipEvery until ctx ends.
func (r *RevocationShipper) Run(ctx context.Context) {
	for {
		_ = r.Ship()
		select {
		case <-ctx.Done():
			return
		case <-time.After(RevocationShipEvery):
		}
	}
}

// Status is where the log stands after the last round.
func (r *RevocationShipper) Status() revlog.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.status
	st.Sink = r.Sink != ""
	return st
}

// Collectors are the shipper's metrics (docs/10-operations.md, "Metrics").
func (r *RevocationShipper) Collectors() []prometheus.Collector {
	gauge := func(name, help string, value func(revlog.Status) float64) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, func() float64 { return value(r.Status()) })
	}
	return []prometheus.Collector{
		gauge("rpmgr_revocation_log_sink", "1 if a sink keeps the revocation log off the host", func(s revlog.Status) float64 {
			if s.Sink {
				return 1
			}
			return 0
		}),
		gauge("rpmgr_revocation_log_unshipped", "revocation log entries the sink does not hold yet", func(s revlog.Status) float64 { return float64(s.Unshipped) }),
		gauge("rpmgr_revocation_log_oldest_unshipped_timestamp_seconds", "when the oldest unshipped revocation log entry was logged; 0 when none",
			func(s revlog.Status) float64 {
				if s.Oldest.IsZero() {
					return 0
				}
				return float64(s.Oldest.Unix())
			}),
	}
}
