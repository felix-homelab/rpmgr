// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestAgentReadiness: an agent is ready only with a control session and an applied snapshot; one
// that rejects every snapshot is not; its metrics report the applied revision and its
// certificate's expiry.
func TestAgentReadiness(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	for _, tc := range []struct {
		name    string
		applier agent.Applier
		want    error
	}{{"applies", &recorder{}, nil}, {"rejects", rejecter{}, agent.ErrNoSnapshot}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := c.EnrollConnector(t, filepath.Join(dir, "identity"))
			state := filepath.Join(dir, "state")
			if err := os.MkdirAll(state, 0o750); err != nil {
				t.Fatal(err)
			}
			ctl, err := agent.NewControl(agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
				Applier: tc.applier, Backoff: fast(), Logger: c.Logs.Logger()})
			if err != nil {
				t.Fatal(err)
			}
			reg := telemetry.NewRegistry()
			if err := ctl.Register(reg); err != nil {
				t.Fatal(err)
			}
			if err := ctl.Ready(context.Background()); !errors.Is(err, agent.ErrNoSession) {
				t.Fatalf("before Run: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { _ = ctl.Run(ctx); close(done) }()
			defer func() { cancel(); <-done }()
			waitFor(t, "the readiness", func() bool { return errors.Is(ctl.Ready(context.Background()), tc.want) })
			if tc.want != nil {
				return
			}
			families, err := reg.Gather()
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]float64{}
			for _, f := range families {
				if len(f.GetMetric()) == 1 && f.GetMetric()[0].GetGauge() != nil {
					values[f.GetName()] = f.GetMetric()[0].GetGauge().GetValue()
				}
			}
			if values["rpmgr_agent_cert_expiry_timestamp_seconds"] != float64(id.Certificate.Leaf.NotAfter.Unix()) {
				t.Errorf("certificate expiry %v", values["rpmgr_agent_cert_expiry_timestamp_seconds"])
			}
			if _, ok := values["rpmgr_agent_applied_revision"]; !ok {
				t.Error("no applied revision")
			}
		})
	}
}
