// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"slices"
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
)

// TestLocalControllerEndpoints: the host's commands try the controller endpoints of the stored
// snapshot, as the agent does after a start, or those of the enrollment while there is no stored
// snapshot that verifies (ReadLocal leaves Snapshot nil then) or it names none.
func TestLocalControllerEndpoints(t *testing.T) {
	enrolled := []string{"https://gw.example.net:8443"}
	stored := []string{"https://ctl.example", "https://gw.example.net:8443"}
	for _, tt := range []struct {
		name string
		snap *agentv1.Snapshot
		want []string
	}{
		{"no stored snapshot", nil, enrolled},
		{"a stored snapshot without endpoints", &agentv1.Snapshot{}, enrolled},
		{"a stored snapshot with an empty list", &agentv1.Snapshot{ControllerEndpoints: []string{}}, enrolled},
		{"a stored snapshot", &agentv1.Snapshot{ControllerEndpoints: stored}, stored},
	} {
		l := agent.Local{Loaded: agent.Loaded{Identity: agent.Identity{Endpoints: enrolled}}, Snapshot: tt.snap}
		if got := l.ControllerEndpoints(); !slices.Equal(got, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}
