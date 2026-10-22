// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// TestStager_UpdaterTakesStaging: what the agent stages is what the root updater takes: its copy
// of the staging directory verifies for a connector-variant install, with the artifact of that
// variant.
func TestStager_UpdaterTakesStaging(t *testing.T) {
	rel := newOTARelease(t, "0.2.0", 7, release.Stable, "full", "connector")
	e := newOTAEnv(t, rel)
	e.stager(run(t), "connector").Offer(rel.offer())
	e.until(agentv1.UpdatePhase_UPDATE_PHASE_STAGED)

	state := filepath.Join(t.TempDir(), "rpmgr-update")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"install.json": `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"connector","roles":["connector"]}`,
		"state.json":   `{"seq":6,"floor":"0.1.0"}`,
	} {
		if err := os.WriteFile(filepath.Join(state, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := release.ParsePublicKey(otaRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	u := &update.Updater{Staged: e.dir, State: state, Policy: filepath.Join(t.TempDir(), "policy.yaml"),
		Roots: []release.PublicKey{root}, Now: func() time.Time { return otaNow }, OS: "linux", Arch: "amd64"}
	staged, err := u.Stage()
	if err != nil {
		t.Fatalf("the updater refused what the agent staged: %v", err)
	}
	if staged.Manifest.Version != "0.2.0" || staged.Artifact.Variant != "connector" || staged.Next.Seq != 7 {
		t.Fatalf("the updater staged %+v", staged)
	}
}
