// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

// TestTrustRoots_ReportedAndCarried: an agent (that announces the capability, which none does yet) reports the digest of the roots it holds, the
// controller records it with the session and puts the trust roots in the agent's snapshot, and the
// agent, which does not take roots from them yet, keeps the roots file it enrolled with.
func TestTrustRoots_ReportedAndCarried(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	id := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	rootsBefore, err := os.ReadFile(filepath.Join(id.Dir, agent.RootsFile))
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := agent.NewControl(agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.7.0",
		Capabilities: []string{agentproto.CapTrustRoots}, // no agent announces it yet; the test does
		Applier:      &recorder{}, Backoff: fast(), Logger: c.Logs.Logger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = ctl.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "the applied snapshot", func() bool { return ctl.Ready(context.Background()) == nil })

	want := hex.EncodeToString(pki.RootsDigest([]*x509.Certificate{c.CA.Root()}))
	row := c.DB.Client().AgentSession.GetX(c.Sys, id.AgentID)
	if row.RootsDigest != want {
		t.Errorf("recorded digest %q, want %q", row.RootsDigest, want)
	}
	snaps := c.DB.Client().CompiledSnapshot.Query().AllX(c.Sys)
	if len(snaps) == 0 {
		t.Fatal("no snapshot was sent")
	}
	var snap agentv1.Snapshot
	if err := proto.Unmarshal(snaps[len(snaps)-1].Payload, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.TrustRoots) != 1 || !bytes.Equal(snap.TrustRoots[0], c.CA.Root().Raw) {
		t.Errorf("the snapshot's trust roots: %d", len(snap.TrustRoots))
	}
	rootsAfter, err := os.ReadFile(filepath.Join(id.Dir, agent.RootsFile))
	if err != nil || !bytes.Equal(rootsBefore, rootsAfter) {
		t.Errorf("the roots file changed: %v", err)
	}
}
