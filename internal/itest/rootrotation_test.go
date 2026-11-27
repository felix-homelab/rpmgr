// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// TestRootRotation_AgentLearnsAndDropsTheRoot: a connected agent that enrolled under the old root learns the
// new root from the snapshot the rotation's revision produced, its digest is recorded and it is no straggler;
// when the old root is dropped, a snapshot of the next revision, signed under the new root, removes it from
// the agent's roots, and the agent keeps the snapshots coming.
func TestRootRotation_AgentLearnsAndDropsTheRoot(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	id := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	ctl, err := agent.NewControl(agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.7.0",
		Applier: &recorder{}, Backoff: fast(), Logger: c.Logs.Logger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = ctl.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "the applied snapshot", func() bool { return ctl.Ready(context.Background()) == nil })

	r1 := c.CA.Root()
	clock := func() time.Time { return time.Now() }
	plan, err := castore.PlanNewRoot(c.Sys, c.DB.ReadClient().CAKey, c.Sealer(), clock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) { _, err := plan.Apply(c.Sys, tx); return []string{"pki"}, err }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CA.Reload(c.Sys, c.DB, c.Sealer(), clock); err != nil {
		t.Fatal(err)
	}
	r2 := c.CA.Root()
	held := func() []*x509.Certificate { return ctl.Identity().RootCerts }

	waitFor(t, "the agent to learn the new root", func() bool { return len(held()) == 2 })
	if !held()[0].Equal(r1) || !held()[1].Equal(r2) {
		t.Fatal("the agent holds other roots than the old and the new")
	}
	// It reports the new digest from the reconnect, and the controller does not list it as a straggler.
	want := hex.EncodeToString(pki.RootsDigest([]*x509.Certificate{r1, r2}))
	waitFor(t, "the session to report the new digest", func() bool { return c.DB.Client().AgentSession.GetX(c.Sys, id.AgentID).RootsDigest == want })
	if err := store.ReadTx(c.Sys, c.DB, func(tx *ent.Tx, _ store.Revision) error {
		l, err := controller.Stragglers(c.Sys, tx, time.Now().Add(-time.Hour))
		if err != nil || len(l) != 0 {
			t.Errorf("stragglers %v, %v", l, err)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// The drop: the next revision's snapshot is signed under the new root and no longer lists the old one.
	dp, err := castore.PlanDropRoot(c.Sys, c.DB.ReadClient().CAKey, time.Now().Add(time.Minute), castore.DropOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) { _, err := dp.Apply(c.Sys, tx); return []string{"pki"}, err }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CA.Reload(c.Sys, c.DB, c.Sealer(), clock); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the agent to drop the old root", func() bool { return len(held()) == 1 && held()[0].Equal(r2) })
	if b, err := os.ReadFile(filepath.Join(id.Dir, agent.RootsFile)); err != nil || len(b) == 0 {
		t.Fatalf("roots.pem: %v", err)
	}
}

// rotateRoot runs `ca new-root` against the controller's database with the old root online, as the command does,
// and reloads the CA.
func rotateRoot(t *testing.T, c *itest.Controller) {
	t.Helper()
	now := time.Now()
	plan, err := castore.PlanNewRoot(c.Sys, c.DB.ReadClient().CAKey, c.Sealer(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) { _, err := plan.Apply(c.Sys, tx); return []string{"pki"}, err }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CA.Reload(c.Sys, c.DB, c.Sealer(), time.Now); err != nil {
		t.Fatal(err)
	}
}

// TestRootRotation_OfflineAgentReauthenticates: an agent that was offline through the switch, whose certificate
// expired in the meantime within the grace period, reauthenticates through the old root, which it still knows
// only: the controller accepts its old chain, the chain it gets back carries Y beside the new intermediate and
// verifies under the old root alone, and then it learns the new root from its next session.
func TestRootRotation_OfflineAgentReauthenticates(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	id := c.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	expired := c.IssueAt(t, id, time.Now().Add(-8*24*time.Hour)) // under the old intermediate
	r1 := c.CA.Root()
	rotateRoot(t, c) // while the agent is offline
	id, err := agent.Load(id.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.RootCerts) != 1 {
		t.Fatalf("the agent holds %d roots before it reconnects", len(id.RootCerts))
	}
	runAgent(t, id, nil)
	renewed := waitNewCertificate(t, id.Dir, pki.SerialHex(expired.SerialNumber))
	roots := x509.NewCertPool()
	roots.AddCert(r1) // all the agent knows
	inters := x509.NewCertPool()
	for _, der := range renewed.Certificate.Certificate[1:] {
		ic, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		inters.AddCert(ic)
	}
	if _, err := renewed.Certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the reissued certificate does not verify under the old root alone: %v", err)
	}
	if len(renewed.Certificate.Certificate) != 3 {
		t.Fatalf("the reissued chain holds %d certificates, want the leaf, the new intermediate and Y", len(renewed.Certificate.Certificate))
	}
	waitFor(t, "a session after Reauth", func() bool { return slices.Contains(c.Sessions.Connected(), id.AgentID) })
	waitFor(t, "the agent to learn the new root", func() bool {
		l, err := agent.Load(id.Dir)
		return err == nil && len(l.RootCerts) == 2 && l.RootCerts[1].Equal(c.CA.Root())
	})
}
