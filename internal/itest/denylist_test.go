// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// rejecter is an Applier that rejects every snapshot.
type rejecter struct{}

func (rejecter) Validate(*agentv1.Snapshot) []*agentv1.SnapshotError {
	return []*agentv1.SnapshotError{{Message: "rejected by the test"}}
}

func (rejecter) Apply(context.Context, *agentv1.Snapshot, agent.Changes) []*agentv1.ResourceStatus {
	return nil
}

// TestDenyList_AppliedDespiteRejectedSnapshot: an agent that rejects its snapshots still applies
// and stores every deny-list; after a restore that lost the revocation (a new database epoch and a
// list without the entry), the agent still denies the certificate.
func TestDenyList_AppliedDespiteRejectedSnapshot(t *testing.T) {
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}})
	dir := t.TempDir()
	id := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	other := c.EnrollConnector(t, filepath.Join(dir, "other"))
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
			Applier: rejecter{}, Backoff: fast()})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "a session", func() bool { return slices.Contains(c.Sessions.Connected(), id.AgentID) })
	waitFor(t, "the rejection", func() bool {
		st, err := c.DB.Client().AgentState.Get(c.Sys, id.AgentID)
		return err == nil && controller.ApplyStatus(st, time.Now()) == controller.ApplyRejected
	})

	revoked := other.Certificate.Leaf
	serial := pki.SerialHex(revoked.SerialNumber)
	if err := c.Revoker().RevokeCertificate(c.Sys, serial, "test", controller.Actor{Type: audit.ActorUser, ID: "usr_t"}); err != nil {
		t.Fatal(err)
	}
	stored := func() *agent.DenyList {
		d := agent.NewDenyList(agent.DenyListOptions{StateDir: state, Root: id.Root,
			Signers: func() []*x509.Certificate { return id.Signing }})
		if err := d.Load(); err != nil {
			t.Fatal(err)
		}
		return d
	}
	waitFor(t, "the stored deny-list", func() bool { return stored().Denied(revoked) })

	// A restore from a backup without the revocation: a new epoch, and lists without the entry.
	if err := store.WriteTx(c.Sys, c.DB, func(tx *ent.Tx) error {
		return tx.IssuedCertificate.UpdateOneID(serial).ClearRevokedAt().Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewEpoch(c.Sys, c.DB); err != nil {
		t.Fatal(err)
	}
	third := c.EnrollConnector(t, filepath.Join(dir, "third")).Certificate.Leaf
	if err := c.Revoker().RevokeCertificate(c.Sys, pki.SerialHex(third.SerialNumber), "after the restore",
		controller.Actor{Type: audit.ActorUser, ID: "usr_t"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the list of the new epoch", func() bool { return stored().Denied(third) })
	if !stored().Denied(revoked) {
		t.Fatal("a new epoch removed an unexpired entry")
	}
}
