// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// TestRotation_NextSigningKey: an agent gets the next config-signing key in Welcome; once that key
// replaces the old one, the agent receives its snapshot signed by the new key, keeps that copy,
// and starts from it with the controller down.
func TestRotation_NextSigningKey(t *testing.T) {
	// A CA old enough that its signing keys are due for rotation.
	c := itest.StartController(t, itest.Options{Sources: []snapshot.Source{orgResources}, CAAge: 310 * 24 * time.Hour})
	dir := t.TempDir()
	id := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	start := func(rec *recorder) func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: state, Version: "0.1.0",
				Applier: rec, Backoff: fast()})
			close(done)
		}()
		return func() { cancel(); <-done }
	}
	rotate := func() {
		t.Helper()
		if err := store.WriteTx(c.Sys, c.DB, func(tx *ent.Tx) error {
			_, err := pki.Rotate(c.Sys, tx, c.Sealer(), time.Now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.CA.Reload(c.Sys, c.DB, c.Sealer(), time.Now); err != nil {
			t.Fatal(err)
		}
	}
	storedKey := func() string {
		b, err := os.ReadFile(filepath.Join(state, agent.LastKnownGoodFile))
		if err != nil {
			return ""
		}
		s := &agentv1.Signed{}
		if proto.Unmarshal(b, s) != nil {
			return ""
		}
		return s.GetKeyId()
	}
	old := c.CA.ConfigSigner().Cert

	rec := &recorder{}
	stop := start(rec)
	waitFor(t, "the first snapshot", func() bool { return len(rec.applied()) == 1 })
	stop()

	// The next key exists; the agent's next session delivers its certificate.
	rotate()
	if !c.CA.ConfigSigner().Cert.Equal(old) {
		t.Fatal("the next key replaced the old one at once")
	}
	rec = &recorder{}
	stop = start(rec)
	defer func() { stop() }()
	waitFor(t, "a session", func() bool { return len(rec.applied()) >= 1 })

	// The next key replaces the old one: the agent gets and keeps a copy signed by it.
	rotate()
	next := snapshot.KeyID(c.CA.ConfigSigner().Cert)
	if next == snapshot.KeyID(old) {
		t.Fatal("the key did not change")
	}
	waitFor(t, "a copy signed by the new key", func() bool { return storedKey() == next })
	stop()

	c.Stop()
	rec = &recorder{}
	stop = start(rec)
	waitFor(t, "the last-known-good copy without a controller", func() bool { return len(rec.applied()) == 1 })
}
