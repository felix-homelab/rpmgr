// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/telemetry/telemetrytest"
)

// runAgent runs an agent's control plane until the test ends.
func runAgent(t *testing.T, id agent.Loaded, now func() time.Time) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.RunControl(ctx, agent.ControlOptions{IdentityDir: id.Dir, StateDir: t.TempDir(), Version: "0.1.0",
			Applier: &recorder{}, Backoff: fast(), Now: now, Logger: telemetrytest.Logger(t)})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// waitNewCertificate waits until the identity directory holds a certificate with a serial other
// than old, and returns it.
func waitNewCertificate(t *testing.T, dir string, old string) agent.Loaded {
	t.Helper()
	var l agent.Loaded
	waitFor(t, "a new certificate on disk", func() bool {
		var err error
		l, err = agent.Load(dir)
		return err == nil && pki.SerialHex(l.Certificate.Leaf.SerialNumber) != old
	})
	return l
}

// TestRenewal_EndToEnd: in its renewal window the agent renews over the control session with a new
// key, stores the new certificate, reconnects with it, and the controller then supersedes the old.
func TestRenewal_EndToEnd(t *testing.T) {
	c := itest.StartController(t, itest.Options{})
	id := c.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	old := id.Certificate.Leaf
	// The agent's clock is in the renewal window; the controller's is not.
	ahead := time.Until(agent.RenewAt(old, 1)) + time.Minute
	runAgent(t, id, func() time.Time { return time.Now().Add(ahead) })

	renewed := waitNewCertificate(t, id.Dir, pki.SerialHex(old.SerialNumber))
	leaf := renewed.Certificate.Leaf
	if leaf.URIs[0].String() != old.URIs[0].String() || leaf.PublicKey.(*ecdsa.PublicKey).Equal(old.PublicKey) {
		t.Fatal("the renewed certificate is for another identity or the same key")
	}
	waitFor(t, "the old certificate superseded", func() bool {
		return errors.Is(pki.CheckRenewable(c.Sys, c.DB.Client(), old), pki.ErrSuperseded)
	})
	waitFor(t, "a session with the new certificate", func() bool { return slices.Contains(c.Sessions.Connected(), id.AgentID) })
}

// TestRenewal_ExpiredCertificateReauth: an agent whose certificate expired within the grace period
// gets a new one through Reauth and then opens its control session.
func TestRenewal_ExpiredCertificateReauth(t *testing.T) {
	c := itest.StartController(t, itest.Options{})
	id := c.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	expired := c.IssueAt(t, id, time.Now().Add(-8*24*time.Hour))
	id, err := agent.Load(id.Dir)
	if err != nil {
		t.Fatal(err)
	}
	runAgent(t, id, nil)
	renewed := waitNewCertificate(t, id.Dir, pki.SerialHex(expired.SerialNumber))
	if !renewed.Certificate.Leaf.NotAfter.After(time.Now()) {
		t.Fatal("the re-issued certificate is not valid")
	}
	waitFor(t, "a session after Reauth", func() bool { return slices.Contains(c.Sessions.Connected(), id.AgentID) })
}

// TestRenewal_ExpiredBeyondGrace: an agent whose certificate expired longer ago than the grace
// period gets no new one and no session.
func TestRenewal_ExpiredBeyondGrace(t *testing.T) {
	c := itest.StartController(t, itest.Options{})
	id := c.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	expired := c.IssueAt(t, id, time.Now().Add(-40*24*time.Hour))
	id, err := agent.Load(id.Dir)
	if err != nil {
		t.Fatal(err)
	}
	runAgent(t, id, nil)
	time.Sleep(time.Second)
	l, err := agent.Load(id.Dir)
	if err != nil || l.Certificate.Leaf.SerialNumber.Cmp(expired.SerialNumber) != 0 {
		t.Fatalf("the certificate changed: %v", err)
	}
	if slices.Contains(c.Sessions.Connected(), id.AgentID) {
		t.Fatal("a session with a certificate expired beyond the grace period")
	}
}
