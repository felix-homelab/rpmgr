// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package agent_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// TestAgent_RootsWriteCrashLeavesOldOrNew: a crash while roots.pem is written leaves the old file or
// the new one, never a mixture, and the agent starts from either (docs/04, "Root rotation").
func TestAgent_RootsWriteCrashLeavesOldOrNew(t *testing.T) {
	for _, point := range []string{"before-rename", "after-rename"} {
		t.Run(point, func(t *testing.T) {
			e := newRTEnv(t)
			c, _ := e.control(t, &fakeApplier{}, []*x509.Certificate{e.root.Cert})
			old := rootsFile(t, e.id.Dir)
			r2 := newRoot(t, e.ident.TrustDomain, time.Now())
			offer := ders(r2.Cert, crossCert(t, e.root, r2, &r2.Key.PublicKey, nil))

			crash := errors.New("crash")
			agent.SetRootsFault(func(p string) error {
				if p == point {
					return crash
				}
				return nil
			})
			t.Cleanup(func() { agent.SetRootsFault(nil) })
			kept := agent.OfferRoots(c, "a Welcome", offer)
			agent.SetRootsFault(nil)

			l, err := agent.Load(e.id.Dir)
			if err != nil {
				t.Fatalf("roots.pem does not load after the crash: %v", err)
			}
			switch point {
			case "before-rename":
				if kept || !bytes.Equal(rootsFile(t, e.id.Dir), old) {
					t.Error("a crash before the rename changed roots.pem or the roots in use")
				}
				if !bytes.Equal(pki.RootsDigest(l.RootCerts), pki.RootsDigest(certs(e.root))) {
					t.Error("the restarted agent does not hold the old roots")
				}
			case "after-rename":
				if len(l.RootCerts) != 2 || !l.RootCerts[1].Equal(r2.Cert) {
					t.Error("the file is neither the old one nor the new one")
				}
			}
		})
	}
}
