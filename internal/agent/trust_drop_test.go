// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// rotationEnv is an agent that knows R1 and has learned R2, with a runtime that applies snapshots.
type rotationEnv struct {
	*rtEnv
	c      *agent.Control
	f      *fakeApplier
	logs   *logBuf
	rt     *agent.Runtime
	r2     pki.KeyPair
	x      *x509.Certificate
	s2, i2 []byte // R2's signing certificate and intermediate, as DER
	signer pki.KeyPair
}

func newRotationEnv(t *testing.T, learnR2 bool) *rotationEnv {
	t.Helper()
	e := &rotationEnv{rtEnv: newRTEnv(t), f: &fakeApplier{}}
	e.c, e.logs = e.control(t, e.f, []*x509.Certificate{e.root.Cert})
	e.r2 = newRoot(t, e.ident.TrustDomain, time.Now())
	e.x = crossCert(t, e.root, e.r2, &e.r2.Key.PublicKey, nil)
	s2, i2 := signerUnder(t, e.r2)
	e.signer, e.s2, e.i2 = s2, s2.Cert.Raw, i2.Raw
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e.rt = agent.RuntimeOf(e.c)
	go func() { e.rt.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	// The Welcome delivers the signing certificates under both roots, as the controller does in the overlap.
	e.rt.Welcome(&agentv1.Welcome{DbEpoch: epoch1, SigningCertificates: [][]byte{e.config.Cert.Raw, e.inter.Cert.Raw, e.s2, e.i2}})
	if learnR2 && !agent.OfferRoots(e.c, "a Welcome", ders(e.r2.Cert, e.x)) {
		t.Fatal("R2 was refused")
	}
	return e
}

func (e *rotationEnv) send(t *testing.T, kp pki.KeyPair, seq uint64, roots [][]byte) {
	t.Helper()
	e.rt.Message(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: e.withRoots(t, kp, seq, roots)}})
	waitSeq(t, e.f, seq)
}

// rejected sends a snapshot that the runtime must not apply and waits until it was dealt with.
func (e *rotationEnv) ignored(t *testing.T, kp pki.KeyPair, seq uint64, roots [][]byte) {
	t.Helper()
	e.rt.Message(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: e.withRoots(t, kp, seq, roots)}})
	time.Sleep(200 * time.Millisecond)
}

func (e *rotationEnv) held(t *testing.T) []*x509.Certificate {
	t.Helper()
	l, err := agent.Load(e.id.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return l.RootCerts
}

func sameRoots(got []*x509.Certificate, want ...pki.KeyPair) bool {
	if len(got) != len(want) {
		return false
	}
	for i, w := range want {
		if !got[i].Equal(w.Cert) {
			return false
		}
	}
	return true
}

// TestAgent_DropsRootOnNewerBundle: a root leaves roots.pem when a newer snapshot, which verifies with
// the root that is kept, no longer lists it; the kept root becomes the pinned one, the digest and the
// pool follow, the control session ends once to report it, and a restart keeps the result.
func TestAgent_DropsRootOnNewerBundle(t *testing.T) {
	e := newRotationEnv(t, false)
	ended := make(chan struct{}, 4)
	agent.SetSessionEnd(e.c, func() { ended <- struct{}{} })
	// The overlap: {R1, R2, X}, signed under R1.
	e.send(t, e.config, 1, ders(e.root.Cert, e.r2.Cert, e.x))
	if !sameRoots(e.held(t), e.root, e.r2) {
		t.Fatal("the agent did not learn R2 from the overlap's bundle")
	}
	<-ended
	// The drop: {R2}, signed under R2.
	e.send(t, e.signer, 2, ders(e.r2.Cert))
	if got := e.held(t); !sameRoots(got, e.r2) {
		t.Fatalf("after the drop roots.pem holds %d certificates, want R2 alone", len(got))
	}
	<-ended
	if l := e.c.Identity(); !l.Root.Equal(e.r2.Cert) || len(l.RootCerts) != 1 {
		t.Error("R2 is not the pinned root after the drop")
	}
	if h := agent.HelloOf(e.c); !bytes.Equal(h.GetRootsDigest(), pki.RootsDigest(certs(e.r2))) {
		t.Error("Hello still reports the digest of the old roots")
	}
	if _, err := e.root.Cert.Verify(x509.VerifyOptions{Roots: e.c.Roots()}); err == nil {
		t.Error("the pool still trusts the dropped root")
	}
	if _, err := e.r2.Cert.Verify(x509.VerifyOptions{Roots: e.c.Roots()}); err != nil {
		t.Errorf("the pool does not trust R2: %v", err)
	}
	// After a restart: from roots.pem, which says the same.
	c2, _ := e.control(t, &fakeApplier{}, agent.RootsOf(e.c))
	if !sameRoots(agent.RootsOf(c2), e.r2) {
		t.Error("a restarted agent trusts another set")
	}
	if !strings.Contains(e.logs.String(), "the trusted roots changed") {
		t.Errorf("the drop was not logged:\n%s", e.logs.String())
	}
}

// TestAgent_ReplayedBundleNeitherDropsNorAdds: an older snapshot, replayed, does not drop a newer root
// and does not add a dropped one; neither does a snapshot while none runs yet.
func TestAgent_ReplayedBundleNeitherDropsNorAdds(t *testing.T) {
	e := newRotationEnv(t, true)
	// No snapshot runs yet: a snapshot that lists R1 alone adds and drops nothing, although R1 signed it.
	e.send(t, e.config, 3, ders(e.root.Cert))
	if !sameRoots(e.held(t), e.root, e.r2) {
		t.Fatal("the first snapshot dropped a root; nothing orders it against an older one")
	}
	// The overlap's bundle at revision 5.
	e.send(t, e.config, 5, ders(e.root.Cert, e.r2.Cert, e.x))
	// Replay: the older snapshot of revision 4 that lists R1 alone, validly signed under R1.
	e.ignored(t, e.config, 4, ders(e.root.Cert))
	if !sameRoots(e.held(t), e.root, e.r2) {
		t.Fatal("a replayed older snapshot dropped the newer root R2")
	}
	// The drop at revision 6, then the overlap's snapshot replayed (revision 5, signed under R2 as the
	// controller does from then on) and an older Welcome: R1 does not come back.
	e.send(t, e.signer, 6, ders(e.r2.Cert))
	if !sameRoots(e.held(t), e.r2) {
		t.Fatal("the drop did not happen")
	}
	e.ignored(t, e.signer, 5, ders(e.root.Cert, e.r2.Cert, e.x))
	if agent.OfferRoots(e.c, "a replayed Welcome", ders(e.root.Cert, e.r2.Cert, e.x)) || !sameRoots(e.held(t), e.r2) {
		t.Fatal("a replayed Welcome added the dropped root again")
	}
	// Not even a snapshot that is newer can do it: R2 signed no cross-certificate for R1.
	e.send(t, e.signer, 7, ders(e.root.Cert, e.r2.Cert, e.x))
	if !sameRoots(e.held(t), e.r2) {
		t.Fatal("a newer snapshot added the dropped root again without a cross-certificate")
	}
}

// TestAgent_DropNeedsAKeptRoot: a root is not dropped when the snapshot does not verify with the roots
// that are kept alone, nor when it lists none of the roots held, nor on a Welcome.
func TestAgent_DropNeedsAKeptRoot(t *testing.T) {
	e := newRotationEnv(t, true)
	e.send(t, e.config, 1, ders(e.root.Cert, e.r2.Cert, e.x))
	// {R2} signed under R1 only: R1 would vouch for its own removal.
	e.send(t, e.config, 2, ders(e.r2.Cert))
	if !sameRoots(e.held(t), e.root, e.r2) {
		t.Fatal("a root was dropped on a snapshot that only the dropped root vouches for")
	}
	if !strings.Contains(e.logs.String(), "not dropping a root") {
		t.Errorf("the refused drop was not logged:\n%s", e.logs.String())
	}
	// A bundle with an unrelated root only: nothing is kept, so nothing is dropped.
	other := newRoot(t, e.ident.TrustDomain, time.Now())
	e.send(t, e.config, 3, ders(other.Cert))
	if !sameRoots(e.held(t), e.root, e.r2) {
		t.Fatal("a bundle that lists no held root changed the set")
	}
	// A Welcome never drops a root: it carries no revision.
	if agent.OfferRoots(e.c, "a Welcome", ders(e.r2.Cert)) || !sameRoots(e.held(t), e.root, e.r2) {
		t.Fatal("a Welcome dropped a root")
	}
}
