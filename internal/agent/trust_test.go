// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapsig"
)

// newRoot makes a root of trust domain td, or fails the test.
func newRoot(t *testing.T, td string, at time.Time) pki.KeyPair {
	t.Helper()
	r, err := pki.NewRoot(td, at)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// crossCert makes what `rpmgr ca new-root` makes of a new root r: a certificate for pub with r's
// Subject and SubjectKeyId, signed by parent. edit changes the template first.
func crossCert(t *testing.T, parent, r pki.KeyPair, pub crypto.PublicKey, edit func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), RawSubject: r.Cert.RawSubject, SubjectKeyId: r.Cert.SubjectKeyId,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: r.Cert.URIs}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, pub, parent.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func certs(kps ...pki.KeyPair) []*x509.Certificate {
	var out []*x509.Certificate
	for _, k := range kps {
		out = append(out, k.Cert)
	}
	return out
}

func ders(cs ...*x509.Certificate) [][]byte {
	var out [][]byte
	for _, c := range cs {
		out = append(out, c.Raw)
	}
	return out
}

func TestAcceptRoots(t *testing.T) {
	const td = "rpmgr-7f3k2q6m"
	now := time.Now()
	r1, r2 := newRoot(t, td, now), newRoot(t, td, now)
	x := crossCert(t, r1, r2, &r2.Key.PublicKey, nil)
	other := newRoot(t, td, now) // an attacker's root of the same trust domain
	foreignTD, err := pki.NewTrustDomain()
	if err != nil {
		t.Fatal(err)
	}
	f2 := newRoot(t, foreignTD, now)
	trusted := certs(r1)

	cases := []struct {
		name    string
		offered []*x509.Certificate
		want    []*x509.Certificate // after the trusted root
	}{
		{"new root with its cross-certificate", []*x509.Certificate{r2.Cert, x}, certs(r2)},
		{"cross-certificate first", []*x509.Certificate{x, r2.Cert}, certs(r2)},
		{"root again", []*x509.Certificate{r1.Cert, r2.Cert, x, r2.Cert}, certs(r2)},
		{"root without a cross-certificate", []*x509.Certificate{r2.Cert}, nil},
		{"cross-certificate alone is no anchor", []*x509.Certificate{x}, nil},
		{"unrelated root", []*x509.Certificate{other.Cert, x}, nil},
		{"cross-certificate for another key", []*x509.Certificate{r2.Cert, crossCert(t, r1, r2, &other.Key.PublicKey, nil)}, nil},
		{"cross-certificate of an untrusted key", []*x509.Certificate{r2.Cert, crossCert(t, other, r2, &r2.Key.PublicKey, nil)}, nil},
		{"other trust domain", []*x509.Certificate{f2.Cert, crossCert(t, r1, f2, &f2.Key.PublicKey, nil)}, nil},
		{"cross-certificate without a SAN", []*x509.Certificate{r2.Cert,
			crossCert(t, r1, r2, &r2.Key.PublicKey, func(c *x509.Certificate) { c.URIs = nil })}, certs(r2)},
		{"expired cross-certificate", []*x509.Certificate{r2.Cert, crossCert(t, r1, r2, &r2.Key.PublicKey, func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
		})}, nil},
		{"cross-certificate not yet valid", []*x509.Certificate{r2.Cert, crossCert(t, r1, r2, &r2.Key.PublicKey, func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = now.Add(time.Hour), now.Add(48*time.Hour)
		})}, nil},
		{"cross-certificate that is no CA", []*x509.Certificate{r2.Cert,
			crossCert(t, r1, r2, &r2.Key.PublicKey, func(c *x509.Certificate) { c.IsCA, c.MaxPathLen = false, 0 })}, nil},
		{"cross-certificate with path length 0", []*x509.Certificate{r2.Cert, crossCert(t, r1, r2, &r2.Key.PublicKey, func(c *x509.Certificate) {
			c.MaxPathLen, c.MaxPathLenZero = 0, true
		})}, nil},
		{"cross-certificate with another SubjectKeyId", []*x509.Certificate{r2.Cert,
			crossCert(t, r1, r2, &r2.Key.PublicKey, func(c *x509.Certificate) { c.SubjectKeyId = []byte("another") })}, nil},
		{"cross-certificate with another Subject", []*x509.Certificate{r2.Cert, crossCert(t, r1, r2, &r2.Key.PublicKey, func(c *x509.Certificate) {
			c.RawSubject, c.Subject = nil, pkix.Name{CommonName: "something else"}
		})}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := agent.AcceptRoots(trusted, td, c.offered, now)
			want := append(certs(r1), c.want...)
			if len(got) != len(want) {
				t.Fatalf("kept %d roots, want %d", len(got), len(want))
			}
			for i := range want {
				if !got[i].Equal(want[i]) {
					t.Errorf("root %d is not the expected one", i)
				}
			}
			for _, g := range got {
				if g.Equal(x) {
					t.Error("the cross-certificate became a trust anchor")
				}
			}
		})
	}

	t.Run("expired root", func(t *testing.T) {
		old := newRoot(t, td, now.Add(-11*365*24*time.Hour))
		got := agent.AcceptRoots(trusted, td, []*x509.Certificate{old.Cert, crossCert(t, r1, old, &old.Key.PublicKey, nil)}, now)
		if len(got) != 1 {
			t.Errorf("kept %d roots, want only the trusted one", len(got))
		}
	})
	t.Run("a root a new root vouches for, in the same offer", func(t *testing.T) {
		r3 := newRoot(t, td, now)
		x3 := crossCert(t, r2, r3, &r3.Key.PublicKey, nil)
		got := agent.AcceptRoots(trusted, td, []*x509.Certificate{x3, r3.Cert, x, r2.Cert}, now)
		if len(got) != 3 {
			t.Errorf("kept %d roots, want 3", len(got))
		}
	})
	t.Run("never more than the limit", func(t *testing.T) {
		have := certs(r1)
		var offered []*x509.Certificate
		for range pki.MaxTrustRoots {
			n := newRoot(t, td, now)
			offered = append(offered, n.Cert, crossCert(t, r1, n, &n.Key.PublicKey, nil))
		}
		got := agent.AcceptRoots(have, td, offered, now)
		if len(got) != pki.MaxTrustRoots {
			t.Errorf("kept %d roots, want %d", len(got), pki.MaxTrustRoots)
		}
	})
	t.Run("the input is not changed", func(t *testing.T) {
		have := certs(r1)
		_ = agent.AcceptRoots(have, td, []*x509.Certificate{r2.Cert, x}, now)
		if len(have) != 1 {
			t.Error("the trusted slice grew")
		}
	})
}

// logBuf is a log sink that tests can read while the agent writes.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// control lays down the env's identity with roots as roots.pem and loads a control plane from it.
func (e *rtEnv) control(t *testing.T, f *fakeApplier, roots []*x509.Certificate) (*agent.Control, *logBuf) {
	t.Helper()
	key, ok := e.id.Certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("the test identity has no ECDSA key")
	}
	chain := []*x509.Certificate{e.id.Certificate.Leaf, e.inter.Cert}
	ident := agent.Identity{AgentID: e.ident.ID, Kind: string(e.ident.Kind), TrustDomain: e.ident.TrustDomain, EnrolledAt: time.Now()}
	if err := agent.WriteIdentity(e.id.Dir, key, chain, roots, e.id.Signing, ident); err != nil {
		t.Fatal(err)
	}
	logs := &logBuf{}
	c, err := agent.NewControl(agent.ControlOptions{IdentityDir: e.id.Dir, StateDir: e.stateDir, Applier: f,
		Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c, logs
}

func rootsFile(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, agent.RootsFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitSeq(t *testing.T, f *fakeApplier, seq uint64) {
	t.Helper()
	for range 500 {
		if slices.Contains(f.appliedSeqs(), seq) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("snapshot %d was not applied", seq)
}

func (e *rtEnv) withRoots(t *testing.T, kp pki.KeyPair, seq uint64, roots [][]byte) *agentv1.Signed {
	t.Helper()
	s, err := snapsig.Sign(kp, &agentv1.Snapshot{Revision: &agentv1.Revision{DbEpoch: epoch1, Seq: seq}, Agent: e.id.SPIFFE(),
		ControllerEndpoints: []string{"https://ctl.example"}, SigningKeyId: snapsig.KeyID(kp.Cert), TrustRoots: roots})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAgent_SnapshotRootNeedsCrossSign: a root offered in a snapshot or a Welcome is kept only
// with a cross-certificate a trusted root signed for the same public key; the others are ignored
// and never reject the snapshot. The agent trusts the self-signed root, never the
// cross-certificate, and writes roots.pem with it. (Enroll's response follows the same rule,
// TestEnroll_BundleWithExtraRootRejected.)
func TestAgent_SnapshotRootNeedsCrossSign(t *testing.T) {
	e := newRTEnv(t)
	f := &fakeApplier{}
	c, logs := e.control(t, f, []*x509.Certificate{e.root.Cert})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	rt := agent.RuntimeOf(c)
	go func() { rt.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	rt.Welcome(&agentv1.Welcome{DbEpoch: epoch1})
	before := rootsFile(t, e.id.Dir)

	td := e.ident.TrustDomain
	r2 := newRoot(t, td, time.Now())
	x := crossCert(t, e.root, r2, &r2.Key.PublicKey, nil)
	attacker := newRoot(t, td, time.Now())
	foreign, err := pki.NewTrustDomain()
	if err != nil {
		t.Fatal(err)
	}
	f2 := newRoot(t, foreign, time.Now())

	// Offers that gain nothing: the snapshot is applied all the same, roots.pem stays.
	for i, bad := range [][][]byte{
		ders(r2.Cert), // no cross-certificate
		ders(x),       // the cross-certificate alone
		ders(attacker.Cert, crossCert(t, attacker, attacker, &attacker.Key.PublicKey, nil)), // self-vouched
		ders(r2.Cert, crossCert(t, e.root, r2, &attacker.Key.PublicKey, nil)),               // another key
		ders(f2.Cert, crossCert(t, e.root, f2, &f2.Key.PublicKey, nil)),                     // another trust domain
	} {
		seq := uint64(i + 1)
		rt.Message(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: e.withRoots(t, e.config, seq, bad)}})
		waitSeq(t, f, seq)
		if got := rootsFile(t, e.id.Dir); !bytes.Equal(got, before) {
			t.Fatalf("offer %d changed roots.pem", i)
		}
		if h := agent.HelloOf(c); !bytes.Equal(h.GetRootsDigest(), pki.RootsDigest(certs(e.root))) {
			t.Fatalf("offer %d changed the digest", i)
		}
	}
	if !strings.Contains(logs.String(), "ignoring") {
		t.Errorf("the ignored roots were not logged:\n%s", logs.String())
	}

	// The right offer: R2 with X.
	rt.Message(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: e.withRoots(t, e.config, 10, ders(r2.Cert, x))}})
	waitSeq(t, f, 10)
	got, err := agent.Load(e.id.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RootCerts) != 2 || !got.RootCerts[0].Equal(e.root.Cert) || !got.RootCerts[1].Equal(r2.Cert) {
		t.Fatalf("roots.pem holds %d certificates, want the pinned root and R2 only (not the cross-certificate)", len(got.RootCerts))
	}
	if got.Root == nil || !got.Root.Equal(e.root.Cert) {
		t.Error("the pinned root is no longer the first")
	}
	if h := agent.HelloOf(c); !bytes.Equal(h.GetRootsDigest(), pki.RootsDigest(certs(e.root, r2))) {
		t.Error("Hello still carries the old digest after roots.pem was rewritten")
	}
	if _, err := r2.Cert.Verify(x509.VerifyOptions{Roots: c.Identity().Roots}); err != nil {
		t.Errorf("the control session does not trust R2: %v", err)
	}
	if _, err := x.Verify(x509.VerifyOptions{Roots: c.Identity().Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Logf("the cross-certificate verifies through R1 only: %v", err)
	}

	// A Welcome offering R3 without a cross-certificate, and again R2 with it, change nothing.
	r3 := newRoot(t, td, time.Now())
	if agent.OfferRoots(c, "a Welcome", ders(r3.Cert, r2.Cert, x)) {
		t.Error("a root without a cross-certificate was kept")
	}
	if agent.OfferRoots(c, "a Welcome", ders(r2.Cert, x)) {
		t.Error("a root already held changed the set")
	}
	// R3 vouched for by R2, which the agent now trusts, comes in at once.
	if !agent.OfferRoots(c, "a Welcome", ders(r3.Cert, crossCert(t, r2, r3, &r3.Key.PublicKey, nil))) {
		t.Error("a root cross-signed by R2 was refused")
	}
}

func TestControl_AnnouncesTrustRoots(t *testing.T) {
	e := newRTEnv(t)
	c, _ := e.control(t, &fakeApplier{}, []*x509.Certificate{e.root.Cert})
	if !slices.Contains(agent.CapsOf(c), agentproto.CapTrustRoots) {
		t.Errorf("capabilities %v lack %s", agent.CapsOf(c), agentproto.CapTrustRoots)
	}
}

func TestControl_RootsDigestReloaded(t *testing.T) {
	e := newRTEnv(t)
	c, _ := e.control(t, &fakeApplier{}, []*x509.Certificate{e.root.Cert})
	first := agent.HelloOf(c).GetRootsDigest()
	if !bytes.Equal(first, pki.RootsDigest(certs(e.root))) {
		t.Fatal("the first digest is not the pinned root's")
	}
	r2 := newRoot(t, e.ident.TrustDomain, time.Now())
	if !agent.OfferRoots(c, "a Welcome", ders(r2.Cert, crossCert(t, e.root, r2, &r2.Key.PublicKey, nil))) {
		t.Fatal("R2 was refused")
	}
	second := agent.HelloOf(c).GetRootsDigest()
	if bytes.Equal(first, second) || !bytes.Equal(second, pki.RootsDigest(certs(e.root, r2))) {
		t.Error("the digest of the next Hello is not that of the new roots")
	}
	// A restart reads the same set from roots.pem.
	l, err := agent.Load(e.id.Dir)
	if err != nil || !bytes.Equal(pki.RootsDigest(l.RootCerts), second) {
		t.Errorf("roots.pem does not give the reported digest: %v", err)
	}
}

func TestControl_RootsOverTheLimitsIgnored(t *testing.T) {
	e := newRTEnv(t)
	c, logs := e.control(t, &fakeApplier{}, []*x509.Certificate{e.root.Cert})
	before := rootsFile(t, e.id.Dir)
	r2 := newRoot(t, e.ident.TrustDomain, time.Now())
	good := ders(r2.Cert, crossCert(t, e.root, r2, &r2.Key.PublicKey, nil))

	tooMany := slices.Clone(good)
	for len(tooMany) <= pki.MaxTrustCerts {
		tooMany = append(tooMany, []byte("not a certificate")) // would fail to parse: the count is checked first
	}
	tooBig := append(slices.Clone(good), bytes.Repeat([]byte{1}, pki.MaxTrustCertBytes+1))
	for name, offer := range map[string][][]byte{"too many certificates": tooMany, "a certificate too big": tooBig,
		"garbage": append(slices.Clone(good), []byte("not a certificate"))} {
		if agent.OfferRoots(c, "a Welcome", offer) {
			t.Errorf("%s: the roots were kept", name)
		}
	}
	if !bytes.Equal(rootsFile(t, e.id.Dir), before) {
		t.Error("roots.pem changed")
	}
	if !strings.Contains(logs.String(), "at most") {
		t.Errorf("the limit was not named in the log:\n%s", logs.String())
	}
	// Exactly at the limits is fine.
	if !agent.OfferRoots(c, "a Welcome", good) {
		t.Error("a valid offer within the limits was refused")
	}
}
