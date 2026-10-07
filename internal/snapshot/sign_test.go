// SPDX-License-Identifier: Apache-2.0

package snapshot_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

const agent = "spiffe://rpmgr-7f3k2q6m/org/org_1/connector/con_1"

// signers is a test CA with its config-signing and audit-checkpoint keys.
type signers struct {
	root, inter, config, audit pki.KeyPair
}

func newSigners(t *testing.T, td string) signers {
	t.Helper()
	var s signers
	var err error
	if s.root, err = pki.NewRoot(td, t0); err != nil {
		t.Fatal(err)
	}
	if s.inter, err = pki.NewIntermediate(s.root, t0); err != nil {
		t.Fatal(err)
	}
	is, err := pki.NewIssuer(s.root.Cert, s.inter, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	for p, dst := range map[pki.Purpose]*pki.KeyPair{pki.PurposeConfigSigning: &s.config, pki.PurposeAuditCheckpoint: &s.audit} {
		key, err := pki.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := is.IssueSigner(&key.PublicKey, p)
		if err != nil {
			t.Fatal(err)
		}
		*dst = pki.KeyPair{Cert: cert, Key: key}
	}
	return s
}

// certs is what an agent holds after enrollment: the signing certificates and the intermediate.
func (s signers) certs() []*x509.Certificate {
	return []*x509.Certificate{s.config.Cert, s.inter.Cert}
}

func testSnapshot() *agentv1.Snapshot {
	return &agentv1.Snapshot{
		Revision:            &agentv1.Revision{DbEpoch: "0192f0aa-0000-7000-8000-000000000000", Seq: 7},
		Agent:               agent,
		ControllerEndpoints: []string{"https://ctl.example:443"},
		Resources: []*agentv1.Resource{{Id: "rt_1", Kind: &agentv1.Resource_Reference{
			Reference: &agentv1.ResourceReference{Size: 42}}}},
	}
}

func TestSignVerify(t *testing.T) {
	s := newSigners(t, "rpmgr-7f3k2q6m")
	signed, err := snapshot.Sign(s.config, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if signed.GetKeyId() != snapshot.KeyID(s.config.Cert) || len(signed.GetKeyId()) != 64 {
		t.Fatalf("key_id %q", signed.GetKeyId())
	}
	if h := sha256.Sum256(signed.GetPayload()); !bytes.Equal(snapshot.Hash(signed), h[:]) {
		t.Fatal("the hash is not the SHA-256 of the payload")
	}
	got, err := snapshot.VerifySnapshot(signed, s.certs(), s.root.Cert, agent, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, testSnapshot()) {
		t.Fatalf("got %v", got)
	}
	// The certificates may come in any order, as signing.pem holds them.
	if _, err := snapshot.VerifySnapshot(signed, []*x509.Certificate{s.inter.Cert, s.config.Cert}, s.root.Cert, agent, t0); err != nil {
		t.Fatal(err)
	}
}

func TestSign_Deterministic(t *testing.T) {
	s := newSigners(t, "rpmgr-7f3k2q6m")
	a, err := snapshot.Sign(s.config, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	b, err := snapshot.Sign(s.config, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.GetPayload(), b.GetPayload()) || !bytes.Equal(snapshot.Hash(a), snapshot.Hash(b)) {
		t.Fatal("the same snapshot gave different payloads")
	}
}

func TestVerify_Refused(t *testing.T) {
	s := newSigners(t, "rpmgr-7f3k2q6m")
	other := newSigners(t, "rpmgr-7f3k2q6m") // the same trust domain, another CA
	foreign := newSigners(t, "rpmgr-abcdefgh")
	sign := func(kp pki.KeyPair, m proto.Message) *agentv1.Signed {
		t.Helper()
		signed, err := snapshot.Sign(kp, m)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	good := sign(s.config, testSnapshot())
	tampered := proto.Clone(good).(*agentv1.Signed)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	badSig := proto.Clone(good).(*agentv1.Signed)
	badSig.Signature[len(badSig.Signature)-1] ^= 1
	noSig := proto.Clone(good).(*agentv1.Signed)
	noSig.Signature = nil
	// A valid signature over bytes that are not a protobuf message.
	garbage := []byte{0xff, 0xff, 0xff}
	digest := sha256.Sum256(garbage)
	sig, err := ecdsa.SignASN1(rand.Reader, s.config.Key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	notSnapshot := &agentv1.Signed{Payload: garbage, Signature: sig, KeyId: snapshot.KeyID(s.config.Cert)}
	tests := []struct {
		name   string
		signed *agentv1.Signed
		certs  []*x509.Certificate
		root   *x509.Certificate
		agent  string
		at     time.Time
		sigErr bool // ErrSignature expected
	}{
		{name: "tampered payload", signed: tampered, sigErr: true},
		{name: "tampered signature", signed: badSig, sigErr: true},
		{name: "no signature", signed: noSig, sigErr: true},
		{name: "unknown key", signed: sign(other.config, testSnapshot()), sigErr: true},
		{name: "audit-checkpoint key", signed: sign(s.audit, testSnapshot()),
			certs: []*x509.Certificate{s.audit.Cert, s.inter.Cert}},
		{name: "signer of another ca", signed: sign(other.config, testSnapshot()),
			certs: []*x509.Certificate{other.config.Cert, other.inter.Cert}},
		{name: "signer of another trust domain", signed: sign(foreign.config, testSnapshot()),
			certs: []*x509.Certificate{foreign.config.Cert, foreign.inter.Cert}},
		{name: "no intermediate", signed: good, certs: []*x509.Certificate{s.config.Cert}},
		{name: "signer expired", signed: good, at: s.config.Cert.NotAfter.Add(time.Second)},
		{name: "signer not yet valid", signed: good, at: s.config.Cert.NotBefore.Add(-time.Second)},
		{name: "for another agent", signed: good, agent: "spiffe://rpmgr-7f3k2q6m/org/org_1/connector/con_2"},
		{name: "not a snapshot", signed: notSnapshot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, root, ag, at := s.certs(), s.root.Cert, agent, t0
			if tt.certs != nil {
				certs = tt.certs
			}
			if tt.root != nil {
				root = tt.root
			}
			if tt.agent != "" {
				ag = tt.agent
			}
			if !tt.at.IsZero() {
				at = tt.at
			}
			snap, err := snapshot.VerifySnapshot(tt.signed, certs, root, ag, at)
			if err == nil {
				t.Fatalf("accepted: %v", snap)
			}
			t.Log(err)
			if tt.sigErr != errors.Is(err, snapshot.ErrSignature) {
				t.Fatalf("error %v; want ErrSignature: %v", err, tt.sigErr)
			}
		})
	}
}

func TestSign_TooLarge(t *testing.T) {
	s := newSigners(t, "rpmgr-7f3k2q6m")
	snap := testSnapshot()
	for i := range 5 {
		snap.Resources = append(snap.Resources, &agentv1.Resource{Id: strings.Repeat("x", 1<<20) + string(rune('a'+i))})
	}
	if _, err := snapshot.Sign(s.config, snap); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("a snapshot above 4 MiB was signed: %v", err)
	}
}

func TestResourceHash(t *testing.T) {
	r := &agentv1.Resource{Id: "rt_1", Kind: &agentv1.Resource_Reference{Reference: &agentv1.ResourceReference{Size: 1}}}
	h1, err := snapshot.ResourceHash(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Hash = []byte("stale")
	h2, err := snapshot.ResourceHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatal("the hash covers the hash field")
	}
	if !bytes.Equal(r.Hash, []byte("stale")) {
		t.Fatal("ResourceHash changed its argument")
	}
	r.GetReference().Size = 2
	h3, _ := snapshot.ResourceHash(r)
	if bytes.Equal(h1, h3) {
		t.Fatal("a content change kept the hash")
	}
	r.GetReference().Size, r.Id = 1, "rt_2"
	h4, _ := snapshot.ResourceHash(r)
	if bytes.Equal(h1, h4) {
		t.Fatal("another ID kept the hash")
	}
}
