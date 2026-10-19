// SPDX-License-Identifier: Apache-2.0

package snapshot_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

// FuzzVerifySnapshot: a signed snapshot as it arrives on the wire verifies only with the payload
// the config-signing key signed. Whatever the fuzzer changes in the message (payload, signature,
// key ID, unknown fields), an accepted snapshot is the one that was signed, and one signed with
// the audit-checkpoint key never verifies (docs/04-security.md, "CA hierarchy").
func FuzzVerifySnapshot(f *testing.F) {
	s := newSigners(f, "rpmgr-7f3k2q6m")
	good, err := snapshot.Sign(s.config, testSnapshot())
	if err != nil {
		f.Fatal(err)
	}
	audit, err := snapshot.Sign(s.audit, testSnapshot())
	if err != nil {
		f.Fatal(err)
	}
	for _, m := range []*agentv1.Signed{good, audit, {Payload: good.GetPayload(), KeyId: good.GetKeyId()}} {
		wire, err := proto.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		var m agentv1.Signed
		if proto.Unmarshal(wire, &m) != nil {
			return
		}
		snap, err := snapshot.VerifySnapshot(&m, s.certs(), s.root.Cert, agent, t0)
		if err != nil {
			return
		}
		if !bytes.Equal(m.GetPayload(), good.GetPayload()) || !proto.Equal(snap, testSnapshot()) {
			t.Fatalf("accepted a changed snapshot: %v", snap)
		}
	})
}

// FuzzSnapshotPayload: any payload the config-signing key signs either is refused with an error,
// or decodes to a snapshot compiled for this agent; the same payload signed with the
// audit-checkpoint key is always refused.
func FuzzSnapshotPayload(f *testing.F) {
	s := newSigners(f, "rpmgr-7f3k2q6m")
	good, err := snapshot.Sign(s.config, testSnapshot())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good.GetPayload())
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Add([]byte{})
	sign := func(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
		digest := sha256.Sum256(payload)
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		m := &agentv1.Signed{Payload: payload, Signature: sign(t, s.config.Key, payload), KeyId: snapshot.KeyID(s.config.Cert)}
		if snap, err := snapshot.VerifySnapshot(m, s.certs(), s.root.Cert, agent, t0); err == nil && snap.GetAgent() != agent {
			t.Fatalf("accepted a snapshot for %q", snap.GetAgent())
		}
		bad := &agentv1.Signed{Payload: payload, Signature: sign(t, s.audit.Key, payload), KeyId: snapshot.KeyID(s.audit.Cert)}
		if _, err := snapshot.VerifySnapshot(bad, []*x509.Certificate{s.audit.Cert, s.config.Cert, s.inter.Cert}, s.root.Cert, agent, t0); err == nil {
			t.Fatal("a payload signed with the audit-checkpoint key verified")
		}
	})
}
