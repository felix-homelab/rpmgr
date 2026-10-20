// SPDX-License-Identifier: Apache-2.0

// Package snapsig signs, hashes and verifies what the controller signs for agents: snapshots and
// deny-lists (docs/03-connections.md, "Configuration reconciliation"). Agents use it to verify;
// it links nothing of the controller, so the connector-only build can (docs/02-architecture.md,
// "Roles").
package snapsig

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// marshal is the one deterministic encoding of snapshot content.
var marshal = proto.MarshalOptions{Deterministic: true}

// ResourceHash is the SHA-256 of a resource's deterministic encoding without its hash field, so
// an unchanged resource keeps its hash and the agent keeps its running instance.
func ResourceHash(r *agentv1.Resource) ([]byte, error) {
	c := proto.Clone(r).(*agentv1.Resource)
	c.Hash = nil
	b, err := marshal.Marshal(c)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// Hash is the SHA-256 of a signed message's payload: a snapshot's hash.
func Hash(s *agentv1.Signed) []byte {
	h := sha256.Sum256(s.GetPayload())
	return h[:]
}

// KeyID names a signing key: the hexadecimal SHA-256 of its certificate's SubjectPublicKeyInfo.
func KeyID(cert *x509.Certificate) string { return pki.KeyID(cert) }

// Sign encodes m deterministically and signs it with the config-signing key.
func Sign(signer pki.KeyPair, m proto.Message) (*agentv1.Signed, error) {
	payload, err := marshal.Marshal(m)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, signer.Key, digest[:])
	if err != nil {
		return nil, err
	}
	s := &agentv1.Signed{Payload: payload, Signature: sig, KeyId: KeyID(signer.Cert)}
	if err := agentproto.CheckSize(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: s}}); err != nil {
		return nil, err
	}
	return s, nil
}

// ErrSignature is returned for a signed message that does not verify.
var ErrSignature = errors.New("snapshot: the signature does not verify")

// Verify checks a signed message as an agent does and returns its payload. The key it names must
// be among certs, the config-signing certificates and their intermediates as enrollment delivered
// them, and its certificate must chain to root as a config-signing key at time at
// (pki.VerifySigner); the signature must verify over the payload.
func Verify(s *agentv1.Signed, certs []*x509.Certificate, root *x509.Certificate, at time.Time) ([]byte, error) {
	i := slices.IndexFunc(certs, func(c *x509.Certificate) bool { return KeyID(c) == s.GetKeyId() })
	if i < 0 {
		return nil, fmt.Errorf("%w: unknown signing key %q", ErrSignature, s.GetKeyId())
	}
	cert := certs[i]
	others := slices.Delete(slices.Clone(certs), i, i+1)
	if err := pki.VerifySigner(cert, others, root, pki.PurposeConfigSigning, at); err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	digest := sha256.Sum256(s.GetPayload())
	if !ok || !ecdsa.VerifyASN1(pub, digest[:], s.GetSignature()) {
		return nil, ErrSignature
	}
	return s.GetPayload(), nil
}

// VerifySnapshot verifies s and decodes the snapshot, which must be for agent.
func VerifySnapshot(s *agentv1.Signed, certs []*x509.Certificate, root *x509.Certificate, agent string, at time.Time) (*agentv1.Snapshot, error) {
	payload, err := Verify(s, certs, root, at)
	if err != nil {
		return nil, err
	}
	snap := &agentv1.Snapshot{}
	if err := proto.Unmarshal(payload, snap); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if snap.GetAgent() != agent {
		return nil, fmt.Errorf("snapshot: compiled for %s, not for this agent", snap.GetAgent())
	}
	return snap, nil
}
