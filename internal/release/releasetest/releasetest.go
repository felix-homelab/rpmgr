// SPDX-License-Identifier: Apache-2.0

// Package releasetest signs releases with test keys, for tests and rpmgrtest builds only (D60).
// Its keys are derived from their names, so no private key is stored anywhere.
package releasetest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// A Signer is a minisign key pair.
type Signer struct {
	id   [8]byte
	priv ed25519.PrivateKey
}

// Key derives the test key of a name.
func Key(name string) Signer {
	seed := sha256.Sum256([]byte("rpmgr release test key: " + name))
	var s Signer
	copy(s.id[:], seed[:8])
	s.priv = ed25519.NewKeyFromSeed(seed[:])
	return s
}

// Public is the public key in minisign's base64 form.
func (s Signer) Public() string {
	return base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), s.id[:]...), s.priv.Public().(ed25519.PublicKey)...))
}

// Sign makes a minisign signature file over msg, prehashed as minisign does by default.
func (s Signer) Sign(msg []byte) []byte {
	hash := blake2b.Sum512(msg)
	sig := ed25519.Sign(s.priv, hash[:])
	trusted := "timestamp:0\tfile:test"
	global := ed25519.Sign(s.priv, append(bytes.Clone(sig), trusted...))
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Appendf(nil, "untrusted comment: rpmgr test signature\n%s\ntrusted comment: %s\n%s\n",
		b64(append(append([]byte("ED"), s.id[:]...), sig...)), trusted, b64(global))
}
