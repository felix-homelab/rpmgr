// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// The minisign formats (docs/04-security.md, "Release signing"): a public key is "Ed", an 8-byte
// key ID and the Ed25519 key, in base64; a signature file has an untrusted comment, "ED", the key
// ID and the signature of the file's BLAKE2b-512 hash in base64, a trusted comment, and a global
// signature over the signature and the trusted comment.
const (
	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "
)

var (
	keyAlgorithm    = []byte("Ed")
	hashedAlgorithm = []byte("ED") // minisign's default; the legacy "Ed" signatures are refused
)

// ErrSignature means a signature is malformed, made with another key, or does not verify.
var ErrSignature = errors.New("release: bad signature")

// PublicKey is a minisign Ed25519 public key.
type PublicKey struct {
	ID  [8]byte
	Key ed25519.PublicKey
}

// ParsePublicKey reads a minisign public key: the base64 line, alone or after its untrusted
// comment as in a .pub file.
func ParsePublicKey(text string) (PublicKey, error) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 2 && strings.HasPrefix(lines[0], untrustedPrefix) {
		lines = lines[1:]
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[0]))
	if len(lines) != 1 || err != nil || len(b) != 2+8+ed25519.PublicKeySize || !bytes.Equal(b[:2], keyAlgorithm) {
		return PublicKey{}, errors.New("release: not a minisign Ed25519 public key")
	}
	var k PublicKey
	copy(k.ID[:], b[2:10])
	k.Key = ed25519.PublicKey(bytes.Clone(b[10:]))
	return k, nil
}

// String is the key in minisign's base64 form.
func (k PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(append(append(bytes.Clone(keyAlgorithm), k.ID[:]...), k.Key...))
}

// IDString is the key ID as minisign prints it: the little-endian number in upper-case hex.
func (k PublicKey) IDString() string {
	return fmt.Sprintf("%016X", binary.LittleEndian.Uint64(k.ID[:]))
}

// Fingerprint is the SHA-256 of the key, in hex.
func (k PublicKey) Fingerprint() string {
	sum := sha256.Sum256(k.Key)
	return hex.EncodeToString(sum[:])
}

// verify checks a minisign signature file over msg with the key of its ID among keys, and
// returns that key and the trusted comment.
func verify(keys []PublicKey, msg, sigFile []byte) (PublicKey, string, error) {
	lines := strings.Split(strings.TrimRight(string(sigFile), "\n"), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], untrustedPrefix) || !strings.HasPrefix(lines[2], trustedPrefix) {
		return PublicKey{}, "", fmt.Errorf("%w: not a minisign signature file", ErrSignature)
	}
	sig, err1 := base64.StdEncoding.DecodeString(lines[1])
	global, err2 := base64.StdEncoding.DecodeString(lines[3])
	if err1 != nil || err2 != nil || len(sig) != 2+8+ed25519.SignatureSize || len(global) != ed25519.SignatureSize {
		return PublicKey{}, "", fmt.Errorf("%w: malformed", ErrSignature)
	}
	if !bytes.Equal(sig[:2], hashedAlgorithm) {
		return PublicKey{}, "", fmt.Errorf("%w: not a prehashed (ED) signature", ErrSignature)
	}
	var key *PublicKey
	for i := range keys {
		if bytes.Equal(keys[i].ID[:], sig[2:10]) {
			key = &keys[i]
		}
	}
	if key == nil {
		return PublicKey{}, "", fmt.Errorf("%w: made with an unknown key", ErrSignature)
	}
	hash := blake2b.Sum512(msg)
	trusted := strings.TrimPrefix(lines[2], trustedPrefix)
	if !ed25519.Verify(key.Key, hash[:], sig[10:]) || !ed25519.Verify(key.Key, append(bytes.Clone(sig[10:]), trusted...), global) {
		return PublicKey{}, "", fmt.Errorf("%w: does not verify with key %s", ErrSignature, key.IDString())
	}
	return *key, trusted, nil
}
