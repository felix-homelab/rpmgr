// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Envelope encryption (docs/04-security.md, "Secrets at rest and in logs"): every secret gets its
// own random data key; the data key encrypts the secret with AES-256-GCM and is itself wrapped by
// the key-encryption key (KEK) with AES-256-GCM. The secret's associated data is the table,
// column and row it belongs to; the wrapped data key's associated data adds the KEK version. A
// sealed secret copied to another row, column or table, or presented with another KEK version,
// therefore does not open, and re-wrapping under a new KEK never decrypts the secret itself.
//
// Sealed format, version 1:
//
//	1 byte   format version (1)
//	8 bytes  KEK version
//	12 bytes nonce of the wrapped data key
//	48 bytes wrapped data key (32-byte key + 16-byte tag)
//	12 bytes nonce of the secret
//	n+16     encrypted secret and tag

const (
	formatV1    = 1
	kekIDLen    = 8
	keyLen      = 32
	nonceLen    = 12
	tagLen      = 16
	wrappedLen  = keyLen + tagLen
	headerLen   = 1 + kekIDLen + nonceLen + wrappedLen + nonceLen
	maxSealSize = 1 << 20 // secrets are keys, tokens and passwords; 1 MiB is far beyond any
)

// ErrOpen is returned for every sealed secret that does not open: tampered, truncated, sealed for
// another row, or under an unknown KEK. The cases are deliberately not told apart.
var ErrOpen = errors.New("secret: sealed value does not open")

// Context names where a sealed secret is stored; it is bound to the ciphertext.
type Context struct {
	Table, Column, RowID string
}

// KEK is a key-encryption key. Its version is derived from the key itself, so it needs no
// configuration and changes whenever the key does.
type KEK struct {
	id  [kekIDLen]byte
	key Value
}

// NewKEK returns a KEK for a 32-byte key.
func NewKEK(key []byte) (KEK, error) {
	if len(key) != keyLen {
		return KEK{}, fmt.Errorf("secret: KEK must be %d bytes, got %d", keyLen, len(key))
	}
	sum := sha256.Sum256(append([]byte("rpmgr-kek-version\x00"), key...))
	var k KEK
	copy(k.id[:], sum[:kekIDLen])
	k.key = FromBytes(key)
	return k, nil
}

// Version returns the KEK version as 16 hexadecimal digits.
func (k KEK) Version() string { return hex.EncodeToString(k.id[:]) }

// Sealer seals with the current KEK and opens with the current or any previous KEK, so secrets
// stay readable while `rpmgr kek rotate` re-wraps them.
type Sealer struct {
	current KEK
	byID    map[[kekIDLen]byte]KEK
}

// NewSealer returns a Sealer that seals with current and also opens secrets sealed with previous.
func NewSealer(current KEK, previous ...KEK) (*Sealer, error) {
	if current.key.IsZero() {
		return nil, errors.New("secret: no current KEK")
	}
	s := &Sealer{current: current, byID: map[[kekIDLen]byte]KEK{current.id: current}}
	for _, k := range previous {
		if k.key.IsZero() {
			return nil, errors.New("secret: empty previous KEK")
		}
		s.byID[k.id] = k
	}
	return s, nil
}

// Seal encrypts v for storage at ctx.
func (s *Sealer) Seal(ctx Context, v Value) ([]byte, error) {
	plain := []byte(v.Reveal())
	if len(plain) > maxSealSize {
		return nil, fmt.Errorf("secret: %d bytes is more than the %d a secret may have", len(plain), maxSealSize)
	}
	dataKey := make([]byte, keyLen)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+len(plain)+tagLen)
	out = append(out, formatV1)
	out = append(out, s.current.id[:]...)
	out, err := sealGCM(out, []byte(s.current.key.Reveal()), dataKey, wrapAD(ctx, s.current.id))
	if err != nil {
		return nil, err
	}
	return sealGCM(out, dataKey, plain, dataAD(ctx))
}

// Open decrypts a secret sealed for ctx. Every failure returns ErrOpen.
func (s *Sealer) Open(ctx Context, sealed []byte) (Value, error) {
	_, dataKey, rest, err := s.unwrap(ctx, sealed)
	if err != nil {
		return Value{}, err
	}
	plain, err := openGCM(dataKey, rest, dataAD(ctx))
	if err != nil {
		return Value{}, ErrOpen
	}
	return FromBytes(plain), nil
}

// Rewrap re-wraps the data key of a sealed secret under the current KEK; the encrypted secret
// itself is kept as it is. A secret already under the current KEK is returned unchanged.
func (s *Sealer) Rewrap(ctx Context, sealed []byte) ([]byte, error) {
	kek, dataKey, rest, err := s.unwrap(ctx, sealed)
	if err != nil {
		return nil, err
	}
	if kek.id == s.current.id {
		return sealed, nil
	}
	out := append([]byte{formatV1}, s.current.id[:]...)
	if out, err = sealGCM(out, []byte(s.current.key.Reveal()), dataKey, wrapAD(ctx, s.current.id)); err != nil {
		return nil, err
	}
	return append(out, rest...), nil
}

// KEKVersion returns the version of the KEK a sealed secret is wrapped with.
func KEKVersion(sealed []byte) (string, error) {
	if len(sealed) < headerLen+tagLen || sealed[0] != formatV1 {
		return "", ErrOpen
	}
	return hex.EncodeToString(sealed[1 : 1+kekIDLen]), nil
}

func (s *Sealer) unwrap(ctx Context, sealed []byte) (KEK, []byte, []byte, error) {
	if len(sealed) < headerLen+tagLen || len(sealed) > headerLen+maxSealSize+tagLen || sealed[0] != formatV1 {
		return KEK{}, nil, nil, ErrOpen
	}
	var id [kekIDLen]byte
	copy(id[:], sealed[1:1+kekIDLen])
	kek, ok := s.byID[id]
	if !ok {
		return KEK{}, nil, nil, ErrOpen
	}
	wrapped := sealed[1+kekIDLen : 1+kekIDLen+nonceLen+wrappedLen]
	dataKey, err := openGCM([]byte(kek.key.Reveal()), wrapped, wrapAD(ctx, id))
	if err != nil {
		return KEK{}, nil, nil, ErrOpen
	}
	return kek, dataKey, sealed[1+kekIDLen+nonceLen+wrappedLen:], nil
}

// dataAD is the secret's associated data: the context, with length prefixes so that no two
// different contexts produce the same bytes.
func dataAD(ctx Context) []byte {
	ad := []byte("rpmgr-envelope-v1/data")
	for _, f := range []string{ctx.Table, ctx.Column, ctx.RowID} {
		ad = binary.AppendUvarint(ad, uint64(len(f)))
		ad = append(ad, f...)
	}
	return ad
}

// wrapAD is the wrapped data key's associated data: the context and the KEK version.
func wrapAD(ctx Context, kekID [kekIDLen]byte) []byte {
	return append(append([]byte("rpmgr-envelope-v1/wrap"), dataAD(ctx)...), kekID[:]...)
}

// sealGCM appends nonce ‖ AES-256-GCM(key, plain, aad) to dst.
func sealGCM(dst, key, plain, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	dst = append(dst, nonce...)
	return aead.Seal(dst, nonce, plain, aad), nil
}

// openGCM opens nonce ‖ ciphertext.
func openGCM(key, in, aad []byte) ([]byte, error) {
	if len(in) < nonceLen+tagLen {
		return nil, ErrOpen
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, in[:nonceLen], in[nonceLen:], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
