// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Envelope encryption (docs/04-security.md, "Secrets at rest and in logs"): every secret gets its
// own random data key; the data key encrypts the secret with AES-256-GCM and is itself wrapped by
// a Wrapper, the key-encryption key (KEK) held locally or in a key service. The secret's
// associated data is the table, column and row it belongs to; a local wrap's adds the KEK
// version. A sealed secret copied to another row, column or table, or presented with another KEK
// version, therefore does not open, and re-wrapping under a new KEK never decrypts the secret
// itself.
//
// Sealed format, version 2 ("Envelope format v2" in docs/04-security.md); lengths are big-endian:
//
//	1 byte   format version (2)
//	1 byte   wrapper kind (1 = a local KEK, 2 = Transit)
//	2 bytes  K, the length of the KEK identifier
//	K bytes  the KEK identifier (kind 1: the 8-byte KEK version)
//	2 bytes  W, the length of the wrapped data key
//	W bytes  the wrapped data key (kind 1: 12-byte nonce, 32-byte key, 16-byte tag)
//	12 bytes nonce of the secret
//	n+16     encrypted secret and tag
//
// Version 1 (see v1.go) stays readable and is rewritten as version 2 whenever it is sealed or
// re-wrapped again.

const (
	formatV1 = 1
	formatV2 = 2

	kekIDLen = 8 // the identifier of a local KEK
	keyLen   = 32
	nonceLen = 12
	tagLen   = 16

	maxSealSize = 1 << 20 // secrets are keys, tokens and passwords; 1 MiB is far beyond any
	maxIDLen    = 256     // K
	maxWrapLen  = 512     // W

	// minV2Header is the version, kind and the two lengths; maxV2Header adds the largest K and W
	// and the secret's nonce.
	minV2Header = 1 + 1 + 2 + 2
	maxV2Header = minV2Header + maxIDLen + maxWrapLen + nonceLen
)

// ErrOpen is returned for every sealed secret that does not open: tampered, truncated, sealed for
// another row, or under an unknown KEK. The cases are deliberately not told apart.
var ErrOpen = errors.New("secret: sealed value does not open")

// ErrUnknownKey is returned for a sealed secret whose KEK identifier or kind is not one of the
// Sealer's: sealed under another KEK, another Transit key, or a wrapper this controller has not
// configured. It wraps ErrOpen, so a caller that tests for ErrOpen sees it as every other value that
// does not open, and boot and `rpmgr kek status` can still name the case. It is returned before
// any call to a key service.
var ErrUnknownKey = fmt.Errorf("%w: it is wrapped under a KEK that is not configured", ErrOpen)

// Context names where a sealed secret is stored; it is bound to the ciphertext.
type Context struct {
	Table, Column, RowID string
}

// KEK is a local key-encryption key. Its version is derived from the key itself, so it needs no
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

// IsZero reports whether k is the zero KEK, which holds no key.
func (k KEK) IsZero() bool { return k.key.IsZero() }

// Version returns the KEK version as 16 hexadecimal digits.
func (k KEK) Version() string { return hex.EncodeToString(k.id[:]) }

// wrapperID names a wrapper: its kind and its KEK identifier.
type wrapperID struct {
	kind byte
	id   string
}

// Sealer seals with the current Wrapper and opens with the current or any previous one, so secrets
// stay readable while `rpmgr kek rotate` re-wraps them.
type Sealer struct {
	current Wrapper
	byID    map[wrapperID]Wrapper
}

// NewSealer returns a Sealer for local KEKs: it seals with current and also opens secrets sealed
// with previous.
func NewSealer(current KEK, previous ...KEK) (*Sealer, error) {
	if current.key.IsZero() {
		return nil, errors.New("secret: no current KEK")
	}
	prev := make([]Wrapper, 0, len(previous))
	for _, k := range previous {
		if k.key.IsZero() {
			return nil, errors.New("secret: empty previous KEK")
		}
		prev = append(prev, NewLocalWrapper(k))
	}
	return NewSealerWith(NewLocalWrapper(current), prev...)
}

// NewSealerWith returns a Sealer that seals with current and also opens secrets sealed with
// previous. A wrapper's kind and identifier name it; two with the same ones are one.
func NewSealerWith(current Wrapper, previous ...Wrapper) (*Sealer, error) {
	if current == nil {
		return nil, errors.New("secret: no current wrapper")
	}
	s := &Sealer{current: current, byID: map[wrapperID]Wrapper{}}
	for _, w := range append([]Wrapper{current}, previous...) {
		if w == nil || len(w.ID()) == 0 || len(w.ID()) > maxIDLen {
			return nil, errors.New("secret: a wrapper needs an identifier of 1 to 256 bytes")
		}
		s.byID[wrapperID{w.Kind(), string(w.ID())}] = w
	}
	return s, nil
}

// Seal encrypts v for storage at sc, as a version 2 value. ctx bounds the call to a key service.
func (s *Sealer) Seal(ctx context.Context, sc Context, v Value) ([]byte, error) {
	plain := []byte(v.Reveal())
	if len(plain) > maxSealSize {
		return nil, fmt.Errorf("secret: %d bytes is more than the %d a secret may have", len(plain), maxSealSize)
	}
	dataKey := make([]byte, keyLen)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	defer clear(dataKey)
	ad := dataAD(formatV2, sc)
	out, err := s.wrapHeader(ctx, dataKey, ad)
	if err != nil {
		return nil, err
	}
	return sealGCM(out, dataKey, plain, ad)
}

// wrapHeader returns the version 2 header up to and including the wrapped data key, wrapped by the
// current Wrapper.
func (s *Sealer) wrapHeader(ctx context.Context, dataKey, ad []byte) ([]byte, error) {
	wrapped, err := s.current.Wrap(ctx, dataKey, ad)
	if err != nil {
		return nil, err
	}
	return s.header(wrapped)
}

// header returns the version 2 header up to and including wrapped, which the current Wrapper made.
func (s *Sealer) header(wrapped []byte) ([]byte, error) {
	w := s.current
	id := w.ID()
	if len(id) == 0 || len(id) > maxIDLen {
		return nil, fmt.Errorf("secret: a KEK identifier of %d bytes is outside 1 to %d", len(id), maxIDLen)
	}
	if len(wrapped) == 0 || len(wrapped) > maxWrapLen {
		return nil, fmt.Errorf("secret: a wrapped data key of %d bytes is outside 1 to %d", len(wrapped), maxWrapLen)
	}
	out := make([]byte, 0, minV2Header+len(id)+len(wrapped))
	out = append(out, formatV2, w.Kind())
	out = binary.BigEndian.AppendUint16(out, uint16(len(id))) //nolint:gosec // 1 to 256, checked above
	out = append(out, id...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped))) //nolint:gosec // 1 to 512, checked above
	return append(out, wrapped...), nil
}

// Open decrypts a secret sealed for sc. Every failure to open returns ErrOpen; a wrapper that
// cannot be reached returns its own error. ctx bounds the call to a key service.
func (s *Sealer) Open(ctx context.Context, sc Context, sealed []byte) (Value, error) {
	p, err := s.unwrap(ctx, sc, sealed)
	if err != nil {
		return Value{}, err
	}
	defer clear(p.dataKey)
	plain, err := openGCM(p.dataKey, p.rest, dataAD(p.format, sc))
	if err != nil {
		return Value{}, ErrOpen
	}
	return FromBytes(plain), nil
}

// Rewrap re-wraps the data key of a sealed secret under the current Wrapper; the encrypted secret
// itself is kept as it is. A version 2 secret already under the current Wrapper is returned
// unchanged, unless the Wrapper is a Rewrapper, which decides: a Transit key keeps its identifier
// when it is rotated and changes its version only. A version 1 secret is sealed again as version 2
// with a new data key, because its associated data carries the version 1 label.
func (s *Sealer) Rewrap(ctx context.Context, sc Context, sealed []byte) ([]byte, error) {
	if rw, ok := s.current.(Rewrapper); ok && len(sealed) > 0 && sealed[0] == formatV2 {
		h, err := parseV2(sealed)
		if err != nil {
			return nil, err
		}
		if h.kind == rw.Kind() && string(h.id) == string(rw.ID()) {
			wrapped, err := rw.Rewrap(ctx, h.wrapped, dataAD(formatV2, sc))
			if err != nil {
				return nil, err
			}
			if bytes.Equal(wrapped, h.wrapped) {
				return sealed, nil
			}
			out, err := s.header(wrapped)
			if err != nil {
				return nil, err
			}
			return append(out, h.rest...), nil
		}
	}
	p, err := s.unwrap(ctx, sc, sealed)
	if err != nil {
		return nil, err
	}
	defer clear(p.dataKey)
	if p.format == formatV1 {
		plain, err := openGCM(p.dataKey, p.rest, dataAD(formatV1, sc))
		if err != nil {
			return nil, ErrOpen
		}
		return s.Seal(ctx, sc, FromBytes(plain))
	}
	if p.wrapper.Kind() == s.current.Kind() && string(p.wrapper.ID()) == string(s.current.ID()) {
		if _, ok := s.current.(Rewrapper); !ok {
			return sealed, nil
		}
	}
	out, err := s.wrapHeader(ctx, p.dataKey, dataAD(formatV2, sc))
	if err != nil {
		return nil, err
	}
	return append(out, p.rest...), nil
}

// KEKVersion returns the version of the KEK a sealed secret is wrapped with: 16 hexadecimal digits
// for a local KEK, "<mount>/<key>@v<n>" for a Transit key, the key identifier for any other
// wrapper. It reads the header only.
func KEKVersion(sealed []byte) (string, error) {
	if len(sealed) > 0 && sealed[0] == formatV1 {
		if len(sealed) < v1HeaderLen+tagLen {
			return "", ErrOpen
		}
		return hex.EncodeToString(sealed[1 : 1+kekIDLen]), nil
	}
	h, err := parseV2(sealed)
	if err != nil {
		return "", err
	}
	if h.kind == KindLocal {
		return hex.EncodeToString(h.id), nil
	}
	if h.kind == KindTransit {
		// "vault:v<n>:<base64>" gives the key version: "<mount>/<key>@v<n>".
		if v, ok := strings.CutPrefix(string(h.wrapped), "vault:v"); ok {
			if n, _, ok := strings.Cut(v, ":"); ok && validKeyVersion(n) {
				return string(h.id) + "@v" + n, nil
			}
		}
	}
	return string(h.id), nil
}

// KEKIdentity is a KEK version without the key version: "<mount>/<key>" for "<mount>/<key>@v<n>",
// and a local KEK's version as it is. Two versions of one Transit key share it.
func KEKIdentity(version string) string {
	id, _, _ := strings.Cut(version, "@v")
	return id
}

// validKeyVersion is a decimal number from 1 to 9999999999 without a leading zero, the form
// Transit writes, so that one key version has one spelling in secrets_meta.
func validKeyVersion(n string) bool {
	return n != "" && len(n) <= 10 && n[0] != '0' && strings.Trim(n, "0123456789") == ""
}

// parsed is a sealed value taken apart and its data key unwrapped.
type parsed struct {
	format  byte
	wrapper Wrapper
	dataKey []byte
	rest    []byte // the secret's nonce, ciphertext and tag
}

func (s *Sealer) unwrap(ctx context.Context, sc Context, sealed []byte) (parsed, error) {
	if len(sealed) == 0 {
		return parsed{}, ErrOpen
	}
	switch sealed[0] {
	case formatV1:
		return s.unwrapV1(sc, sealed)
	case formatV2:
		h, err := parseV2(sealed)
		if err != nil {
			return parsed{}, err
		}
		w, ok := s.byID[wrapperID{h.kind, string(h.id)}]
		if !ok {
			return parsed{}, ErrUnknownKey
		}
		dataKey, err := w.Unwrap(ctx, h.wrapped, dataAD(formatV2, sc))
		if err != nil {
			return parsed{}, err
		}
		if len(dataKey) != keyLen {
			return parsed{}, ErrOpen
		}
		// A copy, because the caller clears it and a wrapper may return a slice of its input.
		return parsed{format: formatV2, wrapper: w, dataKey: bytes.Clone(dataKey), rest: h.rest}, nil
	}
	return parsed{}, ErrOpen
}

// header is the structure of a version 2 value, before anything is opened.
type header struct {
	kind    byte
	id      []byte
	wrapped []byte
	rest    []byte
}

// parseV2 checks the lengths of a version 2 value against the bounds; every violation is ErrOpen.
func parseV2(b []byte) (header, error) {
	var h header
	if len(b) < minV2Header || b[0] != formatV2 || len(b) > maxV2Header+maxSealSize+tagLen {
		return h, ErrOpen
	}
	h.kind = b[1]
	k := int(binary.BigEndian.Uint16(b[2:4]))
	if k == 0 || k > maxIDLen || len(b) < 4+k+2 {
		return h, ErrOpen
	}
	h.id = b[4 : 4+k]
	w := int(binary.BigEndian.Uint16(b[4+k : 6+k]))
	if w == 0 || w > maxWrapLen || len(b) < 6+k+w+nonceLen+tagLen {
		return h, ErrOpen
	}
	h.wrapped = b[6+k : 6+k+w]
	h.rest = b[6+k+w:]
	if len(h.rest) > nonceLen+maxSealSize+tagLen {
		return h, ErrOpen
	}
	return h, nil
}

// dataAD is the secret's associated data: the version's label and the context, with length
// prefixes so that no two different contexts produce the same bytes.
func dataAD(format byte, ctx Context) []byte {
	ad := []byte("rpmgr-envelope-v2/data")
	if format == formatV1 {
		ad = []byte("rpmgr-envelope-v1/data")
	}
	for _, f := range []string{ctx.Table, ctx.Column, ctx.RowID} {
		ad = binary.AppendUvarint(ad, uint64(len(f)))
		ad = append(ad, f...)
	}
	return ad
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
