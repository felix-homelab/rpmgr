// SPDX-License-Identifier: Apache-2.0

// Package token creates and checks rpmgr's bearer tokens (docs/04-security.md, "Tokens"):
// `rpmgr_<kind>_<base62 of 32 random bytes>_<6-character CRC32 checksum>`. The checksum lets a
// typo be found offline and a secret scanner recognise a real token; the database stores only the
// SHA-256 of a token.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash/crc32"
	"math/big"
	"strings"
)

// Kind is a token's purpose.
type Kind string

// The kinds of token.
const (
	Enrollment     Kind = "enr" // enrolls an agent
	PersonalAPI    Kind = "pat" // a user's API token
	ServiceAccount Kind = "sat" // a service account's API token
	Session        Kind = "ses" // a web session
	PasswordReset  Kind = "prs" // a one-time link that sets a password or creates the first user
	Invitation     Kind = "inv" // a one-time link that makes its holder a member of an org
)

const (
	alphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	randomBytes = 32
	randomLen   = 43 // base62 digits of 256 bits
	checksumLen = 6  // base62 digits of 32 bits
	prefix      = "rpmgr_"
	// Len is the length of every token.
	Len = len(prefix) + 3 + 1 + randomLen + 1 + checksumLen
)

// Errors of Parse.
var (
	ErrMalformed = errors.New("token: not an rpmgr token")
	ErrChecksum  = errors.New("token: checksum does not match; mistyped?")
)

// New returns a new token of kind k.
func New(k Kind) (string, error) {
	if !known(k) {
		return "", ErrMalformed
	}
	b := make([]byte, randomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	body := prefix + string(k) + "_" + base62(new(big.Int).SetBytes(b), randomLen)
	return body + "_" + checksum(body), nil
}

// Parse checks the form and the checksum of s and returns its kind.
func Parse(s string) (Kind, error) {
	if len(s) != Len || !strings.HasPrefix(s, prefix) {
		return "", ErrMalformed
	}
	k := Kind(s[len(prefix) : len(prefix)+3])
	rest := s[len(prefix)+3:]
	if !known(k) || rest[0] != '_' || rest[1+randomLen] != '_' ||
		!isBase62(rest[1:1+randomLen]) || !isBase62(rest[2+randomLen:]) {
		return "", ErrMalformed
	}
	if checksum(s[:len(s)-checksumLen-1]) != s[len(s)-checksumLen:] {
		return "", ErrChecksum
	}
	return k, nil
}

// Hash is the form in which a token is stored and looked up.
func Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func known(k Kind) bool {
	return k == Enrollment || k == PersonalAPI || k == ServiceAccount || k == Session || k == PasswordReset || k == Invitation
}

// checksum is the CRC32 (IEEE) of body in base62, 6 digits.
func checksum(body string) string {
	return base62(new(big.Int).SetUint64(uint64(crc32.ChecksumIEEE([]byte(body)))), checksumLen)
}

// base62 writes n in exactly digits base62 digits, most significant first.
func base62(n *big.Int, digits int) string {
	out := make([]byte, digits)
	base, mod := big.NewInt(62), new(big.Int)
	for i := digits - 1; i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = alphabet[mod.Int64()]
	}
	return string(out)
}

func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}
