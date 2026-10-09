// SPDX-License-Identifier: Apache-2.0

// Package totp computes and checks time-based one-time passwords (RFC 6238 over RFC 4226 HOTP,
// HMAC-SHA-1, 6 digits, 30-second steps), as authenticator apps expect them
// (docs/04-security.md, "Human authentication and sessions").
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 with HMAC-SHA-1 is what authenticator apps compute
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// The parameters every authenticator app supports.
const (
	Digits     = 6
	Step       = 30 * time.Second
	SecretSize = 20 // bytes, the HMAC-SHA-1 block-friendly size RFC 4226 recommends
)

// Skew is how many steps before or after the current one a code may come from.
const Skew = 1

// NewSecret returns a random secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretSize)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// StepOf returns the time step of t.
func StepOf(t time.Time) int64 { return t.Unix() / int64(Step/time.Second) }

// Code returns the code of a step.
func Code(secret []byte, step int64) string {
	return hotp(secret, uint64(step), Digits) //nolint:gosec // G115: steps of times after 1970 are positive
}

// hotp is RFC 4226's HOTP with dynamic truncation.
func hotp(secret []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, secret)
	_ = binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// Verify finds the step, within Skew of now and after last, whose code is code; ok is false when
// there is none, so a code that was used once, or an older one, never works again.
func Verify(secret []byte, code string, now time.Time, last int64) (step int64, ok bool) {
	if len(code) != Digits {
		return 0, false
	}
	cur := StepOf(now)
	found := int64(0)
	for s := cur - Skew; s <= cur+Skew; s++ {
		// Every candidate is computed and compared, so timing does not tell which step matched.
		if subtle.ConstantTimeCompare([]byte(Code(secret, s)), []byte(code)) == 1 && s > last && found == 0 {
			found = s
		}
	}
	return found, found != 0
}

// Encode is a secret in the unpadded base32 that authenticator apps take.
func Encode(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// URI is the otpauth:// URI of a secret, for a QR code; issuer names the instance, account the
// user.
func URI(secret []byte, issuer, account string) string {
	q := url.Values{"secret": {Encode(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(int(Step / time.Second))}}
	return (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + account, RawQuery: q.Encode()}).String()
}
