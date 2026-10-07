// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrPinNotFound is returned when no root in a trust bundle matches the pin.
var ErrPinNotFound = errors.New("pki: no root in the bundle matches the pin")

// RootPin returns the --ca-pin value of a root: "sha256:" and the standard base64 of the SHA-256
// of its SubjectPublicKeyInfo (docs/04-security.md, "Join command").
func RootPin(root *x509.Certificate) string {
	sum := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	return "sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// ValidPin reports whether pin has the form of a root pin.
func ValidPin(pin string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(pin, "sha256:"))
	return strings.HasPrefix(pin, "sha256:") && err == nil && len(b) == sha256.Size
}

// SelectPinnedRoot keeps only the root whose pin equals pin, and returns it with the trust domain
// read from it. Every other certificate of the unauthenticated bundle is discarded.
func SelectPinnedRoot(bundle []*x509.Certificate, pin string) (*x509.Certificate, string, error) {
	if !ValidPin(pin) {
		return nil, "", errors.New("pki: the pin is not sha256:<base64 of 32 bytes>")
	}
	for _, c := range bundle {
		if RootPin(c) != pin {
			continue
		}
		if c.CheckSignatureFrom(c) != nil {
			return nil, "", errors.New("pki: the pinned certificate is not a self-signed root")
		}
		td, err := TrustDomainOf(c)
		if err != nil {
			return nil, "", err
		}
		return c, td, nil
	}
	return nil, "", ErrPinNotFound
}
