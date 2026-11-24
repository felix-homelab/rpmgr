// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// The limits of the trust roots in Welcome and in a snapshot (docs/03-connections.md, "Trust roots
// in Welcome and snapshots" and the timeout and limit table).
const (
	MaxTrustRoots     = 4       // self-signed roots
	MaxTrustCerts     = 8       // certificates in all, cross-certificates included
	MaxTrustCertBytes = 2 << 10 // one certificate as DER
	RootsDigestSize   = sha256.Size
)

// RootsDigest is the SHA-256 over self-signed roots, sorted by the SHA-256 of their
// SubjectPublicKeyInfo, each as its length in bytes (an unsigned varint) and its DER. It is the
// digest an agent sends in Hello.roots_digest and the controller compares it with. A certificate
// that is not self-signed does not count, so the cross-certificates of a bundle can be passed
// along with its roots.
func RootsDigest(certs []*x509.Certificate) []byte {
	roots := selfSigned(certs)
	sortByKey(roots)
	h := sha256.New()
	var n [binary.MaxVarintLen64]byte
	for _, r := range roots {
		h.Write(n[:binary.PutUvarint(n[:], uint64(len(r.Raw)))])
		h.Write(r.Raw)
	}
	return h.Sum(nil)
}

// TrustRootsDER returns the trust roots for Welcome and snapshots: the DER of the self-signed
// certificates of bundle first, then the rest (the cross-certificates), each group sorted by the
// SHA-256 of the public key, so that two replicas send the same bytes. It refuses a bundle past
// the limits, and one without a root.
func TrustRootsDER(bundle []*x509.Certificate) ([][]byte, error) {
	roots := selfSigned(bundle)
	var cross []*x509.Certificate
	for _, c := range bundle {
		if !slices.ContainsFunc(roots, func(r *x509.Certificate) bool { return r == c }) {
			cross = append(cross, c)
		}
	}
	switch {
	case len(roots) == 0:
		return nil, errors.New("pki: the trust bundle holds no self-signed root")
	case len(roots) > MaxTrustRoots:
		return nil, fmt.Errorf("pki: the trust bundle holds %d roots, at most %d", len(roots), MaxTrustRoots)
	case len(bundle) > MaxTrustCerts:
		return nil, fmt.Errorf("pki: the trust bundle holds %d certificates, at most %d", len(bundle), MaxTrustCerts)
	}
	sortByKey(roots)
	sortByKey(cross)
	out := make([][]byte, 0, len(bundle))
	for _, c := range append(roots, cross...) {
		if len(c.Raw) > MaxTrustCertBytes {
			return nil, fmt.Errorf("pki: a trust certificate is %d bytes, at most %d", len(c.Raw), MaxTrustCertBytes)
		}
		out = append(out, c.Raw)
	}
	return out, nil
}

func selfSigned(certs []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range certs {
		if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			out = append(out, c)
		}
	}
	return out
}

func sortByKey(certs []*x509.Certificate) {
	slices.SortFunc(certs, func(a, b *x509.Certificate) int {
		ka, kb := sha256.Sum256(a.RawSubjectPublicKeyInfo), sha256.Sum256(b.RawSubjectPublicKeyInfo)
		if c := bytes.Compare(ka[:], kb[:]); c != 0 {
			return c
		}
		return bytes.Compare(a.Raw, b.Raw)
	})
}
