// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

var ErrPinNotFound = errors.New("no root in the bundle matches the pin")

// SelectPinnedRoot keeps only the root whose SPKI hash equals the pin and reads the trust domain
// from its URI SAN (docs/04-security.md, "Join command"). Every other certificate in the
// unauthenticated bundle is discarded.
func SelectPinnedRoot(bundle []*x509.Certificate, pin string) (*x509.Certificate, string, error) {
	for _, c := range bundle {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		if "sha256:"+base64.StdEncoding.EncodeToString(sum[:]) != pin {
			continue
		}
		if !c.IsCA || len(c.URIs) != 1 || c.URIs[0].Scheme != "spiffe" || c.URIs[0].Host == "" ||
			(c.URIs[0].Path != "" && c.URIs[0].Path != "/") {
			return nil, "", errors.New("pinned certificate is not an rpmgr root")
		}
		return c, c.URIs[0].Host, nil
	}
	return nil, "", ErrPinNotFound
}
