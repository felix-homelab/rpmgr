// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

// SerialHex is a serial number's key in issued_certificates and on the deny-list.
func SerialHex(n *big.Int) string { return n.Text(16) }

// PublicKeyHash is the lower-case hexadecimal SHA-256 of a SubjectPublicKeyInfo, as
// issued_certificates and the fleet tables store it.
func PublicKeyHash(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}
