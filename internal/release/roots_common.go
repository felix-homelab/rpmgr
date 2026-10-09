// SPDX-License-Identifier: Apache-2.0

package release

// Roots returns the release root keys compiled into this binary.
func Roots() []PublicKey {
	out := make([]PublicKey, len(rootKeys))
	for i, s := range rootKeys {
		k, err := ParsePublicKey(s)
		if err != nil {
			panic("release: a compiled-in root key is not a minisign public key: " + s)
		}
		out[i] = k
	}
	return out
}
