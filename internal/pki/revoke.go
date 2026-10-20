// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/sha256"
	"slices"
	"strings"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// SortDenyEntries orders a deny-list: serials before identities, each in ascending order.
func SortDenyEntries(es []*agentv1.DenyEntry) {
	slices.SortFunc(es, func(a, b *agentv1.DenyEntry) int { return strings.Compare(denyKey(a), denyKey(b)) })
}

// denyKey is an entry's place in the order and its identity in the digest.
func denyKey(e *agentv1.DenyEntry) string {
	if s := e.GetSerial(); s != "" {
		return "1 serial " + s
	}
	return "2 identity " + e.GetIdentity()
}

// DenyDigest is the digest of a deny-list that an agent sends in Hello: SHA-256 over the sorted,
// distinct entries, serial or identity, each followed by a newline, and then the line
// "key <keyID>" of the key that signed the list; nothing for an empty list. Expiry times are not
// part of it, so a controller and an agent that prune at slightly different times still agree; the
// key is, so that after a key rotation every agent receives the list signed by the new key.
func DenyDigest(es []*agentv1.DenyEntry, keyID string) []byte {
	if len(es) == 0 {
		return nil
	}
	keys := make([]string, 0, len(es))
	for _, e := range es {
		keys = append(keys, denyKey(e))
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k + "\n"))
	}
	h.Write([]byte("key " + keyID + "\n"))
	return h.Sum(nil)
}
