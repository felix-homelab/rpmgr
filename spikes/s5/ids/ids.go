// SPDX-License-Identifier: Apache-2.0

// Package ids creates rpmgr IDs: <prefix>_<26-character Crockford base32 of a UUIDv7>
// (docs/06-data-model.md, "Identifiers").
package ids

import (
	"github.com/google/uuid"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a new, time-ordered ID with the given prefix, e.g. "rte_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R".
func New(prefix string) string {
	u := uuid.Must(uuid.NewV7())
	return prefix + "_" + encode(u)
}

// encode writes 128 bits as 26 base32 characters, most significant first (the first character
// carries only 3 bits), so IDs sort like their UUIDs.
func encode(u uuid.UUID) string {
	var out [26]byte
	// Treat u as a 130-bit big-endian number with two leading zero bits.
	for i := 25; i >= 0; i-- {
		bit := (25 - i) * 5 // position of the lowest bit of this character, from the right
		v := 0
		for b := 0; b < 5; b++ {
			pos := bit + b // bit position from the right, 0..129
			if pos >= 128 {
				continue
			}
			byteIdx := 15 - pos/8
			if u[byteIdx]&(1<<(pos%8)) != 0 {
				v |= 1 << b
			}
		}
		out[i] = crockford[v]
	}
	return string(out[:])
}
