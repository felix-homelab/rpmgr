// SPDX-License-Identifier: Apache-2.0

// Package ids creates rpmgr IDs: <prefix>_<26-character Crockford base32 of a UUIDv7>
// (docs/06-data-model.md, "Identifiers"). IDs sort by creation time, are globally unique and show
// their type.
package ids

import (
	"fmt"
	"regexp"

	"github.com/google/uuid"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	prefixRe = regexp.MustCompile(`^[a-z]{2,4}$`)
	idRe     = regexp.MustCompile(`^([a-z]{2,4})_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
)

// New returns a new, time-ordered ID with the given prefix, e.g. "rte_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R".
// It panics on a prefix that is not 2–4 lower-case letters: prefixes are constants of the schema.
func New(prefix string) string {
	if !prefixRe.MatchString(prefix) {
		panic(fmt.Sprintf("ids: invalid prefix %q", prefix))
	}
	return prefix + "_" + encode(uuid.Must(uuid.NewV7()))
}

// Valid reports whether id is an rpmgr ID with the given prefix.
func Valid(prefix, id string) bool {
	m := idRe.FindStringSubmatch(id)
	return m != nil && m[1] == prefix
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
			if u[15-pos/8]&(1<<(pos%8)) != 0 {
				v |= 1 << b
			}
		}
		out[i] = crockford[v]
	}
	return string(out[:])
}
