// SPDX-License-Identifier: Apache-2.0

package ids

import (
	"sort"
	"testing"

	"github.com/google/uuid"
)

func TestNewFormatAndOrder(t *testing.T) {
	var all []string
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id := New("rte")
		if !Valid("rte", id) {
			t.Fatalf("New returned an invalid ID %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate ID %q", id)
		}
		seen[id] = true
		all = append(all, id)
	}
	if !sort.StringsAreSorted(all) {
		t.Fatal("IDs created in sequence do not sort in creation order")
	}
}

func TestNewRejectsBadPrefixes(t *testing.T) {
	for _, p := range []string{"", "r", "route", "RTE", "rt_", "r1"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New(%q) did not panic", p)
				}
			}()
			New(p)
		}()
	}
}

func TestValid(t *testing.T) {
	good := "rte_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R"
	if !Valid("rte", good) {
		t.Errorf("Valid(rte, %q) = false", good)
	}
	for _, bad := range []string{
		"", "rte_", good + "X", good[:len(good)-1], "org_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R",
		"rte_81JA2Z8Q6W7Y3V9K4M5N6P7Q8R", // first character above 7: more than 128 bits
		"rte_01JA2Z8Q6W7Y3V9K4M5N6P7Q8I", // I is not Crockford base32
		"rte_01ja2z8q6w7y3v9k4m5n6p7q8r", // lower case
		"rte-01JA2Z8Q6W7Y3V9K4M5N6P7Q8R",
	} {
		if Valid("rte", bad) {
			t.Errorf("Valid(rte, %q) = true", bad)
		}
	}
}

func TestEncodeBoundaries(t *testing.T) {
	var zero, max uuid.UUID
	for i := range max {
		max[i] = 0xff
	}
	if got := encode(zero); got != "00000000000000000000000000" {
		t.Errorf("zero: %s", got)
	}
	if got := encode(max); got != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Errorf("max: %s", got)
	}
}
