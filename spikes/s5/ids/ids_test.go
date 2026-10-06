// SPDX-License-Identifier: Apache-2.0

package ids

import (
	"regexp"
	"sort"
	"testing"

	"github.com/google/uuid"
)

func TestNew_FormatAndOrder(t *testing.T) {
	re := regexp.MustCompile(`^rte_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	var all []string
	for i := 0; i < 1000; i++ {
		id := New("rte")
		if !re.MatchString(id) {
			t.Fatalf("bad ID %q", id)
		}
		all = append(all, id)
	}
	if !sort.StringsAreSorted(all) {
		t.Fatal("IDs created in sequence do not sort in creation order")
	}
}

func TestEncode_Boundaries(t *testing.T) {
	var zero, max uuid.UUID
	for i := range max {
		max[i] = 0xff
	}
	if got := encode(zero); got != "00000000000000000000000000" {
		t.Fatalf("zero: %s", got)
	}
	if got := encode(max); got != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("max: %s", got)
	}
}
