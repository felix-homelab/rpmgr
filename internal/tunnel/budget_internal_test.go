// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"testing"

	"github.com/quic-go/quic-go"
)

// TestBudget: windows grow while the budget has room; a refusal changes nothing; a session's share
// returns when it ends.
func TestBudget(t *testing.T) {
	b := NewBudget(100)
	c1, c2 := new(quic.Conn), new(quic.Conn)
	if !b.allow(c1, 60) || !b.allow(c2, 40) {
		t.Fatal("refused within the budget")
	}
	if b.allow(c1, 1) {
		t.Fatal("allowed beyond the budget")
	}
	if b.Used() != 100 {
		t.Fatalf("used %d", b.Used())
	}
	b.release(c1)
	if b.Used() != 40 || !b.allow(c2, 60) || b.allow(c2, 1) {
		t.Fatalf("after a release: used %d", b.Used())
	}
	b.release(c1) // twice is harmless
	if b.Used() != 100 {
		t.Fatalf("a second release changed the budget: %d", b.Used())
	}
}
