// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"errors"
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

// TestBudget_QUICAndH2Share: QUIC windows and h2 reservations draw on one budget: QUIC growth
// leaves h2 sessions smaller windows and finally none, and h2 reservations stop QUIC windows from
// growing beyond what is left.
func TestBudget_QUICAndH2Share(t *testing.T) {
	const mib = 1 << 20
	b := NewBudget(64 * mib)
	q := new(quic.Conn)
	if !b.allow(q, 48*mib) {
		t.Fatal("QUIC refused within the budget")
	}
	w, release, err := b.AdmitH2(DefaultH2Windows())
	if err != nil || w.Conn != mib { // a sixteenth of 16 MiB free
		t.Fatalf("h2 beside QUIC: %+v %v", w, err)
	}
	if b.allow(q, 15*mib+1) {
		t.Fatal("QUIC grew into the h2 reservation")
	}
	if !b.allow(q, 15*mib) {
		t.Fatal("QUIC refused what is left")
	}
	if _, _, err := b.AdmitH2(DefaultH2Windows()); !errors.Is(err, ErrBudget) {
		t.Fatalf("h2 in a budget QUIC filled: %v", err)
	}
	release()
	b.release(q)
	if b.Used() != 0 {
		t.Fatalf("used %d after both ended", b.Used())
	}
}
