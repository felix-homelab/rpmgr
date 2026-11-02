// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"errors"
	"testing"
)

// TestBudget_QUICAdmission: a QUIC session is admitted with its connection window, at most 64 MiB
// and a sixteenth of the free budget, and a stream window of at most a sixteenth of it; a release
// returns the share, twice is harmless, and a budget with less than 1 MiB free refuses.
func TestBudget_QUICAdmission(t *testing.T) {
	const mib = 1 << 20
	b := NewBudget(64 * mib)
	w1, release1, err := b.AdmitQUIC()
	if err != nil || w1.Conn != 4*mib || w1.Stream != mib/4 { // a sixteenth of 64 MiB
		t.Fatalf("first session: %+v %v", w1, err)
	}
	w2, release2, err := b.AdmitQUIC()
	if err != nil || w2.Conn != 60*mib/16 || w2.Stream != w2.Conn/16 {
		t.Fatalf("second session: %+v %v", w2, err)
	}
	release1()
	release1()                                     // twice is harmless
	if want := uint64(w2.Conn); b.Used() != want { //nolint:gosec // G115: a test window
		t.Fatalf("used %d after a release, want %d", b.Used(), want)
	}
	release2()
	if b.Used() != 0 {
		t.Fatalf("used %d after both ended", b.Used())
	}
	var releases []func()
	for {
		w, release, err := b.AdmitQUIC()
		if errors.Is(err, ErrBudget) {
			break
		}
		if err != nil || w.Conn < mib || w.Stream != w.Conn/16 {
			t.Fatalf("session %d: %+v %v", len(releases)+1, w, err)
		}
		if b.Used() > 64*mib {
			t.Fatalf("the reservations exceed the budget: %d", b.Used())
		}
		releases = append(releases, release)
		if len(releases) > 1000 {
			t.Fatal("no end to admission")
		}
	}
	if len(releases) == 0 {
		t.Fatal("nothing was admitted")
	}
	releases[0]()
	if _, release, err := b.AdmitQUIC(); err != nil {
		t.Fatalf("a freed share was not admitted again: %v", err)
	} else {
		release()
	}
}

// TestBudget_QUICAndH2Share: QUIC and h2 sessions draw on one budget, so each shrinks what is left
// for the other and finally refuses it.
func TestBudget_QUICAndH2Share(t *testing.T) {
	const mib = 1 << 20
	b := NewBudget(32 * mib)
	wq, releaseQ, err := b.AdmitQUIC()
	if err != nil || wq.Conn != 2*mib {
		t.Fatalf("QUIC: %+v %v", wq, err)
	}
	wh, releaseH, err := b.AdmitH2(DefaultH2Windows())
	if err != nil || wh.Conn != 30*mib/16 {
		t.Fatalf("h2 beside QUIC: %+v %v", wh, err)
	}
	if b.Used() != uint64(wq.Conn+wh.Conn) { //nolint:gosec // G115: a test window
		t.Fatalf("used %d", b.Used())
	}
	releaseQ()
	releaseH()
	if b.Used() != 0 {
		t.Fatalf("used %d after both ended", b.Used())
	}
	full := NewBudget(mib - 1)
	if _, _, err := full.AdmitQUIC(); !errors.Is(err, ErrBudget) {
		t.Fatalf("a budget below 1 MiB admitted QUIC: %v", err)
	}
}
