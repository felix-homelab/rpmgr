// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestDrain_RoundTrip: a report reads back as written, to the second.
func TestDrain_RoundTrip(t *testing.T) {
	d := Drain{Conns: 12, Flows: 3, Sessions: 2, Since: time.Unix(1000, 0), Ends: time.Unix(1300, 0)}
	got, err := ParseDrain(d.String())
	if err != nil || got != d {
		t.Fatalf("%q read back as %+v, %v", d.String(), got, err)
	}
	if got, err := ParseDrain((Drain{Since: time.Unix(0, 0), Ends: time.Unix(0, 0)}).String()); err != nil || got.Conns != 0 {
		t.Fatalf("zeros: %+v, %v", got, err)
	}
}

// TestParseDrain_Invalid: a report of another shape, or with a negative or non-numeric field, is an
// error, so the new process shows nothing for it.
func TestParseDrain_Invalid(t *testing.T) {
	for _, s := range []string{"", "1 2 3", "1 2 3 4 5 6", "1 2 x 4 5", "-1 2 3 4 5", "1 2 3 4 99999999999999999999", "1,2,3,4,5"} {
		if d, err := ParseDrain(s); err == nil {
			t.Errorf("%q read as %+v", s, d)
		}
	}
}

// TestReportDrain: the old process reports at once, then at every interval, with the counts of the
// moment, and stops when the pipe breaks or ctx ends.
func TestReportDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var n atomic.Int64
	type got struct{ typ, reason string }
	sent := make(chan got, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ReportDrain(ctx, func(typ, reason string) error {
			sent <- got{typ, reason}
			if n.Load() >= 3 {
				return errors.New("the pipe is gone")
			}
			return nil
		}, 5*time.Millisecond, time.Unix(100, 0), time.Unix(400, 0), func() (int64, int64, int64) {
			c := n.Add(1)
			return c, 0, 1
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("it did not stop when the pipe broke")
	}
	close(sent)
	var all []Drain
	for g := range sent {
		if g.typ != MsgDrain {
			t.Fatalf("sent %q", g.typ)
		}
		d, err := ParseDrain(g.reason)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, d)
	}
	if len(all) != 3 || all[0].Conns != 1 || all[2].Conns != 3 || all[0].Ends.Unix() != 400 || all[0].Since.Unix() != 100 {
		t.Fatalf("reports %+v", all)
	}

	// ctx ending stops it, too.
	ctx2, cancel2 := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		ReportDrain(ctx2, func(string, string) error { return nil }, time.Hour, time.Now(), time.Now(), func() (int64, int64, int64) { return 0, 0, 0 })
		close(stopped)
	}()
	cancel2()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("it did not stop with its context")
	}
}

// TestWatch: the new process gets the old one's reports, passes the other messages on, skips a
// report it cannot read, and learns that the old process is gone from the pipe breaking; asking
// the old one to end arrives as MsgEnd.
func TestWatch(t *testing.T) {
	ours, theirs := net.Pipe()
	oldEnd, newEnd := newPipe(ours), newPipe(theirs)
	var drains []Drain
	var others []string
	errc := make(chan error, 1)
	go func() {
		errc <- Watch(newEnd, func(d Drain) { drains = append(drains, d) }, func(typ, reason string) { others = append(others, typ+":"+reason) })
	}()
	for _, m := range [][2]string{{MsgDrain, "1 2 3 4 5"}, {MsgDrain, "garbage"}, {"revoked", ""}, {MsgDrain, "6 0 0 4 5"}} {
		if err := oldEnd.Send(m[0], m[1]); err != nil {
			t.Fatal(err)
		}
	}
	_ = oldEnd.Close() // the old process exits
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Watch ended without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not end with the pipe")
	}
	if len(drains) != 2 || drains[0].Conns != 1 || drains[1].Conns != 6 || len(others) != 1 || others[0] != "revoked:" {
		t.Fatalf("drains %+v, others %v", drains, others)
	}

	a, b := net.Pipe()
	go func() { _ = EndOld(newPipe(a)) }()
	typ, _, err := newPipe(b).Recv()
	if err != nil || typ != MsgEnd {
		t.Fatalf("EndOld sent %q, %v", typ, err)
	}
}
