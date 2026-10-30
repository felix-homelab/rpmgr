// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// stallAge is the age the session tests inject; the rule's ticker runs every second, so a stream
// that is not stalled by the time the fill ends cannot be reset before the test looks.
const stallAge = 1500 * time.Millisecond

// peerAge is the age after which the connector's rule acts: never in a test, whose peer ends are
// plain writers that nobody reads, which a healthy relay's would be waiting in Read.
const peerAge = time.Hour

// stallEnv is a data session of one transport whose receiving ends are watched by the
// stalled-stream rule: gw is the gateway's session, whose streams the tests stall.
type stallEnv struct {
	gw, con tunnel.Session
	gc, cc  tunnel.Stream // the session control stream, at the gateway and at the connector
	// open opens a stream whose gateway end g is watched and whose connector end c writes to it.
	open func(t *testing.T) (g, c tunnel.Stream)
	// half is how many stalled streams hold half the connection window as the rule counts them
	// (the stream window is a sixteenth of the connection window on QUIC, and set by the test on
	// h2, where one stalled stream is enough in the tests that need it).
	half int
}

type stallTransport struct {
	name string
	// new returns a session whose rule assumes the given windows; QUIC uses them as the
	// assumption (quic-go does not tell the real ones), HTTP/2 as the windows it advertises.
	new func(t *testing.T, stream, conn int) stallEnv
}

var stallTransports = []stallTransport{
	{"h2", func(t *testing.T, stream, conn int) stallEnv {
		w := tunnel.H2Windows{Stream: stream, Conn: conn}
		gw, con, gc, cc := h2SessionWindows(t, tunnel.WithStallAge(w, stallAge), tunnel.WithStallAge(w, peerAge))
		return stallEnv{gw: gw, con: con, gc: gc, cc: cc,
			open: func(t *testing.T) (tunnel.Stream, tunnel.Stream) { return h2Open(t, gw, con) }, half: 0}
	}},
	{"quic", func(t *testing.T, stream, conn int) stallEnv {
		p := newPeers(t)
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tr := &quic.Transport{Conn: pc}
		// The session is admitted with window conn and a stream window of a sixteenth of it, from a
		// budget of sixteen times that (the stream window argument is that sixteenth).
		budget := func(age time.Duration) *tunnel.Budget {
			return tunnel.BudgetWithStallAge(tunnel.NewBudget(uint64(conn)*16), age) //nolint:gosec // G115: a test window
		}
		ln, err := tunnel.ListenQUIC(tr, p.gateway, budget(stallAge))
		if err != nil {
			t.Fatal(err)
		}
		cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctr := &quic.Transport{Conn: cpc}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		con, err := tunnel.DialQUIC(ctx, ctr, pc.LocalAddr(), p.connector, budget(peerAge))
		if err != nil {
			t.Fatal(err)
		}
		gw, err := ln.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = con.Close(); _ = gw.Close(); _ = ln.Close(); _ = tr.Close(); _ = ctr.Close() })
		cc, err := con.Control(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cc.Write([]byte("hello")); err != nil { // a QUIC stream is visible to the peer with its first byte
			t.Fatal(err)
		}
		gc, err := gw.Control(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(gc, make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		return stallEnv{gw: gw, con: con, gc: gc, cc: cc, half: 8, open: func(t *testing.T) (tunnel.Stream, tunnel.Stream) {
			t.Helper()
			c, err := con.OpenStream(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte{'x'}); err != nil {
				t.Fatal(err)
			}
			g := accept(t, gw)
			if _, err := io.ReadFull(g, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			return g, c
		}}
	}},
}

// eventually fails the test unless ch delivers a nil error within d.
func eventually(t *testing.T, what string, ch <-chan error, d time.Duration) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(d):
		t.Fatalf("%s: still blocked after %v", what, d)
	}
}

// wasReset reports that a peer sees the stream reset: its reads fail with an error that is not
// io.EOF and its writes fail, rather than the stream hanging.
func wasReset(t *testing.T, name string, st tunnel.Stream) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if _, err := io.Copy(io.Discard, st); err == nil {
			done <- errors.New("read ended with EOF, not a reset")
			return
		}
		for range 1000 {
			if _, err := st.Write(make([]byte, 4<<10)); err != nil {
				done <- nil
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		done <- errors.New("writes still succeed")
	}()
	eventually(t, name+" is reset", done, 10*time.Second)
}

// TestFlowControl_StalledStreamsDoNotFreezeSession, on both transports: streams whose gateway-side
// reader stopped fill the connection window, so the session freezes; within the stall age the
// session's own rule resets the oldest of them until the rest hold at most half the window, and
// other streams and the session control stream flow again. Nothing but the session runs the rule.
func TestFlowControl_StalledStreamsDoNotFreezeSession(t *testing.T) {
	for _, tr := range stallTransports {
		t.Run(tr.name, func(t *testing.T) {
			// h2: four streams of 900 KiB fill the 3 MiB window, whose threshold is 1.5 MiB: three are reset.
			// QUIC: a 2 MiB connection window with 128 KiB stream windows; sixteen streams fill it,
			// the threshold is 1 MiB: eight are reset.
			n, each, stream, conn, wantResets := 4, 900<<10, 1<<20, 3<<20, 3
			if tr.name == "quic" {
				n, each, stream, conn, wantResets = 16, 128<<10, 0, 2<<20, 8
			}
			env := tr.new(t, stream, conn)
			// The probe stream waits in Read, as a healthy relay does: it holds nothing and is
			// never counted.
			pg, pc := env.open(t)
			probed := make(chan error, 1)
			go func() { _, err := io.ReadFull(pg, make([]byte, 64<<10)); probed <- err }()

			var gs, cs []tunnel.Stream
			for range n {
				g, c := env.open(t)
				gs, cs = append(gs, g), append(cs, c)
				go func() { _, _ = c.Write(make([]byte, each)) }() // the gateway never reads these
				time.Sleep(20 * time.Millisecond)                  // a distinct age for each
			}
			time.Sleep(500 * time.Millisecond) // the fill reaches the window
			wrote := make(chan error, 1)
			go func() { _, err := pc.Write(make([]byte, 64<<10)); wrote <- err }()
			select {
			case err := <-probed:
				t.Fatalf("the session did not freeze (%v); the test proves nothing", err)
			case <-time.After(300 * time.Millisecond):
			}
			if got := tunnel.StallResets(env.gw); got != 0 {
				t.Fatalf("%d streams reset before the stall age passed", got)
			}

			eventually(t, "the probe stream after the resets", probed, 15*time.Second)
			eventually(t, "the probe write", wrote, 5*time.Second)
			if got := tunnel.StallResets(env.gw); got != wantResets {
				t.Fatalf("%d streams reset, want %d", got, wantResets)
			}
			for i := range wantResets { // the oldest were reset: both ends see it
				wasReset(t, "stalled stream "+string(rune('0'+i)), cs[i])
				if _, err := gs[i].Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) {
					t.Errorf("stalled stream %d: its gateway end reads %v, want a reset", i, err)
				}
			}
			// The newest was left alone, and so were the probe and the control stream, which the
			// rule does not watch: watched are the survivors and the probe.
			if got, want := tunnel.StallWatched(env.gw), n-wantResets+1; got != want {
				t.Errorf("%d streams watched, want %d: a reset stream stays registered, or the control stream is watched", got, want)
			}
			for name, pair := range map[string][2]tunnel.Stream{"gateway to connector": {env.gc, env.cc}, "connector to gateway": {env.cc, env.gc}} {
				if _, err := pair[0].Write([]byte("ping")); err != nil {
					t.Fatalf("control stream, %s: %v", name, err)
				}
				if _, err := io.ReadFull(pair[1], make([]byte, 4)); err != nil {
					t.Fatalf("control stream, %s: %v", name, err)
				}
			}
		})
	}
}

// TestFlowControl_PausedClientNotResetWithoutPressure, on both transports: a reader that pauses for
// longer than the stall age holds data, but without window pressure it is not reset, and every
// byte arrives once it reads again; readers that wait for data never count as stalled.
func TestFlowControl_PausedClientNotResetWithoutPressure(t *testing.T) {
	for _, tr := range stallTransports {
		t.Run(tr.name, func(t *testing.T) {
			env := tr.new(t, 16<<20, 256<<20)
			paused, c := env.open(t)
			payload := make([]byte, 2<<20)
			for i := range payload {
				payload[i] = byte(i * 7)
			}
			go func() { _, _ = c.Write(payload); _ = c.CloseWrite() }()
			for range 20 { // idle streams wait in Read with nothing to read
				g, _ := env.open(t)
				go func() { _, _ = g.Read(make([]byte, 1)) }()
			}
			time.Sleep(2*stallAge + time.Second) // at least two checks after the stall age passed
			if got := tunnel.StallResets(env.gw); got != 0 {
				t.Fatalf("%d streams reset without window pressure", got)
			}
			got, err := io.ReadAll(paused)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("the paused reader got %d of %d bytes: %v", len(got), len(payload), err)
			}
		})
	}
}

// TestFlowControl_ResetStreamEndsRelayOnBothEnds, on both transports: the gateway's relay is blocked
// writing to a target that does not read, which stalls its stream's reader; the rule resets the
// stream, the relay ends, closing the target connection with a reset, and the peer's end of the
// stream sees the reset instead of a hang.
func TestFlowControl_ResetStreamEndsRelayOnBothEnds(t *testing.T) {
	for _, tr := range stallTransports {
		t.Run(tr.name, func(t *testing.T) {
			env := tr.new(t, 256<<10, 256<<10) // h2: one stalled stream is above half the window; QUIC: the 1 MiB floor
			// On QUIC the rule resets only once more streams are stalled than fit into half the
			// window. The relay's stream is younger than the first batch and older than the second,
			// so it is among the oldest streams above that count.
			for range env.half {
				env.open(t)
			}
			g, c := env.open(t)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			far := make(chan net.Conn, 1)
			go func() {
				if conn, err := ln.Accept(); err == nil {
					far <- conn
				}
			}()
			near, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			target := <-far // never read until the relay is over
			defer func() { _ = target.Close() }()

			relayed := make(chan struct{})
			go func() { tunnel.Relay(g, near); close(relayed) }()
			go func() { // the peer writes until the stream fails, far more than the buffers hold
				buf := make([]byte, 64<<10)
				for {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}()
			time.Sleep(500 * time.Millisecond) // the target's buffers fill and the relay blocks
			for range env.half {
				env.open(t)
			}
			select {
			case <-relayed:
			case <-time.After(20 * time.Second):
				t.Fatal("the relay of a stalled, reset stream never ended")
			}
			if got := tunnel.StallResets(env.gw); got == 0 {
				t.Fatal("no stream was reset")
			}
			_ = target.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.Copy(io.Discard, target); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("the target saw %v, want a connection reset", err)
			}
			wasReset(t, "the peer's stream", c)
		})
	}
}

// TestStalls_SessionEndStopsWatcher, on both transports: ending the session ends the goroutine that
// runs the rule, and streams that ended are no longer watched.
func TestStalls_SessionEndStopsWatcher(t *testing.T) {
	runners := func() int {
		buf := make([]byte, 1<<20)
		return bytes.Count(buf[:runtime.Stack(buf, true)], []byte("tunnel.(*Stalls).Run"))
	}
	for _, tr := range stallTransports {
		t.Run(tr.name, func(t *testing.T) {
			base := runners()
			env := tr.new(t, 1<<20, 3<<20)
			if got := runners(); got <= base {
				t.Fatalf("%d goroutines run the rule, %d before the session: the session does not run it", got, base)
			}
			for range 20 { // streams that end orderly leave nothing behind
				g, c := env.open(t)
				_, _ = c.Write([]byte("bye"))
				_ = c.CloseWrite()
				_ = g.CloseWrite()
				for _, st := range []tunnel.Stream{g, c} {
					if _, err := io.Copy(io.Discard, st); err != nil {
						t.Fatal(err)
					}
				}
				_ = g.Close()
				_ = c.Close()
			}
			if gw, con := tunnel.StallWatched(env.gw), tunnel.StallWatched(env.con); gw != 0 || con != 0 {
				t.Fatalf("%d and %d streams watched after all ended, want none", gw, con)
			}
			_ = env.gw.Close()
			_ = env.con.Close()
			deadline := time.Now().Add(10 * time.Second)
			for runners() > base {
				if time.Now().After(deadline) {
					t.Fatalf("%d goroutines still run the rule after the session ended, %d before it", runners(), base)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// TestStalls_OldestFirst: of stalled streams, the oldest are reset first, and a stream that ended
// is not counted.
func TestStalls_OldestFirst(t *testing.T) {
	gw, con, _, _ := h2Session(t, tunnel.DefaultH2Windows())
	stalls := tunnel.NewStalls(1<<20, 4<<20, time.Millisecond)
	var watched []tunnel.Stream
	var peers []tunnel.Stream
	for range 4 {
		g, c := h2Open(t, gw, con)
		watched = append(watched, stalls.Watch(g))
		peers = append(peers, c)
		time.Sleep(5 * time.Millisecond)
	}
	_ = watched[0].Close() // ended: not counted
	time.Sleep(10 * time.Millisecond)
	// Three stalled streams hold 3 MiB, the threshold is 2 MiB: one reset, the oldest one left.
	if n := stalls.Check(time.Now()); n != 1 {
		t.Fatalf("%d resets, want 1", n)
	}
	if _, err := io.ReadAll(peers[1]); err == nil {
		t.Fatal("the oldest stalled stream was not the one reset")
	}
}

// TestH2_AdmissionUnderBudget: h2 sessions are admitted against the window budget (03, "Memory
// bound"; D124): at most 64 MiB each, a sixteenth of the free budget once that is less, never
// less than 1 MiB, so about eighty fit in the default budget; the stream window is a sixteenth of
// the connection window; the reservations never exceed the budget; released ones are free again.
func TestH2_AdmissionUnderBudget(t *testing.T) {
	const mib = 1 << 20
	b := tunnel.NewBudget(tunnel.DefaultWindowBudget)
	full := tunnel.DefaultH2Windows()
	var releases []func()
	var windows []int
	for {
		w, release, err := b.AdmitH2(full)
		if errors.Is(err, tunnel.ErrBudget) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if w.Stream != w.Conn/16 || w.Conn < mib || w.Conn > 64*mib {
			t.Fatalf("session %d: %+v", len(windows)+1, w)
		}
		if n := len(windows); n > 0 && w.Conn > windows[n-1] {
			t.Fatalf("session %d got %d, more than the one before (%d)", n+1, w.Conn, windows[n-1])
		}
		if b.Used() > tunnel.DefaultWindowBudget {
			t.Fatalf("the reservations exceed the budget: %d", b.Used())
		}
		windows = append(windows, w.Conn)
		releases = append(releases, release)
		if len(windows) > 1000 {
			t.Fatal("no end to admission")
		}
	}
	// The first session gets the cap, 64 MiB with a 4 MiB stream window; the second a sixteenth
	// of the 960 MiB left; the tenth still more than 32 MiB (a stream window above 2 MiB).
	if windows[0] != 64*mib || windows[1] != 60*mib || windows[9] < 32*mib {
		t.Fatalf("first windows %v", windows[:10])
	}
	if n := len(windows); n < 75 || n > 85 {
		t.Fatalf("%d sessions admitted under the default budget, want about 80", n)
	}
	if last := windows[len(windows)-1]; last != mib {
		t.Fatalf("the last session got %d, want the 1 MiB floor", last)
	}
	if free := tunnel.DefaultWindowBudget - b.Used(); free >= mib {
		t.Fatalf("refused with %d bytes free", free)
	}
	releases[0]()
	releases[0]() // twice is harmless
	again, releaseAgain, err := b.AdmitH2(full)
	if err != nil || again.Conn < 4*mib || again.Conn >= 5*mib {
		t.Fatalf("after one release: %+v %v, want a sixteenth of the 64 MiB freed and the rest", again, err)
	}
	for _, release := range releases[1:] {
		release()
	}
	if b.Used() != uint64(again.Conn) { //nolint:gosec // G115: a window is positive
		t.Fatalf("after every other release: used %d", b.Used())
	}
	releaseAgain()
	if w, _, err := b.AdmitH2(full); err != nil || w != (tunnel.H2Windows{Stream: 4 * mib, Conn: 64 * mib}) {
		t.Fatalf("in an empty budget again: %+v %v", w, err)
	}
}

// TestH2_AdmissionSmallWants: a session that asks for less than the cap or the floor gets what it
// asks for; a budget below the floor admits nothing, and one of exactly the floor one session.
func TestH2_AdmissionSmallWants(t *testing.T) {
	const mib = 1 << 20
	small := tunnel.H2Windows{Stream: 32 << 10, Conn: 512 << 10}
	if w, _, err := tunnel.NewBudget(tunnel.DefaultWindowBudget).AdmitH2(small); err != nil || w != small {
		t.Fatalf("a small want: %+v %v", w, err)
	}
	if _, _, err := tunnel.NewBudget(mib - 1).AdmitH2(tunnel.DefaultH2Windows()); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("below the floor: %v", err)
	}
	b := tunnel.NewBudget(mib)
	if w, _, err := b.AdmitH2(tunnel.DefaultH2Windows()); err != nil || w.Conn != mib || w.Stream != mib/16 {
		t.Fatalf("a budget of exactly the floor: %+v %v", w, err)
	}
	if _, _, err := b.AdmitH2(tunnel.DefaultH2Windows()); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("a second session in a full budget: %v", err)
	}
}

// TestH2_StalledStreamsHoldAtMostTheAdmittedWindow: the memory a session can hold is its admitted
// connection window: streams whose reader stops take no more than that, however much the peer
// writes, so the budget bounds memory under stalled streams.
func TestH2_StalledStreamsHoldAtMostTheAdmittedWindow(t *testing.T) {
	b := tunnel.NewBudget(40 << 20)
	w, release, err := b.AdmitH2(tunnel.DefaultH2Windows())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if w.Conn != 2<<20+512<<10 { // a sixteenth of 40 MiB
		t.Fatalf("admitted %+v", w)
	}
	gw, con, _, _ := h2Session(t, w)
	var sent atomic.Int64
	for range 4 {
		_, c := h2Open(t, gw, con) // the gateway never reads these streams
		go func() {
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Write(buf)
				sent.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(time.Second)
	if got := sent.Load(); got > int64(w.Conn)+int64(4*w.Stream) {
		t.Fatalf("the peer wrote %d bytes into stalled streams, more than the %d MiB window allows", got, w.Conn>>20)
	}
}

// nullStream is a stream that reads without waiting.
type nullStream struct{ tunnel.Stream }

func (nullStream) Read(p []byte) (int, error) { return len(p), nil }

// BenchmarkStalls_Read is the cost the rule adds to a read of a watched stream, with many other
// streams of the session watched at the same time: it must not grow with their number.
func BenchmarkStalls_Read(b *testing.B) {
	for _, n := range []int{1, 1000} {
		b.Run(strconv.Itoa(n)+"streams", func(b *testing.B) {
			s := tunnel.NewStalls(16<<20, 256<<20, 0)
			for range n {
				s.Watch(nullStream{})
			}
			b.RunParallel(func(pb *testing.PB) {
				st := s.Watch(nullStream{})
				buf := make([]byte, 1)
				for pb.Next() {
					_, _ = st.Read(buf)
				}
			})
		})
	}
}

// TestH2_ResetOfUnacceptedStreamReturnsWindow: the connector's rule resets streams that nobody
// accepted, and their unread bytes return to the connection window at once, instead of staying
// until the stream is accepted: a second stream blocked on the exhausted window flows again.
func TestH2_ResetOfUnacceptedStreamReturnsWindow(t *testing.T) {
	w := tunnel.H2Windows{Stream: 256 << 10, Conn: 256 << 10}
	// Only the connector's rule acts: the gateway's ends are plain writers nobody reads.
	gw, con, _, _ := h2SessionWindows(t, tunnel.WithStallAge(w, peerAge), tunnel.WithStallAge(w, 300*time.Millisecond))
	open := func() tunnel.Stream {
		g, err := gw.OpenStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	first := open()
	if _, err := first.Write(make([]byte, 200<<10)); err != nil { // fits; held unread by the connector
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	second := open()
	wrote := make(chan error, 1)
	go func() { _, err := second.Write(make([]byte, 200<<10)); wrote <- err }() // above the 56 KiB left
	select {
	case err := <-wrote:
		t.Fatalf("the window was not exhausted (%v); the test proves nothing", err)
	case <-time.After(300 * time.Millisecond):
	}
	// Nothing accepts a stream. Whether the rule resets the second stream as well or only the
	// first, the write ends only if a reset returned credit, and the first one is reset.
	select {
	case <-wrote:
	case <-time.After(15 * time.Second):
		t.Fatal("a reset of a stream nobody accepted did not return its bytes to the connection window")
	}
	if got := tunnel.StallResets(con); got == 0 {
		t.Fatal("no stream reset")
	}
	if _, err := io.Copy(io.Discard, first); err == nil {
		t.Fatal("the unaccepted stream's gateway end does not see the reset")
	}
}
