// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/handoff"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func loopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestListeners_Adopt: a listener the old process handed over is taken instead of bound, for the
// address as it was bound, and anything else is bound afresh.
func TestListeners_Adopt(t *testing.T) {
	handed := loopback(t)
	ap := netip.MustParseAddrPort(handed.Addr().String())
	var asked []netip.AddrPort
	l := &listeners{log: quiet(), take: func(a netip.AddrPort) (net.Listener, bool, error) {
		asked = append(asked, a)
		if a == ap {
			return handed, true, nil
		}
		return nil, false, nil
	}}

	got, err := l.listen("tcp", handed.Addr().String())
	if err != nil || got != handed {
		t.Fatalf("handed-over address: %v, %v", got, err)
	}

	// A wildcard address is looked for as [::], then 0.0.0.0, and bound when neither was handed.
	free := loopback(t)
	port := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()
	asked = nil
	fresh, err := l.listen("http", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	if len(asked) != 2 || asked[0].Addr() != netip.IPv6Unspecified() || asked[1].Addr() != netip.IPv4Unspecified() {
		t.Errorf("asked %v", asked)
	}

	// Not an address the hand-off can name: a host name, port 0 and garbage are bound, or fail,
	// as without a hand-off, and nothing is asked.
	asked = nil
	if ln, err := l.listen("tcp", "localhost:0"); err != nil {
		t.Errorf("localhost:0: %v", err)
	} else {
		_ = ln.Close()
	}
	if _, err := l.listen("tcp", "no-port"); err == nil {
		t.Error("an address without a port was accepted")
	}
	if len(asked) != 0 {
		t.Errorf("asked %v for an address it cannot name", asked)
	}
}

// TestListeners_AdoptFails: an error from the hand-off fails the listener rather than binding a
// second one, which the old process's would shadow.
func TestListeners_AdoptFails(t *testing.T) {
	boom := errors.New("boom")
	l := &listeners{log: quiet(), take: func(netip.AddrPort) (net.Listener, bool, error) { return nil, true, boom }}
	if _, err := l.listen("admin", "127.0.0.1:9"); !errors.Is(err, boom) || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("got %v", err)
	}
	if len(l.open) != 0 {
		t.Errorf("remembered %d listeners after a failure", len(l.open))
	}
}

// TestListeners_Sockets: the sockets handed over are the open listeners, by name; a closed one,
// such as a removed route's, is left out and forgotten.
func TestListeners_Sockets(t *testing.T) {
	l := &listeners{log: quiet()}
	a, err := l.listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.listen(routeName(8080), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	socks, err := l.sockets()
	if err != nil || len(socks) != 2 || socks[0].Name != "tcp" || socks[1].Name != "route-8080" {
		t.Fatalf("sockets %v, %v", socks, err)
	}
	closeSockets(socks)
	_ = b.Close()
	socks, err = l.sockets()
	if err != nil || len(socks) != 1 || socks[0].Name != "tcp" {
		t.Fatalf("after closing one: %v, %v", socks, err)
	}
	closeSockets(socks)
	if len(l.open) != 1 {
		t.Errorf("%d listeners remembered, want 1", len(l.open))
	}
}

// TestListeners_StartRefused: a hand-off whose binary does not pass the rule of 04 starts nothing
// and leaves the listeners open: the test binary is not root's.
func TestListeners_StartRefused(t *testing.T) {
	l := &listeners{log: quiet(), link: handoff.NewLink(nil, func(string) string { return "" }, nil)}
	ln, err := l.listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if _, err := l.start(context.Background()); !errors.Is(err, handoff.ErrRefused) {
		t.Fatalf("got %v, want a refusal", err)
	}
	if c, err := net.Dial("tcp", ln.Addr().String()); err != nil {
		t.Errorf("the old listener stopped serving: %v", err)
	} else {
		_ = c.Close()
	}
}

// TestListeners_Ready: after a plain start the gateway is ready when its listeners are up: systemd
// is told and the trigger begins, once.
func TestListeners_Ready(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify")
	srv, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	begun := 0
	link := handoff.NewLink(nil, func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return sock
		}
		return ""
	}, func() { begun++ })
	l := &listeners{log: quiet(), link: link}
	for range 2 {
		if err := l.ready(context.Background(), link, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 64)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := srv.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("notification %q, %v", buf[:n], err)
	}
	if begun != 1 {
		t.Errorf("trigger begun %d times", begun)
	}
}

// TestListeners_ReadyFails: a systemd that cannot be told fails the start rather than going on
// unannounced under Type=notify.
func TestListeners_ReadyFails(t *testing.T) {
	link := handoff.NewLink(nil, func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return filepath.Join(t.TempDir(), "nobody-listens")
		}
		return ""
	}, func() { t.Error("the trigger began after a failed notification") })
	l := &listeners{log: quiet(), link: link}
	if err := l.ready(context.Background(), link, nil, nil); err == nil || !strings.Contains(err.Error(), "hand-off") {
		t.Fatalf("got %v", err)
	}
}

// TestTCPRoutes_ListenHook: a route's port comes from the Listen hook, with the address the route
// would bind; an error from it makes the route not ready and is retried, as a busy port is.
func TestTCPRoutes_ListenHook(t *testing.T) {
	ln := loopback(t)
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	var fail atomic.Bool
	var mu sync.Mutex
	var addrs []string
	routes := NewTCPRoutes(TCPOptions{Host: "127.0.0.1", Logger: quiet(), Listen: func(p uint16, addr string) (net.Listener, error) {
		mu.Lock()
		addrs = append(addrs, addr)
		mu.Unlock()
		if fail.Load() {
			return nil, errors.New("not handed over")
		}
		return ln, nil
	}})
	t.Cleanup(routes.Close)
	fail.Store(true)
	st := routes.Apply([]TCPRoute{{ID: "rt_1", Port: port}})
	if len(st) != 1 || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT {
		t.Fatalf("status %v", st)
	}
	fail.Store(false)
	routes.rebind()
	if st := routes.Status(); len(st) != 0 {
		t.Fatalf("still not ready: %v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))); len(addrs) < 2 || addrs[0] != want {
		t.Errorf("addresses %v, want %s first", addrs, want)
	}
}

// TestListeners_ReadyWaitsForControlPlane: a process a hand-off started whose control plane never
// gets ready does not report ready, so the old process kills it at the readiness window and serves
// on; and it closes nothing it was handed.
func TestListeners_ReadyWaitsForControlPlane(t *testing.T) {
	begun := false
	link := handoff.NewLink(nil, func(string) string { return "" }, func() { begun = true })
	l := &listeners{log: quiet(), link: link}
	rested := false
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	var polls int
	err := l.ready(ctx, link, func() []handoff.Entry { rested = true; return nil }, func(context.Context) error {
		polls++
		return errors.New("no control session")
	})
	if err != nil || begun || rested || polls < 2 {
		t.Fatalf("err %v, begun %v, rested %v, polls %d", err, begun, rested, polls)
	}
}
