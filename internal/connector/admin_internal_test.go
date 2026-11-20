// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// holder holds a free loopback address, as an old process holds the admin listener.
func holder(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, ln.Addr().String()
}

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// noneHandedOver is the take of a hand-off whose old process handed nothing over (0.3.0, 0.4.0).
func noneHandedOver(netip.AddrPort) (net.Listener, bool, error) { return nil, false, nil }

// listenAsync runs listen in the background and returns its result.
func listenAsync(ctx context.Context, a *adminListener, addr string) <-chan error {
	got := make(chan error, 1)
	go func() {
		ln, err := a.listen(ctx, addr)
		if ln != nil {
			_ = ln.Close()
		}
		got <- err
	}()
	return got
}

// TestAdminListener_PlainStart: after a plain start an address in use is an error at once, as
// before; a free one is bound.
func TestAdminListener_PlainStart(t *testing.T) {
	_, addr := holder(t)
	a, err := newAdminListener(addr, nil, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := a.listen(context.Background(), addr); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("address in use: %v, want EADDRINUSE", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("a plain start waited %v for the address", d)
	}
	ln, err := a.listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free address: %v", err)
	}
	_ = ln.Close()
	if a.adopted() {
		t.Fatal("a plain start adopted a listener")
	}
}

// TestAdminListener_Adopts: the listener the old process handed over is taken at its address and
// served; no new one is bound.
func TestAdminListener_Adopts(t *testing.T) {
	old, addr := holder(t)
	want := netip.MustParseAddrPort(addr)
	var asked []netip.AddrPort
	take := func(ap netip.AddrPort) (net.Listener, bool, error) {
		asked = append(asked, ap)
		if ap != want {
			return nil, false, nil
		}
		return old, true, nil
	}
	a, err := newAdminListener(addr, take, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if !a.adopted() || len(asked) != 1 {
		t.Fatalf("adopted %v, asked %v", a.adopted(), asked)
	}
	ln, err := a.listen(context.Background(), addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if ln.Addr().String() != addr {
		t.Fatalf("listens on %s, want the handed-over %s", ln.Addr(), addr)
	}
}

// TestAdminListener_TakeFails: a handed-over socket that is no listener ends the start.
func TestAdminListener_TakeFails(t *testing.T) {
	broken := errors.New("not a listener")
	take := func(netip.AddrPort) (net.Listener, bool, error) { return nil, true, broken }
	if _, err := newAdminListener("127.0.0.1:7383", take, quietLog()); !errors.Is(err, broken) {
		t.Fatalf("got %v, want %v", err, broken)
	}
}

// TestAdminListener_OldReleaseLetsGo: an old process of an earlier release handed nothing over and
// holds the address: the new process waits, without failing, and binds it once it is free (#1187).
func TestAdminListener_OldReleaseLetsGo(t *testing.T) {
	old, addr := holder(t)
	a, err := newAdminListener(addr, noneHandedOver, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	a.retry = 10 * time.Millisecond
	got := listenAsync(context.Background(), a, addr)
	select {
	case err := <-got:
		t.Fatalf("returned while the old process held the address: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = old.Close() // the old process exits
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("after the old process let go: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not bind the freed address")
	}
}

// TestAdminListener_SomebodyElseHolds: once the old process has exited, an address still in use is
// somebody else's, and the error is reported, not waited out.
func TestAdminListener_SomebodyElseHolds(t *testing.T) {
	_, addr := holder(t)
	a, err := newAdminListener(addr, noneHandedOver, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	a.retry = 10 * time.Millisecond
	got := listenAsync(context.Background(), a, addr)
	time.Sleep(50 * time.Millisecond)
	a.gone()
	a.gone() // twice is harmless
	select {
	case err := <-got:
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("got %v, want EADDRINUSE", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("kept waiting after the old process exited")
	}
}

// TestAdminListener_ContextEnds: a process that ends while it waits for the address returns.
func TestAdminListener_ContextEnds(t *testing.T) {
	_, addr := holder(t)
	a, err := newAdminListener(addr, noneHandedOver, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := listenAsync(ctx, a, addr)
	cancel()
	select {
	case err := <-got:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("kept waiting after the context ended")
	}
}

// TestAdminListener_HandOverAndRetire: the old process hands over the listener it serves, and
// once retired its server ends as a shutdown while the duplicate keeps the address.
func TestAdminListener_HandOverAndRetire(t *testing.T) {
	a, err := newAdminListener("127.0.0.1:0", nil, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if s, err := a.sockets(); err != nil || len(s) != 0 {
		t.Fatalf("before listening: %v, %d sockets", err, len(s))
	}
	ln, err := a.listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.sockets()
	if err != nil || len(s) != 1 || s[0].Name != "admin" {
		t.Fatalf("sockets: %v, %+v", err, s)
	}
	dup, err := net.FileListener(s[0].File)
	_ = s[0].File.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dup.Close() }()
	if dup.Addr().String() != ln.Addr().String() {
		t.Fatalf("handed over %s, serves %s", dup.Addr(), ln.Addr())
	}

	a.retire()
	if _, err := ln.Accept(); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("after retiring: %v, want http.ErrServerClosed", err)
	}
	// The new process's copy still answers on the address.
	go func() {
		if c, err := net.Dial("tcp", dup.Addr().String()); err == nil {
			_ = c.Close()
		}
	}()
	c, err := dup.Accept()
	if err != nil {
		t.Fatalf("the handed-over copy: %v", err)
	}
	_ = c.Close()

	// A listen that completes after the hand-off gives the address up again.
	if _, err := a.listen(context.Background(), "127.0.0.1:0"); err == nil {
		t.Fatal("listened after retiring")
	}
}
