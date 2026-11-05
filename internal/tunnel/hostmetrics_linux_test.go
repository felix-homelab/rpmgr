// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tunnel

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func sysctl(t *testing.T, name string) int {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/core/" + name)
	if err != nil {
		t.Skipf("cannot read %s: %v", name, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Skipf("%s: %v", name, err)
	}
	return n
}

// TestTuningOf_AsksFirst: a fresh socket shows the default buffers, so TuningOf asks for quic-go's
// size first and warns only where the kernel caps the request (net.core.rmem_max and wmem_max;
// the kernel doubles what it grants) below it: honoured where the caps allow it, capped where not.
func TestTuningOf_AsksFirst(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	rmax, wmax := sysctl(t, "rmem_max"), sysctl(t, "wmem_max")
	got := TuningOf(pc)
	// What the kernel grants is twice the request, or twice the cap where the request is above it.
	wantRcv, wantSnd := 2*min(desiredUDPBuffer, rmax), 2*min(desiredUDPBuffer, wmax)
	if got.ReceiveBuffer != wantRcv || got.SendBuffer != wantSnd {
		t.Fatalf("buffers %d and %d, want %d and %d (caps %d and %d)", got.ReceiveBuffer, got.SendBuffer, wantRcv, wantSnd, rmax, wmax)
	}
	if want := wantRcv < desiredUDPBuffer || wantSnd < desiredUDPBuffer; got.BufferLow != want {
		t.Fatalf("BufferLow %v, want %v (caps %d and %d)", got.BufferLow, want, rmax, wmax)
	}
}
