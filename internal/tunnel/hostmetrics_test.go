// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"net"
	"testing"
)

// fakeBuffers is a packet conn that records the buffer sizes asked for.
type fakeBuffers struct {
	net.PacketConn
	read, write int
}

func (f *fakeBuffers) SetReadBuffer(n int) error  { f.read = n; return nil }
func (f *fakeBuffers) SetWriteBuffer(n int) error { f.write = n; return nil }

// TestRequestBuffers: both buffers are asked for what quic-go asks for; a conn that cannot be asked
// is left alone.
func TestRequestBuffers(t *testing.T) {
	f := &fakeBuffers{}
	requestBuffers(f)
	if f.read != desiredUDPBuffer || f.write != desiredUDPBuffer {
		t.Fatalf("asked for %d and %d, want %d", f.read, f.write, desiredUDPBuffer)
	}
	requestBuffers(struct{ net.PacketConn }{}) // no setters: no panic
}
