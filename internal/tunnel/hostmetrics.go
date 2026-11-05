// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"errors"
	"net"

	"github.com/prometheus/client_golang/prometheus"
)

// desiredUDPBuffer is the UDP buffer size quic-go asks for, and warns below
// [F quic-go v0.63.0 sys_conn_buffers_nonopenbsd.go:5, sys_conn.go:56-75].
const desiredUDPBuffer = 7 << 20

// Tuning is the host tuning status of a QUIC socket, for `rpmgr diag transport`.
type Tuning struct {
	GSO                       bool // quic-go sends with GSO on it
	ReceiveBuffer, SendBuffer int  // its buffers in bytes, as the kernel reports them; 0 if unknown
	BufferLow                 bool // a buffer is below what quic-go asks for
}

// bufferSetter is what a UDP socket offers to ask for buffer sizes, as *net.UDPConn does.
type bufferSetter interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// requestBuffers asks for the buffer sizes quic-go asks for on its socket, which the kernel caps
// at net.core.rmem_max and wmem_max: a socket nothing asked yet shows the default, not the cap.
// A refusal is not an error here: the kernel's answer is read back afterwards.
func requestBuffers(pc net.PacketConn) {
	if b, ok := pc.(bufferSetter); ok {
		_ = b.SetReadBuffer(desiredUDPBuffer)
		_ = b.SetWriteBuffer(desiredUDPBuffer)
	}
}

// TuningOf reads the tuning status of pc, a socket of the diagnosis that nothing has asked for
// buffers yet: it asks for what quic-go asks for first, so that it reports a buffer low only where
// the kernel caps that request. RegisterHostMetrics reads the role's own socket as it is.
func TuningOf(pc net.PacketConn) Tuning {
	requestBuffers(pc)
	t := Tuning{GSO: gsoEnabled(pc), BufferLow: udpBufferLow(pc)}
	t.ReceiveBuffer, t.SendBuffer = udpBuffers(pc)
	return t
}

// RegisterHostMetrics registers the host tuning status of pc, the packet conn of the role's QUIC
// transport (docs/03-connections.md, "Host tuning applied by the installer"): whether quic-go
// sends with GSO on it, and whether its buffers stay below what quic-go asks for, which makes
// quic-go log its buffer-size warning. Both are read from the socket at each scrape.
func RegisterHostMetrics(reg prometheus.Registerer, pc net.PacketConn) error {
	gauge := func(name, help string, f func() bool) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, func() float64 {
			if f() {
				return 1
			}
			return 0
		})
	}
	return errors.Join(
		reg.Register(gauge("rpmgr_quic_gso_enabled", "1 if quic-go sends with GSO on the QUIC socket.", func() bool { return gsoEnabled(pc) })),
		reg.Register(gauge("rpmgr_quic_udp_buffer_warning", "1 if a UDP buffer of the QUIC socket is below the 7 MiB quic-go asks for.",
			func() bool { return udpBufferLow(pc) })),
	)
}
