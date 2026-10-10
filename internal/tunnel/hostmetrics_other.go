// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package tunnel

import "net"

// gsoEnabled is false: quic-go uses GSO on Linux only.
func gsoEnabled(net.PacketConn) bool { return false }

// udpBufferLow is false: the installer tunes the buffers on Linux only, and nothing is known here.
func udpBufferLow(net.PacketConn) bool { return false }
