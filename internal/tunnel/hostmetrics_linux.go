// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tunnel

import (
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// gsoEnabled reports whether quic-go uses GSO on pc, as it decides: Linux 5 or later, GSO not
// switched off by QUIC_GO_DISABLE_GSO, and UDP_SEGMENT readable on the socket
// [F quic-go v0.63.0 sys_conn_helper_linux.go:66-81].
func gsoEnabled(pc net.PacketConn) bool {
	var uts unix.Utsname
	if unix.Uname(&uts) != nil || kernelMajor(unix.ByteSliceToString(uts.Release[:])) < 5 {
		return false
	}
	if off, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_GSO")); err == nil && off {
		return false
	}
	ok := false
	_ = control(pc, func(fd int) {
		_, err := unix.GetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		ok = err == nil
	})
	return ok
}

// udpBufferLow reports whether the receive or the send buffer of pc is below desiredUDPBuffer.
func udpBufferLow(pc net.PacketConn) bool {
	rcv, snd := udpBuffers(pc)
	return rcv < desiredUDPBuffer || snd < desiredUDPBuffer
}

// udpBuffers returns the receive and send buffer sizes of pc; 0 for one that cannot be read.
func udpBuffers(pc net.PacketConn) (rcv, snd int) {
	_ = control(pc, func(fd int) {
		if n, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			rcv = n
		}
		if n, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil {
			snd = n
		}
	})
	return rcv, snd
}

func control(pc net.PacketConn, f func(fd int)) error {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return syscall.EINVAL
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	return raw.Control(func(fd uintptr) { f(int(fd)) }) //nolint:gosec // G115: a file descriptor fits in an int
}

// kernelMajor is the major version of a kernel release such as 6.18.33-microsoft-standard.
func kernelMajor(release string) int {
	n := 0
	for _, c := range release {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
