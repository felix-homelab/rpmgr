// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// inspect returns what a descriptor is, as the manifest names it: "tcp" for a listening inet
// stream socket, "udp" for an inet datagram socket, and its local address. Anything else, a
// connected stream socket included, is an error.
func inspect(fd int) (network string, addr netip.AddrPort, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", addr, fmt.Errorf("descriptor %d: %w", fd, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return "", addr, fmt.Errorf("descriptor %d is no socket", fd)
	}
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return "", addr, fmt.Errorf("descriptor %d: %w", fd, err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return "", addr, fmt.Errorf("descriptor %d: %w", fd, err)
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		addr = netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)) //nolint:gosec // G115: a port
	case *unix.SockaddrInet6:
		addr = netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port)) //nolint:gosec // G115: a port
	default:
		return "", addr, fmt.Errorf("descriptor %d is no inet socket", fd)
	}
	switch typ {
	case unix.SOCK_STREAM:
		listening, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
		if err != nil || listening != 1 {
			return "", addr, fmt.Errorf("descriptor %d is no listening socket", fd)
		}
		return "tcp", addr, nil
	case unix.SOCK_DGRAM:
		return "udp", addr, nil
	}
	return "", addr, fmt.Errorf("descriptor %d has socket type %d", fd, typ)
}

// isSocket reports whether fd is an open socket.
func isSocket(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK
}

// closeFD closes a descriptor that no *os.File holds.
func closeFD(fd int) { _ = unix.Close(fd) }

// errNotify is returned when systemd's notify socket cannot be reached.
var errNotify = errors.New("handoff: systemd's notify socket")

// notify sends state to systemd's notify socket at addr ($NOTIFY_SOCKET); without one it does
// nothing.
func notify(addr, state string) error {
	if addr == "" {
		return nil
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:] // an abstract socket
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: %w", errNotify, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Sendto(fd, []byte(state), 0, &unix.SockaddrUnix{Name: addr}); err != nil {
		return fmt.Errorf("%w: %w", errNotify, err)
	}
	return nil
}
