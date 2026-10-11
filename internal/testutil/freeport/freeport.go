// SPDX-License-Identifier: Apache-2.0

// Package freeport hands tests a port to listen on later. It picks ports below Linux's ephemeral
// range (32768-60999 by default), which the kernel gives to ":0" listeners and to the source ports
// of outgoing connections: a port that was free a moment ago in that range is soon taken by
// another test of the same run, and the later listen fails with "address already in use".
//
// A port is free when Port checks it, but the test listens on it later: a gateway binds a route's
// port only once its snapshot arrives. Port therefore never hands out a port twice in one process,
// and, where the platform has flock, holds a lock on the port until the test ends, which every
// test binary of the run honours.
package freeport

import (
	"crypto/rand"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
)

// The ports handed out: below the default ephemeral range, above the well-known services.
const (
	low  = 20000
	high = 32767
)

var (
	mu     sync.Mutex
	handed = map[int]bool{} // the ports this process handed out
)

// Port returns a port that is free now for TCP and UDP on every interface, that no other test of
// this process got, and that no other test binary of the run holds until this test ends.
func Port(t testing.TB) int {
	t.Helper()
	for range 100 {
		n, err := rand.Int(rand.Reader, big.NewInt(high-low+1))
		if err != nil {
			t.Fatal(err)
		}
		if port := low + int(n.Int64()); take(t, port) {
			return port
		}
	}
	t.Fatal("freeport: no free port")
	return 0
}

// take reserves port for t if this process has not handed it out, no other process holds its
// lock, and it is free for TCP and UDP.
func take(t testing.TB, port int) bool {
	mu.Lock()
	defer mu.Unlock()
	if handed[port] {
		return false
	}
	unlock, ok := lock(port)
	if !ok {
		return false
	}
	if !free(port) {
		unlock()
		return false
	}
	handed[port] = true
	t.Cleanup(unlock)
	return true
}

// free reports whether port can be listened on for TCP and UDP on every interface.
func free(port int) bool {
	addr := net.JoinHostPort("", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr) //nolint:gosec // G102: checks the port on every interface, as tests may listen on any
	if err != nil {
		return false
	}
	pc, err := net.ListenPacket("udp", addr) //nolint:gosec // G102: as above
	_ = ln.Close()
	if err != nil {
		return false
	}
	_ = pc.Close()
	return true
}

// Addr returns a loopback address with a port from Port.
func Addr(t testing.TB) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(Port(t)))
}
