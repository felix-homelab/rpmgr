// SPDX-License-Identifier: Apache-2.0

// Package freeport hands tests a port to listen on later. It picks ports below Linux's ephemeral
// range (32768-60999 by default), which the kernel gives to ":0" listeners and to the source ports
// of outgoing connections: a port that was free a moment ago in that range is soon taken by
// another test of the same run, and the later listen fails with "address already in use".
package freeport

import (
	"crypto/rand"
	"math/big"
	"net"
	"strconv"
	"testing"
)

// The ports handed out: below the default ephemeral range, above the well-known services.
const (
	low  = 20000
	high = 32767
)

// Port returns a port that is free now for TCP and UDP on every interface, picked at random so
// that test binaries running in parallel rarely pick the same.
func Port(t testing.TB) int {
	t.Helper()
	for range 100 {
		n, err := rand.Int(rand.Reader, big.NewInt(high-low+1))
		if err != nil {
			t.Fatal(err)
		}
		port := low + int(n.Int64())
		addr := net.JoinHostPort("", strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr) //nolint:gosec // G102: checks the port on every interface, as tests may listen on any
		if err != nil {
			continue
		}
		pc, err := net.ListenPacket("udp", addr) //nolint:gosec // G102: as above
		_ = ln.Close()
		if err != nil {
			continue
		}
		_ = pc.Close()
		return port
	}
	t.Fatal("freeport: no free port")
	return 0
}

// Addr returns a loopback address with a port from Port.
func Addr(t testing.TB) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(Port(t)))
}
