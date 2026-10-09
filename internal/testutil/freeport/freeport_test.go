// SPDX-License-Identifier: Apache-2.0

package freeport_test

import (
	"net"
	"strconv"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/testutil/freeport"
)

// TestPort: the port is below the ephemeral range and can be listened on for TCP and UDP.
func TestPort(t *testing.T) {
	for range 20 {
		p := freeport.Port(t)
		if p < 20000 || p > 32767 {
			t.Fatalf("port %d outside 20000-32767", p)
		}
		ln, err := net.Listen("tcp", freeport.Addr(t))
		if err != nil {
			t.Fatal(err)
		}
		_ = ln.Close()
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			t.Fatal(err)
		}
		_ = pc.Close()
	}
}
