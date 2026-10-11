// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package freeport

import (
	"net"
	"strconv"
	"testing"
)

// TestTake: a port another holder has locked, as another test binary of the run does, is not
// handed out until it is unlocked; a port handed out once is never handed out again; a port that
// is not free is not handed out.
func TestTake(t *testing.T) {
	port := Port(t) // free, and handed out now
	if take(t, port) {
		t.Fatalf("port %d handed out twice", port)
	}

	// Another holder locks a free port: flock conflicts between two opens of the file, as between
	// two processes.
	other, unlock := 0, func() {}
	for p := low; p <= high && other == 0; p++ {
		mu.Lock()
		was := handed[p]
		mu.Unlock()
		if was {
			continue
		}
		u, ok := lock(p)
		if !ok {
			continue
		}
		if free(p) {
			other, unlock = p, u
		} else {
			u()
		}
	}
	if other == 0 {
		t.Skip("no free port to try")
	}
	if take(t, other) {
		t.Fatalf("port %d handed out while another holder locks it", other)
	}
	unlock()

	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(other)))
	if err != nil {
		t.Fatal(err)
	}
	if take(t, other) {
		t.Fatalf("port %d handed out while it is in use", other)
	}
	_ = ln.Close()
	if !take(t, other) {
		t.Fatalf("port %d not handed out once it is free and unlocked", other)
	}
}
