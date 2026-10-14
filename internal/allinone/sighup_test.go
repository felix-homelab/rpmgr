// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package allinone_test

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/allinone"
)

// TestAllInOne_SIGHUP: SIGHUP, which reloads the connector's local policy, does not end the
// process, neither before its roles run nor while they do.
func TestAllInOne_SIGHUP(t *testing.T) {
	h := newHost(t)
	h.init(t)
	hup := func() {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond) // a signal nobody took would have ended the test binary by now
	}
	allinone.SetStarted(t, hup)
	h.run(t)
	waitFor(t, "not ready", h.ready)
	hup()
	if !h.ready() {
		t.Fatal("not ready after SIGHUP")
	}
}
