// SPDX-License-Identifier: Apache-2.0

//go:build unix

package kms

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// N6: a FIFO in place of a credential file is refused; it must not hang the client.
func TestFIFOCredentialFileIsRefused(t *testing.T) {
	f := newFakeTransit(t)
	fifo := filepath.Join(t.TempDir(), "token")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no FIFOs here:", err)
	}
	c, _, _ := testClient(t, f, func(cfg *Config) { cfg.TokenFile = fifo })
	done := make(chan error, 1)
	go func() { _, err := c.Wrap(ctxA, dk, aadA); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Wrap = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the client hangs on a FIFO")
	}
}
