// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/memnet"
)

// TestRun_ClosesTunnelsOnFailure: a gateway that fails to start closes its in-memory tunnel
// listener, so that all-in-one's connector fails its dial at once instead of waiting for it.
func TestRun_ClosesTunnelsOnFailure(t *testing.T) {
	l := memnet.NewListener()
	var cfg config.Gateway
	cfg.IdentityDir, cfg.StateDir = filepath.Join(t.TempDir(), "no-identity"), t.TempDir()
	if err := gateway.Run(context.Background(), gateway.RunOptions{Config: cfg, Tunnels: l}); err == nil {
		t.Fatal("a gateway without an identity started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := l.Dial(ctx, ""); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a dial after the failure: %v, want net.ErrClosed", err)
	}
}
