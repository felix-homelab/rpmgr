// SPDX-License-Identifier: Apache-2.0

package allinone

import (
	"context"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// SetStarted makes Run call f once it has taken SIGHUP over, until the test ends.
func SetStarted(t testing.TB, f func()) {
	old := started
	started = f
	t.Cleanup(func() { started = old })
}

// SetNamesFollowed makes Run call f with the names its connector counts as the host's own each time
// it follows a change of the gateway group's public hostnames, until the test ends.
func SetNamesFollowed(t testing.TB, f func([]string)) {
	old := namesFollowed
	namesFollowed = f
	t.Cleanup(func() { namesFollowed = old })
}

// Unusable is why the built-in agent whose identity is in dir, which should name want, enrolls
// again at now, or "".
func Unusable(ctx context.Context, c *ent.Client, dir string, want pki.Identity, now time.Time, grace time.Duration) (string, error) {
	a := builtIn{role: "gateway", dir: dir}
	if id, err := agent.Load(dir); err == nil {
		a.leaf = id.Certificate.Leaf
	}
	return a.unusable(ctx, c, want.TrustDomain, want, now, grace)
}
