// SPDX-License-Identifier: Apache-2.0

package allinone

import (
	"context"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// SetStarted makes Run call f once it has taken SIGHUP over, until the test ends.
func SetStarted(t testing.TB, f func()) {
	old := started
	started = f
	t.Cleanup(func() { started = old })
}

// Prepare runs what Run does with the agents' identities once the controller has migrated the
// database: replacing agents whose identities are revoked, and making the tokens of those that
// enroll again; it enrolls nothing.
func Prepare(ctx context.Context, cfg config.AllInOne) error {
	l, err := readLocal(cfg)
	if err != nil {
		return err
	}
	return l.prepare(ctx, cfg, time.Now())
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
