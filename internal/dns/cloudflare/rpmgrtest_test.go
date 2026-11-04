// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package cloudflare_test

import (
	"context"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// NewForTest, which other packages' tests use, reaches the fake over verified TLS.
func TestNewForTest(t *testing.T) {
	fake := cftest.New(t, "token-for-the-fake")
	c, err := cloudflare.NewForTest(cloudflare.Config{Token: secret.New("token-for-the-fake")}, fake.URL(), fake.RootCAs())
	if err != nil {
		t.Fatal(err)
	}
	if info, err := c.Verify(context.Background()); err != nil || !info.Active() {
		t.Fatalf("%+v, %v", info, err)
	}
}
