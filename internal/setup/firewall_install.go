// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// InstallFirewall is what the install script and an operator run after the boot file of a gateway
// or all-in-one names the firewall (docs/10-operations.md, "Host firewall helper"): it reads the
// boot file in the host's etc directory and does the plan's firewall step but for enabling the
// units, which the script does. The service user must exist.
func InstallFirewall(ctx context.Context, h Host, role string, noUnit bool) (Result, error) {
	h.defaults()
	if !h.IsRoot() {
		return Result{}, errRoot
	}
	var g config.Gateway
	path := filepath.Join(h.Paths.Etc, role+".yaml")
	switch role {
	case "gateway":
		if err := config.Load(path, &g); err != nil {
			return Result{}, err
		}
	case "all-in-one":
		var a config.AllInOne
		if err := config.Load(path, &a); err != nil {
			return Result{}, err
		}
		g = a.Gateway()
	default:
		return Result{}, fmt.Errorf("a %s has no firewall to hand to rpmgr: only a gateway and an all-in-one have", role)
	}
	if !g.Firewall.On() {
		return Result{}, fmt.Errorf("%s has no firewall.backend: ufw; add it, or use rpmgr setup --firewall ufw", path)
	}
	var r Result
	return r, installFirewall(ctx, h, boundsOf(g), noUnit, false, &r)
}
