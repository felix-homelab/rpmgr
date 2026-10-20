// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/update"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// Updater is `rpmgr updater`: the root-owned updater that rpmgr-update.service runs
// (docs/04-security.md, "Over-the-air updates"). It is named updater, so that it never reads as
// `rpmgr update <kind>` (D51).
func Updater() *cli.Command {
	return &cli.Command{Name: "updater", Summary: "the root-owned updater of a Linux host", Sub: []*cli.Command{updaterApply()}}
}

func updaterApply() *cli.Command {
	a := update.Applier{Services: update.Systemd{}}
	return &cli.Command{
		Name:    "apply",
		Summary: "install the release the agent staged, as root, and roll back if a role is not ready",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&a.Staged, "staged", "/var/lib/rpmgr/update", "the directory the agent stages a release in")
			fs.StringVar(&a.State, "state", "/var/lib/rpmgr-update", "the updater's own directory: install.json, state.json, staging/")
			fs.StringVar(&a.Policy, "policy", "/etc/rpmgr/policy.yaml", "the local policy file")
			fs.StringVar(&a.Status, "status", update.StatusFile, "where the outcome is written for the agent")
		},
		Run: func(ctx context.Context, env *cli.Env, _ []string) error {
			a.Previous = version.Get().Version
			a.Ready = func(ctx context.Context, role string) error { return ready(ctx, BootDir, role) }
			if err := a.Apply(ctx); err != nil {
				return err
			}
			st, err := update.ReadStatus(a.Status)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(env.Stdout, "Installed rpmgr %s; every role is ready.\n", st.Version)
			return err
		},
	}
}

// ready asks a role's admin listener, from its boot file, whether it is ready.
func ready(ctx context.Context, bootDir, role string) error {
	path := filepath.Join(bootDir, role+".yaml")
	var admin string
	switch role {
	case "gateway":
		var g config.Gateway
		if err := config.Load(path, &g); err != nil {
			return err
		}
		admin = g.Listen.Admin
	case "connector":
		var c config.Connector
		if err := config.Load(path, &c); err != nil {
			return err
		}
		admin = c.Listen.Admin
	default:
		return fmt.Errorf("no updatable role %q", role)
	}
	if admin == "" {
		return errors.New("its admin listener is off, so its readiness cannot be checked")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+admin+"/readyz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("nothing answers on %s", admin)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s", strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "not ready:")))
	}
	return nil
}
