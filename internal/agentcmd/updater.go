// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/update"
	"github.com/felix-homelab/rpmgr/internal/version"
)

// Updater is `rpmgr updater`: the root-owned updater that rpmgr-update.service runs
// (docs/04-security.md, "Over-the-air updates"). It is named updater, so that it never reads as
// `rpmgr update <kind>` (D51). variant is the build's, full or connector, which install records.
// The group and both commands are plumbing for the install scripts and rpmgr-update.service: they
// run, but help does not list them (D151).
func Updater(variant string) *cli.Command {
	return &cli.Command{Name: "updater", Summary: "the root-owned updater of a Linux host",
		Hidden: true, Sub: []*cli.Command{updaterApply(), updaterInstall(variant)}}
}

// isRoot reports whether the command runs as root; tests replace it.
var isRoot = func() bool { return os.Geteuid() == 0 }

// updaterInstall is `rpmgr updater install`, which the install scripts run with the binary they
// installed (docs/10-operations.md, "Who installs the updater"): it records the installation with
// this build's variant, initialises or raises the state from the release's verified manifest, and
// writes the updater's units. The scripts enable them.
func updaterInstall(variant string) *cli.Command {
	in := update.Installed{Install: update.Install{Variant: variant}}
	var state, etc, unitDir string
	var roles cli.List
	var noUnits bool
	return &cli.Command{
		Name:    "install",
		Summary: "record this installation for the updater, raise its floor and seq, and write its units, as root",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&state, "state", update.StateDir, "the updater's own directory: install.json, state.json")
			fs.StringVar(&in.Method, "method", "script", "how rpmgr was installed")
			fs.StringVar(&in.Path, "path", "/usr/local/bin/rpmgr", "the installed binary")
			fs.Var(&roles, "role", "a role of this host, besides those recorded and those with a boot file; repeat for more")
			fs.StringVar(&etc, "etc", BootDir, "the boot files, whose roles are recorded")
			fs.Uint64Var(&in.Seq, "seq", 0, "the seq of the installed release's verified manifest (default: none; a missing state starts at this binary's version)")
			fs.StringVar(&in.Floor, "floor", "", "the installed release's version, the floor, with --seq")
			fs.StringVar(&unitDir, "units", "/etc/systemd/system", "where the units rpmgr-update.path and rpmgr-update.service go")
			fs.BoolVar(&noUnits, "no-units", false, "write no units, as on a host without systemd")
		},
		Run: func(_ context.Context, env *cli.Env, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("updater install takes no arguments")
			}
			if (in.Seq != 0) != (in.Floor != "") {
				return cli.Usagef("--seq and --floor go together")
			}
			if in.Seq == 0 {
				in.Floor = version.Get().Version // a development build's is no release, which leaves the state missing
			}
			if !isRoot() {
				return errors.New("run it as root: the updater trusts only files root owns")
			}
			in.Roles = append(bootRoles(etc), roles...)
			rec, st, err := update.Record(state, in)
			if err != nil {
				return err
			}
			p := func(format string, a ...any) { _, _ = fmt.Fprintf(env.Stdout, format+"\n", a...) }
			recorded := "none yet"
			if len(rec.Roles) > 0 {
				recorded = strings.Join(rec.Roles, ", ")
			}
			p("Recorded in %s: the %s build at %s, roles: %s.", filepath.Join(state, "install.json"), rec.Variant, rec.Path, recorded)
			switch {
			case st.Floor == "":
				p("No updater state: this development build has no release version, so the updater refuses every release.")
			case st.Seq == 0:
				p("Updater state: version floor %s; the first update records the manifest seq.", st.Floor)
			default:
				p("Updater state: manifest seq %d, version floor %s.", st.Seq, st.Floor)
			}
			if noUnits {
				return nil
			}
			written, err := update.WriteUnits(unitDir, rec.Path)
			if err != nil {
				return err
			}
			p("Wrote %s.", strings.Join(written, " and "))
			return nil
		},
	}
}

// bootRoles are the roles whose boot file is in dir.
func bootRoles(dir string) []string {
	var roles []string
	for _, r := range update.Roles {
		if fileExists(filepath.Join(dir, r+".yaml")) {
			roles = append(roles, r)
		}
	}
	return roles
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
			a.Control = func(role string) (update.ControlPlane, error) { return controlPlane(BootDir, role) }
			if err := a.Apply(ctx); err != nil {
				return err
			}
			if !a.Reported() {
				_, err := fmt.Fprintln(env.Stdout, "Nothing to install: no release is staged, or the staged one is installed already.")
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

// readyClient asks the admin listeners on this host: never through a proxy, and a redirect is an
// answer, not followed.
var readyClient = &http.Client{
	Transport:     &http.Transport{Proxy: nil},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
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
	case "controller":
		var c config.Controller
		if err := config.Load(path, &c); err != nil {
			return err
		}
		admin = c.Listen.Admin
	case "all-in-one":
		var a config.AllInOne
		if err := config.Load(path, &a); err != nil {
			return err
		}
		admin = a.Listen.Admin
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
	resp, err := readyClient.Do(req)
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

// controlPlane names the boot file of the controller or all-in-one and its database driver. The
// driver is read from the file itself, not through config.Load, so that a PostgreSQL controller
// is refused for what it is and not for a boot file that does not load.
func controlPlane(bootDir, role string) (update.ControlPlane, error) {
	path := filepath.Join(bootDir, role+".yaml")
	b, err := os.ReadFile(path) //nolint:gosec // G304: the role's boot file
	if err != nil {
		return update.ControlPlane{}, err
	}
	var f struct {
		Database struct {
			Driver string `yaml:"driver"`
			DSN    string `yaml:"dsn"`
		} `yaml:"database"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return update.ControlPlane{}, fmt.Errorf("%s: %w", path, err)
	}
	if f.Database.Driver == "" {
		f.Database.Driver = "sqlite" // the default of config
	}
	cp := update.ControlPlane{Config: path, Driver: f.Database.Driver}
	if cp.Driver != "sqlite" {
		return cp, nil
	}
	if f.Database.DSN == "" {
		f.Database.DSN = "/var/lib/rpmgr/controller.db" // the default of config
	}
	// The backup runs as the owner of the state directory, which is the service user. It is read
	// from the directory's own entry, not from anything inside it.
	if cp.UID, cp.GID, err = update.OwnerOf(filepath.Dir(f.Database.DSN)); err != nil {
		return cp, fmt.Errorf("the state directory of %s: %w", path, err)
	}
	return cp, nil
}
