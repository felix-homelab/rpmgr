// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// The upgrade test (docs/12-testing-and-quality.md, "Upgrade test"; docs/10-operations.md,
// "Upgrades and version skew"). E2E_UPGRADE_FROM names the earlier release as a git revision, such
// as the tag v0.1.0; the set-up starts every node on the rpmgrtest build of that revision, and
// TestUpgrade moves them to this tree's build in the documented order, under live traffic.
// E2E_UPGRADE_FROM_VERSION and E2E_UPGRADE_TO_VERSION set the versions the two builds report; by
// default the tag's version, else 0.1.0, and the next minor release.

var (
	upgradeFrom = os.Getenv("E2E_UPGRADE_FROM")
	fromVersion = upgradeVersion("E2E_UPGRADE_FROM_VERSION", tagVersion(upgradeFrom))
	toVersion   = upgradeVersion("E2E_UPGRADE_TO_VERSION", nextMinor(fromVersion))
)

// roleNodes are the nodes that run an rpmgr role.
var roleNodes = []string{"ctl", "gw1", "gw2", "con1", "con2"}

var (
	binMu     sync.Mutex
	fromNodes = map[string]bool{} // nodes that still run the earlier release
)

// fromBin is where an earlier release's binary lies in a node; its name keeps the process name
// rpmgr, which signal looks for.
const fromBin = "/var/lib/rpmgr/from/rpmgr"

// binOf is the rpmgr binary that node runs: the image's, or the earlier release's until the node
// is upgraded.
func binOf(node string) string {
	binMu.Lock()
	defer binMu.Unlock()
	if fromNodes[node] {
		return fromBin
	}
	return "rpmgr"
}

// upgraded makes node run this tree's build from its next start on.
func upgraded(node string) {
	binMu.Lock()
	defer binMu.Unlock()
	delete(fromNodes, node)
}

func upgradeVersion(env, fallback string) string {
	if upgradeFrom == "" {
		return ""
	}
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}

// tagVersion is the version of a release tag vX.Y.Z, else 0.1.0.
func tagVersion(rev string) string {
	if m := regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`).FindStringSubmatch(rev); m != nil {
		return m[1]
	}
	return "0.1.0"
}

// nextMinor is the first release of the minor after v.
func nextMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "0.2.0"
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "0.2.0"
	}
	return parts[0] + "." + strconv.Itoa(minor+1) + ".0"
}

// versionFlags are the linker flags that make a build report version v; none for "".
func versionFlags(v string) string {
	if v == "" {
		return ""
	}
	return "-X github.com/felix-homelab/rpmgr/internal/version.Version=" + v
}

// buildFrom builds the rpmgrtest binary of the earlier release from its git revision, outside the
// working tree, and puts it into every role node; nothing without E2E_UPGRADE_FROM.
func buildFrom() error {
	if upgradeFrom == "" {
		return nil
	}
	src, err := os.MkdirTemp("", "rpmgr-upgrade-from-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(src) }()
	archive := exec.Command("sh", "-c", `git -C "$1" archive "$2" | tar -x -C "$3"`, "sh", filepath.Join(here, "../.."), upgradeFrom, src) //nolint:gosec // G204: the test's own git revision
	if out, err := archive.CombinedOutput(); err != nil {
		return fmt.Errorf("git archive %s: %w\n%s", upgradeFrom, err, out)
	}
	bin := filepath.Join(run, "from", "rpmgr")
	build := exec.Command("go", "build", "-trimpath", "-tags", "rpmgrtest", "-ldflags", versionFlags(fromVersion), "-o", bin, "./cmd/rpmgr") //nolint:gosec // G204: the test's own build
	build.Dir = src
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("go build of %s: %w\n%s", upgradeFrom, err, out)
	}
	b, err := os.ReadFile(bin) //nolint:gosec // G304: the test's own build output
	if err != nil {
		return err
	}
	binMu.Lock()
	defer binMu.Unlock()
	for _, node := range roleNodes {
		if err := os.MkdirAll(filepath.Join(run, node, "from"), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(run, node, "from", "rpmgr"), b, 0o755); err != nil { //nolint:gosec // G306: a binary the container runs
			return err
		}
		fromNodes[node] = true
	}
	return nil
}

// traffic opens new connections through the routes, one after the other, through the gateways in
// service, and records every one that fails: no new connection may fail during an upgrade.
type traffic struct {
	mu      sync.Mutex
	gws     map[string]bool
	ports   []int
	opened  int
	failed  []string
	busy    sync.Mutex // held while a connection is under way
	stop    chan struct{}
	stopped chan struct{}
}

func startTraffic(ports []int) *traffic {
	tr := &traffic{gws: map[string]bool{"gw1": true, "gw2": true}, ports: ports, stop: make(chan struct{}), stopped: make(chan struct{})}
	go func() {
		defer close(tr.stopped)
		for i := 0; ; i++ {
			select {
			case <-tr.stop:
				return
			default:
			}
			tr.busy.Lock()
			tr.mu.Lock()
			var gws []string
			for gw, on := range tr.gws {
				if on {
					gws = append(gws, gw)
				}
			}
			tr.mu.Unlock()
			slices.Sort(gws)
			a := addr(gws[i%len(gws)], tr.ports[i%len(tr.ports)])
			err := client("check", "-addr", a, "-bytes", "65536")
			tr.busy.Unlock()
			tr.mu.Lock()
			tr.opened++
			if err != nil {
				tr.failed = append(tr.failed, fmt.Sprintf("%s %s: %v", time.Now().Format(time.TimeOnly), a, err))
			}
			tr.mu.Unlock()
		}
	}()
	return tr
}

// outOfService takes a gateway out of the rotation, as a load balancer would before it drains,
// and waits for the connection under way.
func (tr *traffic) outOfService(gw string, out bool) {
	tr.mu.Lock()
	tr.gws[gw] = !out
	tr.mu.Unlock()
	tr.busy.Lock() // waits for the connection under way
	defer tr.busy.Unlock()
}

func (tr *traffic) end() (int, []string) {
	close(tr.stop)
	<-tr.stopped
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.opened, tr.failed
}

// controllerDB opens the controller's database from the host, beside the running controller, as
// an administration command does.
func controllerDB(t *testing.T) (*store.DB, context.Context) {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), filepath.Join(run, "ctl", "controller.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sys, err := authz.System(context.Background(), "e2e-upgrade", "check the upgraded database",
		func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return db, sys
}

// upCertificate writes the certificate an http route of the upgrade test uploads.
func upCertificate(t *testing.T, name, host string) {
	t.Helper()
	crt, key, err := issue(host, host)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile("ctl", "route-"+name+".crt", crt); err != nil {
		t.Fatal(err)
	}
	if err := writeFile("ctl", "route-"+name+".key", key); err != nil {
		t.Fatal(err)
	}
}

// agentsOn waits until the four agents run version and have applied the configuration of the
// controller's epoch.
func agentsOn(t *testing.T, version string) {
	t.Helper()
	eventually(t, 90*time.Second, "every agent on "+version+" with the configuration applied", func() error {
		db, sys := controllerDB(t)
		defer func() { _ = db.Close() }()
		c := db.Client()
		live := c.AgentSession.Query().Where(agentsession.DisconnectedAtIsNil()).AllX(sys)
		epoch := c.Instance.GetX(sys, 1).DbEpoch
		var off []string
		for _, s := range live {
			st, err := c.AgentState.Get(sys, s.ID)
			switch {
			case s.AgentVersion != version:
				off = append(off, s.ID+" runs "+s.AgentVersion)
			case err != nil:
				off = append(off, s.ID+": "+err.Error())
			case st.AppliedDbEpoch != epoch || st.AppliedSeq != st.PushedSeq || st.AppliedSeq == 0:
				off = append(off, fmt.Sprintf("%s applied %s/%d, was sent %s/%d", s.ID, st.AppliedDbEpoch, st.AppliedSeq, st.PushedDbEpoch, st.PushedSeq))
			}
		}
		if len(live) != 4 || len(off) > 0 {
			return fmt.Errorf("%d live agents, want 4: %v", len(live), off)
		}
		return nil
	})
}

// TestUpgrade upgrades a running installation from the earlier release to this tree's build in
// the order of docs/10: the controller, after a backup, with its migrations; then each gateway,
// drained while the other serves; then each connector. Under it, new connections run through the
// routes the whole time and none may fail; connections held through the gateway that is not being
// upgraded must survive the controller and gateway upgrades, as a connection may break only when the
// connector process it runs through restarts; no byte may come back changed. The controller's
// database, with the routes, certificate and access rules the earlier release created, must migrate
// and keep them, and every agent must apply the configuration under the new version.
func TestUpgrade(t *testing.T) {
	if upgradeFrom == "" {
		t.Skip("set E2E_UPGRADE_FROM to the earlier release, such as v0.1.0")
	}
	t.Logf("upgrade from %s (%s) to this tree (%s)", upgradeFrom, fromVersion, toVersion)
	ports := map[string]int{"auto": 24001, "quic": 24002, "h2": 24003}
	const held, denied, udp = 24004, 24005, 24006
	var all []int
	for _, tr := range []string{"auto", "quic", "h2"} {
		addRoute(t, "upgrade-"+tr, ports[tr], tr, "con1", "con2")
		all = append(all, ports[tr])
	}
	addRoute(t, "upgrade-held", held, "auto", "con1", "con2")
	addRoute(t, "upgrade-denied", denied, "auto", "con1", "con2")
	if _, err := seed("access", "--route", "upgrade-denied", "--rule", "deny=172.30.0.30/32,fd00:30::30/128"); err != nil {
		t.Fatal(err)
	}
	if _, err := seed("udp-route", "--name", "upgrade-udp", "--port", strconv.Itoa(udp), "--target", svcHost+":7008",
		"--connector", "con1", "--connector", "con2"); err != nil {
		t.Fatal(err)
	}
	upCertificate(t, "upgrade-web", "upgrade.e2e.test")
	if _, err := seed("http-route", "--name", "upgrade-web", "--hostname", "upgrade.e2e.test", "--connector", "con1",
		"--connector", "con2", "--target", svcHost+":7080", "--cert-file", "/var/lib/rpmgr/route-upgrade-web.crt",
		"--key-file", "/var/lib/rpmgr/route-upgrade-web.key"); err != nil {
		t.Fatal(err)
	}
	served := func(what string) {
		t.Helper()
		for _, gw := range []string{"gw1", "gw2"} {
			for _, p := range append(slices.Clone(all), held) {
				eventually(t, 60*time.Second, fmt.Sprintf("%s: %d through %s", what, p, gw), func() error { return client("check", "-addr", addr(gw, p)) })
			}
			eventually(t, 60*time.Second, what+": the udp route through "+gw, func() error {
				return client("udp", "-addr", addr(gw, udp), "-sizes", "100,1200,3000", "-duration", "3s")
			})
			eventually(t, 60*time.Second, what+": the http route through "+gw, func() error {
				return client("http", "-addr", gw+":8443", "-url", "https://upgrade.e2e.test/u", "-expect", "upgrade.e2e.test /u")
			})
			if err := client("gone", "-addr", addr(gw, denied), "-duration", "5s"); err != nil {
				t.Errorf("%s: the route that denies the client through %s: %v", what, gw, err)
			}
		}
	}
	served("on " + fromVersion)
	agentsOn(t, fromVersion)
	db, sys := controllerDB(t)
	routes := db.Client().Route.Query().CountX(sys)
	_ = db.Close()

	tr := startTraffic(all)
	// holdThrough keeps a connection on the unchanged route through gw for d while f runs; it
	// must survive.
	holdThrough := func(gw, what string, d time.Duration, f func()) {
		t.Helper()
		done := background(func() error {
			return client("hold", "-addr", addr(gw, held), "-duration", d.String(), "-every", "500ms")
		})
		time.Sleep(2 * time.Second)
		start := time.Now()
		f()
		if took := time.Since(start); took > d {
			t.Logf("the %s took %s, longer than the connection held across it", what, took.Round(time.Second))
		}
		if err := <-done; err != nil {
			t.Errorf("a connection through %s across the %s: %v", gw, what, err)
		}
	}

	// 1. The controller, after a backup, with its migrations at start.
	holdThrough("gw2", "controller upgrade", 60*time.Second, func() {
		if _, err := in("ctl", binOf("ctl"), "backup", "--out", "/var/lib/rpmgr/before-upgrade.backup", "--config",
			"/var/lib/rpmgr/controller.yaml"); err != nil {
			t.Fatal(err)
		}
		if err := signal("ctl", "TERM"); err != nil {
			t.Fatal(err)
		}
		upgraded("ctl")
		if err := startRole("ctl", "controller"); err != nil {
			t.Fatal(err)
		}
		if err := ready("ctl", 7381); err != nil {
			t.Fatalf("the upgraded controller: %v", err)
		}
	})
	db, sys = controllerDB(t)
	dir, err := migrations.Dir(store.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := store.Pending(context.Background(), db, dir); err != nil || len(pending) > 0 {
		t.Errorf("the controller's database after the upgrade: %d migrations pending, %v", len(pending), err)
	}
	if n := db.Client().Route.Query().CountX(sys); n != routes {
		t.Errorf("%d routes after the migration, %d before", n, routes)
	}
	_ = db.Close()

	// 2. Each gateway, drained while the other one serves.
	for _, gw := range []string{"gw1", "gw2"} {
		other := map[string]string{"gw1": "gw2", "gw2": "gw1"}[gw]
		holdThrough(other, gw+" upgrade", 120*time.Second, func() {
			tr.outOfService(gw, true)
			if err := signal(gw, "TERM"); err != nil {
				t.Fatal(err)
			}
			upgraded(gw)
			if err := startRole(gw, "gateway"); err != nil {
				t.Fatal(err)
			}
			if err := ready(gw, 7382); err != nil {
				t.Fatalf("the upgraded %s: %v", gw, err)
			}
			for _, p := range all {
				eventually(t, 60*time.Second, fmt.Sprintf("%d through the upgraded %s", p, gw), func() error { return client("check", "-addr", addr(gw, p)) })
			}
			tr.outOfService(gw, false)
		})
	}

	// 3. Each connector; a connection held through it may break while it restarts.
	for _, con := range []string{"con1", "con2"} {
		if err := signal(con, "TERM"); err != nil {
			t.Fatal(err)
		}
		upgraded(con)
		if err := startRole(con, "connector"); err != nil {
			t.Fatal(err)
		}
		if err := ready(con, 7383); err != nil {
			t.Fatalf("the upgraded %s: %v", con, err)
		}
		time.Sleep(5 * time.Second) // its data sessions are up before the next one restarts
	}
	opened, failed := tr.end()
	t.Logf("%d new connections during the upgrade, %d failed", opened, len(failed))
	for _, f := range failed {
		t.Errorf("a new connection failed: %s", f)
	}

	agentsOn(t, toVersion)
	served("on " + toVersion)
}
