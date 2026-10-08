// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/testseed"
	"github.com/felix-homelab/rpmgr/internal/token"
)

func seed(t *testing.T, boot string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Main(context.Background(), commands(), append([]string{"testseed"}, args...), &cli.Env{Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string { return map[string]string{"RPMGR_CONFIG": boot}[k] }})
	if code != cli.ExitOK {
		t.Fatalf("testseed %s: exit %d: %s", strings.Join(args, " "), code, errOut.String())
	}
	return strings.TrimSpace(out.String())
}

// TestTestseed: the seeding command writes gateways, tokens, routes, their changes and revocations
// into an initialised controller's database, each as a new revision.
func TestTestseed(t *testing.T) {
	dir := t.TempDir()
	boot, db := filepath.Join(dir, "controller.yaml"), filepath.Join(dir, "lib", "controller.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: "+db+"}\nkek: {source: file, path: "+
		filepath.Join(dir, "kek")+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Init(context.Background(), controller.InitOptions{ConfigPath: boot, Getenv: func(string) string { return "" }}); err != nil {
		t.Fatal(err)
	}
	tok := seed(t, boot, "gateway", "--group", "eu", "--name", "gw1", "--endpoint", "gw1.test:443", "--endpoint", "gw1.test:8443")
	if k, err := token.Parse(tok); err != nil || k != token.Enrollment {
		t.Fatalf("gateway token %q: %v", tok, err)
	}
	if k, err := token.Parse(seed(t, boot, "connector-token", "--uses", "2")); err != nil || k != token.Enrollment {
		t.Fatalf("connector token: %v", err)
	}

	st, err := store.OpenSQLite(context.Background(), db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	sys := storetest.SystemCtx(t)
	c := st.Client()
	gw := c.Gateway.Query().Where(gateway.Name("gw1")).OnlyX(sys)
	if len(gw.TunnelEndpoints) != 2 {
		t.Fatalf("gateway %+v", gw)
	}
	o := c.Org.Query().Where(org.Slug(testseed.OrgSlug)).OnlyX(sys)
	con := c.Connector.Create().SetOrgID(o.ID).SetName("con1").SetSpiffeID("spiffe://x/con1").SetPubkeySha256("x").SaveX(sys)
	seed(t, boot, "route", "--name", "echo", "--group", "eu", "--port", "20001", "--connector", "con1", "--target", "10.0.0.5:7",
		"--transport", "h2", "--idle", "90s")
	rt := c.Route.Query().Where(route.Name("echo")).OnlyX(sys)
	targets := c.RouteTarget.Query().Where(routetarget.RouteID(rt.ID)).AllX(sys)
	tcp := c.RouteTCP.Query().Where(routetcp.RouteID(rt.ID)).WithPort().OnlyX(sys)
	if *rt.Transport != "h2" || len(targets) != 1 || targets[0].ConnectorID != con.ID || targets[0].Port != 7 ||
		tcp.IdleTimeoutSeconds != 90 || tcp.Edges.Port.Port != 20001 {
		t.Fatalf("route %+v, targets %+v, tcp %+v", rt, targets, tcp)
	}
	seed(t, boot, "route-update", "--name", "echo", "--idle", "120s", "--transport", "quic", "--enabled", "false")
	rt = c.Route.Query().Where(route.Name("echo")).OnlyX(sys)
	tcp = c.RouteTCP.Query().Where(routetcp.RouteID(rt.ID)).OnlyX(sys)
	if *rt.Transport != "quic" || rt.Enabled || tcp.IdleTimeoutSeconds != 120 {
		t.Fatalf("updated route %+v, tcp %+v", rt, tcp)
	}
	seed(t, boot, "revoke", "--kind", "connector", "--name", "con1")
	if n := c.RevokedIdentity.Query().CountX(sys); n != 1 {
		t.Fatalf("%d revoked identities", n)
	}
	entries, err := revlog.Read(filepath.Join(filepath.Dir(db), "revocations.log"))
	if err != nil || len(entries) != 1 || entries[0].Kind != revlog.IdentityRevoked {
		t.Fatalf("revocation log %v %v", entries, err)
	}
	if seq := c.ConfigRevision.Query().CountX(sys); seq != 4 {
		t.Fatalf("%d revisions, want one per configuration write", seq)
	}

	var errOut bytes.Buffer
	code := cli.Main(context.Background(), commands(), []string{"testseed", "--config", boot, "revoke", "--kind", "controller", "--name", "x"},
		&cli.Env{Stdout: &bytes.Buffer{}, Stderr: &errOut, Getenv: func(string) string { return "" }})
	if code == cli.ExitOK {
		t.Fatal("revoking a controller")
	}
}
