// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// TestDocumentedBootFiles parses the example boot files of docs/10-operations.md, so the documents
// and the code cannot drift apart.
func TestDocumentedBootFiles(t *testing.T) {
	doc, err := os.ReadFile("../../docs/10-operations.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```yaml\n(# /etc/rpmgr/(\\w[\\w-]*)\\.yaml\n.*?)```").FindAllStringSubmatch(string(doc), -1)
	seen := map[string]bool{}
	for _, b := range blocks {
		role, body := b[2], b[1]
		var f config.File
		switch role {
		case "controller":
			f = &config.Controller{}
		case "gateway":
			f = &config.Gateway{}
		case "connector":
			f = &config.Connector{}
		default:
			continue
		}
		if err := config.Parse([]byte(body), f); err != nil {
			t.Errorf("the documented %s.yaml: %v", role, err)
		}
		seen[role] = true
	}
	if len(seen) != 3 {
		t.Fatalf("found documented boot files for %v, want controller, gateway and connector", seen)
	}
}

func TestDefaults(t *testing.T) {
	var c config.Controller
	if err := config.Parse([]byte("version: 1\npublic_url: https://panel.example.com\n"), &c); err != nil {
		t.Fatal(err)
	}
	if c.Listen.HTTPS != ":443" || *c.Listen.HTTP != ":80" || c.Listen.Admin != "127.0.0.1:7381" ||
		c.Database.Driver != "sqlite" || c.Database.DSN != "/var/lib/rpmgr/controller.db" ||
		c.KEK.Source != config.KEKSystemdCredential || c.KEK.Name != "rpmgr-kek" {
		t.Errorf("controller defaults: %+v", c)
	}
	if err := config.Parse([]byte("version: 1\npublic_url: https://p.example\nlisten: {http: \"\"}\n"), &c); err != nil || *c.Listen.HTTP != "" {
		t.Errorf("an empty listen.http must disable port 80, not take the default: %q, %v", *c.Listen.HTTP, err)
	}
	var g config.Gateway
	if err := config.Parse([]byte("version: 1\ncontroller: {endpoints: [https://p.example]}\n"), &g); err != nil {
		t.Fatal(err)
	}
	if g.IdentityDir != "/var/lib/rpmgr/identity" || g.StateDir != "/var/lib/rpmgr" || g.Listen.TCP != ":443" ||
		g.Listen.UDP != ":443" || g.Listen.TunnelUDP != "" || *g.Listen.HTTP != ":80" || g.Listen.Admin != "127.0.0.1:7382" {
		t.Errorf("gateway defaults: %+v", g)
	}
	var n config.Connector
	if err := config.Parse([]byte("version: 1\ncontroller: {endpoints: [https://p.example]}\n"), &n); err != nil {
		t.Fatal(err)
	}
	if n.PolicyFile != "/etc/rpmgr/policy.yaml" || n.Listen.Admin != "127.0.0.1:7383" || n.StateDir != "/var/lib/rpmgr" {
		t.Errorf("connector defaults: %+v", n)
	}
}

// TestRefused: each case changes a valid file in one place and must be refused with a message that
// names the problem.
func TestRefused(t *testing.T) {
	const ctl = "version: 1\npublic_url: https://panel.example.com\n"
	const agent = "version: 1\ncontroller: {endpoints: [https://panel.example.com]}\n"
	cases := []struct {
		name, role, yaml, want string
	}{
		{"empty file", "controller", "", "empty"},
		{"unknown top-level key", "controller", ctl + "listen_https: \":443\"\n", "listen_https"},
		{"unknown nested key", "controller", ctl + "kek: {source: file, path: /k, mode: \"0600\"}\n", "mode"},
		{"misspelt key in an inline section", "gateway", agent + "identitydir: /x\n", "identitydir"},
		{"second document", "controller", ctl + "---\n" + ctl, "more than one"},
		{"wrong type", "controller", "version: one\npublic_url: https://p.example\n", "cannot unmarshal"},
		{"no version", "controller", "public_url: https://p.example\n", "version"},
		{"version 2", "controller", "version: 2\npublic_url: https://p.example\n", "version"},
		{"no public_url", "controller", "version: 1\n", "public_url"},
		{"http public_url", "controller", "version: 1\npublic_url: http://p.example\n", "public_url"},
		{"public_url with a path", "controller", "version: 1\npublic_url: https://p.example/ui\n", "public_url"},
		{"public_url with a user", "controller", "version: 1\npublic_url: https://u@p.example\n", "public_url"},
		{"public_url with a query", "controller", "version: 1\npublic_url: https://p.example?x\n", "public_url"},
		{"public_url without a host", "controller", "version: 1\npublic_url: https:///\n", "public_url"},
		{"postgres in Phase 1", "controller", ctl + "database: {driver: postgres, dsn: postgres://x}\n", "Phase 2"},
		{"unknown driver", "controller", ctl + "database: {driver: mysql}\n", "driver"},
		{"relative database path", "controller", ctl + "database: {dsn: controller.db}\n", "dsn"},
		{"database path with a pragma", "controller", ctl + "database: {dsn: \"/x.db?_pragma=foreign_keys(0)\"}\n", "dsn"},
		{"KEK from the environment", "controller", ctl + "kek: {source: env}\n", "environment"},
		{"KEK from a KMS", "controller", ctl + "kek: {source: kms}\n", "Phase 2"},
		{"KEK file without a path", "controller", ctl + "kek: {source: file}\n", "absolute path"},
		{"KEK file with a relative path", "controller", ctl + "kek: {source: file, path: kek}\n", "absolute path"},
		{"KEK credential with a path", "controller", ctl + "kek: {source: systemd-credential, path: /k}\n", "credential name"},
		{"KEK credential name with a slash", "controller", ctl + "kek: {source: systemd-credential, name: a/b}\n", "credential name"},
		{"certificate without a key", "controller", ctl + "tls: {cert_file: /etc/rpmgr/ui.crt}\n", "go together"},
		{"key without a certificate", "controller", ctl + "tls: {key_file: /etc/rpmgr/ui.key}\n", "go together"},
		{"relative certificate path", "controller", ctl + "tls: {cert_file: ui.crt, key_file: /k}\n", "tls.cert_file"},
		{"port missing", "controller", ctl + "listen: {https: \"443\"}\n", "listen.https"},
		{"port 0", "controller", ctl + "listen: {admin: \"127.0.0.1:0\"}\n", "listen.admin"},
		{"port too large", "controller", ctl + "listen: {https: \":65536\"}\n", "listen.https"},
		{"port with a sign", "controller", ctl + "listen: {https: \":+443\"}\n", "listen.https"},
		{"listener without a port", "controller", ctl + "listen: {https: \"0.0.0.0\"}\n", "listen.https"},
		{"unknown log level", "controller", ctl + "log: {level: verbose}\n", "log"},
		{"unknown log format", "connector", agent + "log: {format: xml}\n", "log"},
		{"no endpoints", "gateway", "version: 1\n", "endpoints"},
		{"http endpoint", "connector", "version: 1\ncontroller: {endpoints: [http://p.example]}\n", "endpoints[0]"},
		{"relative identity dir", "gateway", agent + "identity_dir: identity\n", "identity_dir"},
		{"bad tunnel port", "gateway", agent + "listen: {tunnel_udp: \":x\"}\n", "listen.tunnel_udp"},
		{"relative policy file", "connector", agent + "policy_file: policy.yaml\n", "policy_file"},
		{"admin on all interfaces", "controller", ctl + "listen: {admin: \"0.0.0.0:7381\"}\n", "listen.admin"},
		{"admin on a public address", "gateway", agent + "listen: {admin: \"203.0.113.5:7382\"}\n", "listen.admin"},
		{"admin on a host name", "connector", agent + "listen: {admin: \"admin.example:7383\"}\n", "listen.admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := map[string]config.File{"controller": &config.Controller{}, "gateway": &config.Gateway{}, "connector": &config.Connector{}}[tc.role]
			err := config.Parse([]byte(tc.yaml), f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error about %q", err, tc.want)
			}
		})
	}
}

func TestLoadAndPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "controller.yaml")
	if err := os.WriteFile(p, []byte("version: 1\npublic_url: https://p.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var c config.Controller
	if err := config.Load(p, &c); err != nil || c.PublicURL != "https://p.example" {
		t.Fatalf("Load: %+v, %v", c, err)
	}
	if err := config.Load(filepath.Join(dir, "missing.yaml"), &c); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, []byte("version: 1\n#"+strings.Repeat("x", 70<<10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := config.Load(big, &c); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("a 70 KiB file: %v", err)
	}
	if err := config.Load(p, &config.Gateway{}); err == nil {
		t.Error("a controller file loaded as gateway file")
	}
	env := map[string]string{"RPMGR_CONFIG": "/srv/c.yaml"}
	getenv := func(k string) string { return env[k] }
	if got := config.Path("/x.yaml", "gateway", getenv); got != "/x.yaml" {
		t.Errorf("flag: %s", got)
	}
	if got := config.Path("", "gateway", getenv); got != "/srv/c.yaml" {
		t.Errorf("RPMGR_CONFIG: %s", got)
	}
	if got := config.Path("", "gateway", func(string) string { return "" }); got != "/etc/rpmgr/gateway.yaml" {
		t.Errorf("default: %s", got)
	}
}

// TestAdminPrivateAddress: the admin listener may be bound to a private interface, for scrapers and
// load-balancer checks.
func TestAdminPrivateAddress(t *testing.T) {
	for _, addr := range []string{"10.0.0.5:7381", "[fd00::5]:7381", "localhost:7381"} {
		var c config.Controller
		if err := config.Parse([]byte("version: 1\npublic_url: https://panel.example.com\nlisten: {admin: \""+addr+"\"}\n"), &c); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

// TestAllInOne: an all-in-one file takes the controller's and the gateway's defaults, and splits
// into a controller whose port 443 is the gateway's and a gateway whose identity and state live
// under state_dir and which leaves port 80 to the controller.
func TestAllInOne(t *testing.T) {
	var a config.AllInOne
	if err := config.Parse([]byte("version: 1\npublic_url: https://panel.example.com\n"), &a); err != nil {
		t.Fatal(err)
	}
	c, g := a.Controller(), a.Gateway()
	if c.PublicURL != "https://panel.example.com" || c.Listen.HTTPS != ":443" || *c.Listen.HTTP != ":80" || c.Listen.Admin != "127.0.0.1:7381" ||
		c.Database.DSN != "/var/lib/rpmgr/controller.db" || c.KEK.Source != config.KEKSystemdCredential || c.KEK.Name != "rpmgr-kek" {
		t.Errorf("controller part: %+v", c)
	}
	if len(g.Controller.Endpoints) != 1 || g.Controller.Endpoints[0] != "https://panel.example.com" || g.Listen.TCP != ":443" ||
		g.Listen.UDP != ":443" || *g.Listen.HTTP != "" || g.IdentityDir != "/var/lib/rpmgr/gateway/identity" || g.StateDir != "/var/lib/rpmgr/gateway" {
		t.Errorf("gateway part: %+v", g)
	}
	for _, tc := range []struct{ yaml, want string }{
		{"version: 1\n", "public_url"},
		{"version: 1\npublic_url: https://p.example\nstate_dir: lib\n", "state_dir"},
		{"version: 1\npublic_url: https://p.example\nlisten: {tcp: \"443\"}\n", "listen.tcp"},
		{"version: 1\npublic_url: https://p.example\nlisten: {https: \":443\"}\n", "https"},
		{"version: 1\npublic_url: https://p.example\nidentity_dir: /x\n", "identity_dir"},
		{"version: 1\npublic_url: https://p.example\nkek: {source: env}\n", "environment"},
	} {
		var b config.AllInOne
		if err := config.Parse([]byte(tc.yaml), &b); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want an error about %q", tc.yaml, err, tc.want)
		}
	}
}
