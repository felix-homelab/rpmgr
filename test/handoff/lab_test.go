// SPDX-License-Identifier: Apache-2.0

//go:build handoff

package handoff

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The lab: four containers of one image on a network of their own, every process of them root's,
// which the hand-off's binary check wants to own the binary. "lab" runs the controller, the lone
// gateway, the all-in-one and the services behind the connectors; "c1" and "c2" run one
// connector each (their host names are the connectors' names).
const (
	ctlURL   = "https://lab:8443"
	webCA    = "/var/lib/web-ca.pem"
	gwPort   = 9443 // the lone gateway's TCP and UDP port
	aioPort  = 9543 // the all-in-one's
	reprobe  = "15s"
	drain    = "25s" // the hand-off drain of both roles: longer than any connection the test holds
	connPol  = "version: 1\nallow_targets:\n  - cidr: %s/32\n    ports: [7007, 7008, 7080]\n"
	imageTag = "rpmgr-handoff:local"
)

type lab struct {
	t         *testing.T
	dir       string // the host's scratch directory: binaries and certificates
	net       string
	prefix    string
	ip        string // the lab container's address, where the services listen
	pin       string
	oldBuild  string
	newBuild  string
	clientEx  string
	triggerAt time.Duration // when the running hand-off was triggered, since the start of its load
}

var (
	webCert    *x509.Certificate
	webCertKey *ecdsa.PrivateKey
)

func run(t testing.TB, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...) //nolint:gosec // G204: the test's own commands
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

// build compiles the rpmgrtest build of the tree in src into out.
func build(t testing.TB, src, out, pkg string) {
	t.Helper()
	run(t, src, []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + runtime.GOARCH}, "go", "build", "-trimpath", "-tags", "rpmgrtest", "-o", out, pkg)
}

// newLab builds the old and the new binary and starts the containers.
func newLab(t *testing.T) *lab {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is needed")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	l := &lab{t: t, dir: t.TempDir(), prefix: fmt.Sprintf("hl-%d", os.Getpid())}
	l.net = l.prefix
	ref := os.Getenv("HANDOFF_FROM")
	if ref == "" {
		ref = "HEAD~1"
	}
	// The previous build is the tree one commit back (D155, point 4), or the revision named in
	// HANDOFF_FROM: it is the process that hands over.
	oldSrc := filepath.Join(l.dir, "old-src")
	if err := os.Mkdir(oldSrc, 0o750); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-c", `git -C "$1" archive "$2" | tar -x -C "$3"`, "sh", root, ref, oldSrc).CombinedOutput(); err != nil { //nolint:gosec // G204: the test's own revision
		t.Fatalf("git archive %s (a shallow clone needs fetch-depth 2): %v\n%s", ref, err, out)
	}
	l.oldBuild, l.newBuild, l.clientEx = filepath.Join(l.dir, "old-rpmgr"), filepath.Join(l.dir, "new-rpmgr"), filepath.Join(l.dir, "e2eclient")
	var wg sync.WaitGroup
	for _, b := range []struct{ src, out, pkg string }{{oldSrc, l.oldBuild, "./cmd/rpmgr"}, {root, l.newBuild, "./cmd/rpmgr"}, {root, l.clientEx, "./test/e2e/e2eclient"}} {
		wg.Go(func() { build(t, b.src, b.out, b.pkg) })
	}
	run(t, ".", nil, "docker", "build", "-q", "-t", imageTag, ".")
	wg.Wait()
	run(t, ".", nil, "docker", "network", "create", l.net)
	t.Cleanup(l.destroy)
	for _, n := range []string{"lab", "c1", "c2"} {
		run(t, ".", nil, "docker", "run", "-d", "--init", "--name", l.prefix+"-"+n, "--hostname", n, "--network", l.net,
			"--network-alias", n, "-e", "SSL_CERT_FILE="+webCA, imageTag)
	}
	l.ip = strings.TrimSpace(run(t, ".", nil, "docker", "inspect", "-f", "{{(index .NetworkSettings.Networks \""+l.net+"\").IPAddress}}", l.prefix+"-lab"))
	if l.ip == "" {
		t.Fatal("no address of the lab container")
	}
	for _, n := range []string{"lab", "c1", "c2"} {
		l.copyIn(n, l.clientEx, "/usr/local/bin/e2eclient")
	}
	for _, n := range []string{"lab", "c1", "c2"} {
		l.sh(n, "mkdir -p /run/rpmgr/gateway /run/rpmgr/all-in-one /run/rpmgr/connector /opt/ctl /opt/gw /opt/aio /opt/con /var/lib/ctl /var/lib/gw /var/lib/aio /var/lib/con")
	}
	l.copyIn("lab", l.newBuild, "/opt/ctl/rpmgr")
	l.copyIn("lab", l.oldBuild, "/opt/gw/rpmgr")
	l.copyIn("lab", l.oldBuild, "/opt/aio/rpmgr")
	l.copyIn("c1", l.newBuild, "/opt/con/rpmgr")
	l.copyIn("c2", l.newBuild, "/opt/con/rpmgr")
	l.certificates()
	return l
}

func (l *lab) destroy() {
	for _, n := range []string{"lab", "c1", "c2"} {
		_ = exec.Command("docker", "rm", "-f", l.prefix+"-"+n).Run()
	}
	_ = exec.Command("docker", "network", "rm", l.net).Run()
}

func (l *lab) name(node string) string { return l.prefix + "-" + node }

// copyIn puts the host file src at dst in node.
func (l *lab) copyIn(node, src, dst string) {
	l.t.Helper()
	run(l.t, ".", nil, "docker", "cp", src, l.name(node)+":"+dst)
	// docker cp keeps the host's owner and mode; the hand-off wants root's, not writable by others.
	l.exec(node, "sh", "-c", "chown 0:0 "+dst+" && chmod 755 "+dst)
}

// put writes data to path in node, readable by its owner only.
func (l *lab) put(node, path, data string) {
	l.t.Helper()
	cmd := exec.Command("docker", "exec", "-i", l.name(node), "sh", "-c", "umask 077; cat > "+path)
	cmd.Stdin = strings.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		l.t.Fatalf("writing %s in %s: %v\n%s", path, node, err, out)
	}
}

// try runs args in node and returns the output and the error.
func (l *lab) try(node string, args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", l.name(node)}, args...)...) //nolint:gosec // G204: the test's own commands
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return string(out), err
}

func (l *lab) exec(node string, args ...string) string {
	l.t.Helper()
	out, err := l.try(node, args...)
	if err != nil {
		l.t.Fatalf("in %s: %v", node, err)
	}
	return out
}

func (l *lab) sh(node, script string) string {
	l.t.Helper()
	return l.exec(node, "sh", "-c", script)
}

// bg runs script in the background in node.
func (l *lab) bg(node, script string) {
	l.t.Helper()
	cmd := exec.Command("docker", "exec", "-d", "-e", "RPMGR_TEST_REPROBE="+reprobe, l.name(node), "sh", "-c", script) //nolint:gosec // G204: the test's own commands
	if out, err := cmd.CombinedOutput(); err != nil {
		l.t.Fatalf("starting %q in %s: %v\n%s", script, node, err, out)
	}
}

// start runs bin's role in the background in node with the boot file cfg; its output goes to
// the log file next to it.
func (l *lab) start(node, bin, role, cfg string) {
	l.t.Helper()
	l.bg(node, fmt.Sprintf("exec %s %s --config %s >> %s.log 2>&1", bin, role, cfg, cfg))
}

func (l *lab) ready(node string, port int) {
	l.t.Helper()
	l.exec(node, "e2eclient", "ready", "-url", fmt.Sprintf("http://127.0.0.1:%d/readyz", port), "-duration", "90s")
}

// seed runs a testseed verb against the boot file of the controller (or the all-in-one's).
func (l *lab) seed(cfg string, env []string, verb string, args ...string) string {
	l.t.Helper()
	a := []string{"exec"}
	for _, e := range env {
		a = append(a, "-e", e)
	}
	a = append(a, l.name("lab"), "/opt/ctl/rpmgr", "testseed", verb, "--config", cfg)
	out, err := exec.Command("docker", append(a, args...)...).CombinedOutput() //nolint:gosec // G204: the test's own commands
	if err != nil {
		l.t.Fatalf("testseed %s: %v\n%s", verb, err, out)
	}
	return strings.TrimSpace(string(out))
}

// enroll enrolls node's host with token against the controller at url.
func (l *lab) enroll(node, bin, url, token, identity string) {
	l.t.Helper()
	l.put(node, "/var/lib/token", token+"\n")
	l.exec(node, bin, "enroll", "--controller", url, "--ca-pin", l.pin, "--token-file", "/var/lib/token", "--identity-dir", identity)
}

// certificates creates the web CA, which every node trusts, and the certificates of the lab's
// controller and all-in-one, and of the HTTP routes.
func (l *lab) certificates() {
	t := l.t
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rpmgr hand-off test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	webCert, _ = x509.ParseCertificate(der)
	webCertKey = key
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for _, n := range []string{"lab", "c1", "c2"} {
		l.put(n, webCA, ca)
	}
	for _, c := range []struct {
		file  string
		names []string
	}{
		{"web", []string{"lab", "localhost"}},
		{"route", []string{"app.e2e.test", "app2.e2e.test"}},
	} {
		crt, k := l.issue(c.names)
		l.put("lab", "/var/lib/ctl/"+c.file+".crt", crt)
		l.put("lab", "/var/lib/ctl/"+c.file+".key", k)
		l.put("lab", "/var/lib/aio/"+c.file+".crt", crt)
		l.put("lab", "/var/lib/aio/"+c.file+".key", k)
	}
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	for _, d := range []string{"ctl", "aio"} {
		l.put("lab", "/var/lib/"+d+"/kek", base64.StdEncoding.EncodeToString(kek)+"\n")
	}
}

func (l *lab) issue(names []string) (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		l.t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, webCert, &key.PublicKey, webCertKey)
	if err != nil {
		l.t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		l.t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
}

var pinRE = regexp.MustCompile(`CA pin:\s+(\S+)`)

// up brings the topology up on the old build: the controller, the lone gateway "gw" of group
// "solo", the connectors c1 and c2, the all-in-one and the services.
func (l *lab) up() {
	t := l.t
	l.put("lab", "/var/lib/ctl/controller.yaml", `version: 1
public_url: `+ctlURL+`
listen: {https: ":8443", http: "", admin: "127.0.0.1:7381"}
database: {dsn: /var/lib/ctl/controller.db}
kek: {source: file, path: /var/lib/ctl/kek}
tls: {cert_file: /var/lib/ctl/web.crt, key_file: /var/lib/ctl/web.key}
`)
	out := l.exec("lab", "/opt/ctl/rpmgr", "controller", "init", "--config", "/var/lib/ctl/controller.yaml")
	m := pinRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no CA pin in %q", out)
	}
	l.pin = m[1]
	l.start("lab", "/opt/ctl/rpmgr", "controller", "/var/lib/ctl/controller.yaml")
	l.ready("lab", 7381)
	l.bg("lab", "exec e2eclient serve -listen :7007 -udp :7008 -http :7080 >> /var/lib/svc.log 2>&1")

	ctl := "/var/lib/ctl/controller.yaml"
	tok := l.seed(ctl, nil, "gateway", "--group", "solo", "--name", "gw", "--endpoint", fmt.Sprintf("lab:%d", gwPort))
	l.enroll("lab", "/opt/gw/rpmgr", ctlURL, tok, "/var/lib/gw/identity")
	l.put("lab", "/var/lib/gw/gateway.yaml", fmt.Sprintf(`version: 1
controller: {endpoints: [%s]}
identity_dir: /var/lib/gw/identity
state_dir: /var/lib/gw
listen: {tcp: ":%d", udp: ":%d", http: "", admin: "127.0.0.1:7382"}
handoff: {drain: %s}
`, ctlURL, gwPort, gwPort, drain))
	l.start("lab", "/opt/gw/rpmgr", "gateway", "/var/lib/gw/gateway.yaml")
	ctok := l.seed(ctl, nil, "connector-token", "--uses", "2")
	for _, c := range []string{"c1", "c2"} {
		l.enroll(c, "/opt/con/rpmgr", ctlURL, ctok, "/var/lib/con/identity")
		l.put(c, "/var/lib/con/policy.yaml", fmt.Sprintf(connPol, l.ip))
		l.put(c, "/var/lib/con/connector.yaml", fmt.Sprintf(`version: 1
controller: {endpoints: [%s]}
identity_dir: /var/lib/con/identity
state_dir: /var/lib/con
policy_file: /var/lib/con/policy.yaml
listen: {admin: "127.0.0.1:7383"}
`, ctlURL))
		l.start(c, "/opt/con/rpmgr", "connector", "/var/lib/con/connector.yaml")
	}
	// c1 serves the auto routes; c2 gets a route pinned to QUIC in the second hand-off.
	target := func(port int) string { return fmt.Sprintf("%s:%d", l.ip, port) }
	l.seed(ctl, nil, "route", "--name", "tcp-auto", "--group", "solo", "--port", "20001", "--target", target(7007), "--transport", "auto", "--connector", "c1")
	l.seed(ctl, nil, "udp-route", "--name", "udp-auto", "--group", "solo", "--port", "20002", "--target", target(7008), "--transport", "auto", "--connector", "c1")
	l.seed(ctl, nil, "http-route", "--name", "web", "--group", "solo", "--hostname", "app.e2e.test", "--connector", "c1", "--target", target(7080),
		"--cert-file", "/var/lib/ctl/route.crt", "--key-file", "/var/lib/ctl/route.key")
	l.ready("lab", 7382)
	l.ready("c1", 7383)
	l.ready("c2", 7383)

	// The all-in-one: its connector is "local" in group "default" of organisation "default".
	l.put("lab", "/var/lib/aio/all-in-one.yaml", fmt.Sprintf(`version: 1
public_url: https://lab:%d
listen: {tcp: ":%d", udp: ":%d", http: "", admin: "127.0.0.1:7392"}
database: {dsn: /var/lib/aio/controller.db}
kek: {source: file, path: /var/lib/aio/kek}
tls: {cert_file: /var/lib/aio/web.crt, key_file: /var/lib/aio/web.key}
state_dir: /var/lib/aio
policy_file: /var/lib/aio/policy.yaml
`, aioPort, aioPort, aioPort))
	l.put("lab", "/var/lib/aio/policy.yaml", fmt.Sprintf(connPol, l.ip))
	l.put("lab", "/var/lib/aio/seed.yaml", `version: 1
public_url: https://lab:9543
listen: {https: ":9543", http: "", admin: "127.0.0.1:7392"}
database: {dsn: /var/lib/aio/controller.db}
kek: {source: file, path: /var/lib/aio/kek}
`)
	l.exec("lab", "/opt/aio/rpmgr", "all-in-one", "init", "--config", "/var/lib/aio/all-in-one.yaml")
	aio := []string{"RPMGR_TESTSEED_ORG=default"}
	l.seed("/var/lib/aio/seed.yaml", aio, "route", "--name", "tcp-auto", "--group", "default", "--port", "21001", "--target", target(7007), "--connector", "local")
	l.seed("/var/lib/aio/seed.yaml", aio, "udp-route", "--name", "udp-auto", "--group", "default", "--port", "21002", "--target", target(7008), "--connector", "local")
	l.seed("/var/lib/aio/seed.yaml", aio, "http-route", "--name", "web", "--group", "default", "--hostname", "app2.e2e.test", "--connector", "local",
		"--target", target(7080), "--cert-file", "/var/lib/aio/route.crt", "--key-file", "/var/lib/aio/route.key")
	l.start("lab", "/opt/aio/rpmgr", "all-in-one", "/var/lib/aio/all-in-one.yaml")
	l.ready("lab", 7392)
}
