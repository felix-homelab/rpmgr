// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package e2e runs the container end-to-end tests (docs/12-testing-and-quality.md, "Where the
// cells run"): real rpmgr processes of the rpmgrtest build in Docker Compose, configured through
// `rpmgr testseed`, enrolled with `rpmgr enroll`, and checked with e2eclient. Run with
//
//	go test -tags e2e -timeout 20m ./test/e2e
//
// E2E_KEEP=1 leaves the containers and the run directory for inspection.
package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	controllerURL = "https://ctl:8443"
	serviceAddr   = "172.31.0.7:7007"
)

var (
	here string // test/e2e
	run  string // the containers' /var/lib/rpmgr directories
	pin  string // the controller's CA pin
)

func TestMain(m *testing.M) {
	code := 1
	if err := setUp(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e set-up:", err)
	} else {
		code = m.Run()
	}
	if code != 0 {
		dumpLogs()
	}
	if os.Getenv("E2E_KEEP") == "" {
		_, _ = compose("down", "--volumes", "--timeout", "5")
		_ = os.RemoveAll(run)
	} else {
		fmt.Fprintln(os.Stderr, "e2e: kept the containers and", run)
	}
	os.Exit(code)
}

// command runs name with args in here and returns its combined output.
func command(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = here
	cmd.Env = append(os.Environ(), "E2E_RUN="+run, "E2E_UID="+strconv.Itoa(os.Getuid()), "E2E_GID="+strconv.Itoa(os.Getgid()))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String(), nil
}

func compose(args ...string) (string, error) {
	return command("docker", append([]string{"compose", "--project-name", "rpmgr-e2e"}, args...)...)
}

// in runs a command in a node.
func in(node string, args ...string) (string, error) {
	return compose(append([]string{"exec", "-T", node}, args...)...)
}

// startRole starts an rpmgr role in node in the background, its output appended to <role>.log.
func startRole(node, role string) error {
	_, err := compose("exec", "-d", "-T", node, "sh", "-c",
		fmt.Sprintf("exec rpmgr %s --config /var/lib/rpmgr/%s.yaml >> /var/lib/rpmgr/%s.log 2>&1", role, role, role))
	return err
}

// signal sends sig to the rpmgr process of node and, for KILL or TERM, waits until it is gone.
func signal(node, sig string) error {
	if _, err := in(node, "pkill", "-"+sig, "-x", "rpmgr"); err != nil {
		return err
	}
	for range 150 {
		if _, err := in(node, "pgrep", "-x", "rpmgr"); err != nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("rpmgr in %s did not end after SIG%s", node, sig)
}

// ready waits for the admin listener of node's role on port.
func ready(node string, port int) error {
	_, err := in(node, "e2eclient", "ready", "-url", fmt.Sprintf("http://127.0.0.1:%d/readyz", port), "-duration", "60s")
	return err
}

// seed runs `rpmgr testseed <verb> <args>` against the controller's boot file.
func seed(verb string, args ...string) (string, error) {
	out, err := in("ctl", append([]string{"rpmgr", "testseed", verb, "--config", "/var/lib/rpmgr/controller.yaml"}, args...)...)
	return strings.TrimSpace(out), err
}

func writeFile(node, name, data string) error {
	return os.WriteFile(filepath.Join(run, node, name), []byte(data), 0o600)
}

func setUp() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	here = wd
	if run, err = os.MkdirTemp("", "rpmgr-e2e-"); err != nil {
		return err
	}
	for _, node := range []string{"ctl", "gw1", "gw2", "con1", "con2"} {
		if err := os.MkdirAll(filepath.Join(run, node), 0o750); err != nil {
			return err
		}
	}
	// The rpmgrtest build and the client, for the containers' platform.
	for _, b := range [][]string{{"rpmgr", "../../cmd/rpmgr"}, {"e2eclient", "./e2eclient"}} {
		cmd := exec.Command("go", "build", "-trimpath", "-tags", "rpmgrtest", "-o", filepath.Join("bin", b[0]), b[1])
		cmd.Dir = here
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go build %s: %w\n%s", b[1], err, out)
		}
	}
	if err := webCertificate(); err != nil {
		return err
	}
	if err := writeFile("ctl", "controller.yaml", `version: 1
public_url: `+controllerURL+`
listen: {https: ":8443", http: "", admin: "127.0.0.1:7381"}
database: {dsn: /var/lib/rpmgr/controller.db}
kek: {source: file, path: /var/lib/rpmgr/kek}
tls: {cert_file: /var/lib/rpmgr/web.crt, key_file: /var/lib/rpmgr/web.key}
`); err != nil {
		return err
	}
	if _, err := compose("down", "--volumes", "--timeout", "1"); err != nil {
		return err
	}
	if _, err := compose("up", "--detach", "--build", "--wait"); err != nil {
		return err
	}
	out, err := in("ctl", "rpmgr", "controller", "init", "--config", "/var/lib/rpmgr/controller.yaml")
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`CA pin:\s+(\S+)`).FindStringSubmatch(out)
	if m == nil {
		return fmt.Errorf("no CA pin in %q", out)
	}
	pin = m[1]
	if err := startRole("ctl", "controller"); err != nil {
		return err
	}
	if err := ready("ctl", 7381); err != nil {
		return fmt.Errorf("controller: %w", err)
	}
	for _, gw := range []string{"gw1", "gw2"} {
		tok, err := seed("gateway", "--group", "e2e", "--name", gw, "--endpoint", gw+":8443")
		if err != nil {
			return err
		}
		if err := enroll(gw, tok); err != nil {
			return err
		}
		if err := writeFile(gw, "gateway.yaml", `version: 1
controller: {endpoints: [`+controllerURL+`]}
identity_dir: /var/lib/rpmgr/identity
state_dir: /var/lib/rpmgr
listen: {tcp: ":8443", udp: ":8443", http: "", admin: "127.0.0.1:7382"}
`); err != nil {
			return err
		}
		if err := startRole(gw, "gateway"); err != nil {
			return err
		}
	}
	tok, err := seed("connector-token", "--uses", "2")
	if err != nil {
		return err
	}
	for _, con := range []string{"con1", "con2"} {
		if err := enroll(con, tok); err != nil {
			return err
		}
		if err := writeFile(con, "policy.yaml", "version: 1\nallow_targets:\n  - cidr: 172.31.0.7/32\n    ports: [7007]\n"); err != nil {
			return err
		}
		if err := writeFile(con, "connector.yaml", `version: 1
controller: {endpoints: [`+controllerURL+`]}
identity_dir: /var/lib/rpmgr/identity
state_dir: /var/lib/rpmgr
policy_file: /var/lib/rpmgr/policy.yaml
listen: {admin: "127.0.0.1:7383"}
`); err != nil {
			return err
		}
		if err := startRole(con, "connector"); err != nil {
			return err
		}
	}
	for node, port := range map[string]int{"gw1": 7382, "gw2": 7382, "con1": 7383, "con2": 7383} {
		if err := ready(node, port); err != nil {
			return fmt.Errorf("%s: %w", node, err)
		}
	}
	return nil
}

func enroll(node, tok string) error {
	if err := writeFile(node, "token", tok+"\n"); err != nil {
		return err
	}
	_, err := in(node, "rpmgr", "enroll", "--controller", controllerURL, "--ca-pin", pin, "--token-file", "/var/lib/rpmgr/token")
	return err
}

// webCertificate writes a certificate for ctl from a new CA, which every node trusts through
// SSL_CERT_FILE.
func webCertificate() error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rpmgr e2e web CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ctl"}, DNSNames: []string{"ctl"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	for _, node := range []string{"ctl", "gw1", "gw2", "con1", "con2"} {
		if err := writeFile(node, "web-ca.pem", caPEM); err != nil {
			return err
		}
	}
	if err := writeFile("ctl", "web.crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))); err != nil {
		return err
	}
	return writeFile("ctl", "web.key", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})))
}

// dumpLogs prints every role's log, for a failed run.
func dumpLogs() {
	for _, node := range []string{"ctl", "gw1", "gw2", "con1", "con2"} {
		logs, _ := filepath.Glob(filepath.Join(run, node, "*.log"))
		for _, l := range logs {
			b, _ := os.ReadFile(l) //nolint:gosec // G304: the test's own run directory
			if len(b) > 64<<10 {
				b = b[len(b)-64<<10:]
			}
			fmt.Fprintf(os.Stderr, "==== %s %s\n%s\n", node, filepath.Base(l), b)
		}
	}
}
