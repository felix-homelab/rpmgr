// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// marker is the text the WSS cell sends through its routes in the clear; the proxy must never
// see it.
const marker = "rpmgr-e2e-wss-plaintext-"

// observed is what the intercepting proxy saw (test/e2e/proxy/observe.py).
type observed struct {
	Connects   []string `json:"connects"`
	Refused    []string `json:"refused"`
	Websockets []string `json:"websockets"`
	Messages   int      `json:"messages"`
	Bytes      int      `json:"bytes"`
	Marker     int      `json:"marker"`
}

func proxySaw() (observed, error) {
	var o observed
	b, err := os.ReadFile(filepath.Join(run, "proxy", "observed.json"))
	if err == nil {
		err = json.Unmarshal(b, &o)
	}
	return o, err
}

// startProxy starts mitmproxy on port 8080 of the proxy node, with the root in its confdir. It
// intercepts every TLS connection it relays, the controller's too unless exemptController.
func startProxy(exemptController bool) error {
	_ = os.Remove(filepath.Join(run, "proxy", "observed.json"))
	cmd := "echo $$ > /var/lib/rpmgr/mitmdump.pid; HOME=/var/lib/rpmgr exec mitmdump --listen-port 8080" +
		" --set confdir=/var/lib/rpmgr/mitm --set ssl_verify_upstream_trusted_ca=/var/lib/rpmgr/web-ca.pem" +
		" -s /opt/rpmgr/observe.py --set marker=" + marker
	if exemptController {
		cmd += ` --ignore-hosts '^ctl:8443$'`
	}
	if _, err := compose("exec", "-d", "-T", "proxy", "sh", "-c", cmd+" >> /var/lib/rpmgr/proxy.log 2>&1"); err != nil {
		return err
	}
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if _, err := proxySaw(); err == nil {
			return nil
		}
	}
	return os.ErrDeadlineExceeded
}

// stopProxy stops mitmproxy and waits until it is gone.
func stopProxy() error {
	if _, err := in("proxy", "sh", "-c", "kill $(cat /var/lib/rpmgr/mitmdump.pid)"); err != nil {
		return err
	}
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if _, err := in("proxy", "sh", "-c", "kill -0 $(cat /var/lib/rpmgr/mitmdump.pid)"); err != nil {
			return nil
		}
	}
	return os.ErrDeadlineExceeded
}

// proxyRoot writes a root for the proxy into its confdir, in mitmproxy's format, the key first,
// and returns the root's certificate in PEM.
func proxyRoot() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rpmgr e2e intercepting proxy"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	crt := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := os.MkdirAll(filepath.Join(run, "proxy", "mitm"), 0o750); err != nil {
		return "", err
	}
	return crt, writeFile("proxy", "mitm/mitmproxy-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))+crt)
}

// TestWSS_InterceptingProxy: a connector whose only way out is a TLS-intercepting proxy, with
// UDP and direct TCP to the gateways blocked, and which trusts the proxy's root as the network
// tells it to, serves its routes over WSS (VB-21 runs the same cell against a real proxy). A
// route on auto, once the proxy has broken TLS + reverse HTTP/2, and one pinned to wss carry
// 1 MiB each way intact through both gateways; the proxy relays the WebSocket but never sees the
// plaintext; a route pinned to h2 is never served, since a pin never falls back. With the
// controller intercepted too, the connector still takes new configuration. A connector that does
// not trust the proxy's root refuses the outer TLS as well and serves nothing.
func TestWSS_InterceptingProxy(t *testing.T) {
	const auto, pinned, h2, late = 25001, 25002, 25003, 25004
	webCA, err := os.ReadFile(filepath.Join(run, "con3", "web-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := proxyRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile("con3", "web-ca.pem", string(webCA)+root); err != nil {
		t.Fatal(err)
	}

	// The gateways' WSS hostnames, served on 8443 behind port 443, and their certificate.
	redirect := []string{"PREROUTING", "-t", "nat", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "8443"}
	for _, gw := range []string{"gw1", "gw2"} {
		for _, ipt := range []string{"iptables", "ip6tables"} {
			if _, err := asRoot(gw, append([]string{ipt, "-A"}, redirect...)...); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = asRoot(gw, append([]string{ipt, "-D"}, redirect...)...) })
		}
	}
	crt, key, err := issue("wss.e2e.test", "wss1.e2e.test", "wss2.e2e.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile("ctl", "wss.crt", crt); err != nil {
		t.Fatal(err)
	}
	if err := writeFile("ctl", "wss.key", key); err != nil {
		t.Fatal(err)
	}
	if _, err := seed("gateway-wss", "--name", "gw1", "--hostname", "wss1.e2e.test",
		"--cert-file", "/var/lib/rpmgr/wss.crt", "--key-file", "/var/lib/rpmgr/wss.key"); err != nil {
		t.Fatal(err)
	}
	if _, err := seed("gateway-wss", "--name", "gw2", "--hostname", "wss2.e2e.test"); err != nil {
		t.Fatal(err)
	}

	// The office network leads only to the proxy; UDP leaves nowhere, so QUIC cannot either.
	for _, rule := range [][]string{
		{"OUTPUT", "-p", "udp", "!", "-o", "lo", "-j", "DROP"},
		{"OUTPUT", "-d", "172.30.0.0/24", "-j", "REJECT"},
	} {
		if _, err := asRoot("con3", append([]string{"iptables", "-A"}, rule...)...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := in("con3", "timeout", "5", "bash", "-c", "exec 3<>/dev/tcp/172.30.0.11/8443"); err == nil {
		t.Fatal("con3 reaches gw1 directly")
	}

	if err := startProxy(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stopProxy() })
	tok, err := seed("connector-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := enroll("con3", tok); err != nil {
		t.Fatalf("enrolling through the proxy, which exempts the controller: %v", err)
	}
	if err := writeFile("con3", "policy.yaml", connectorPolicy); err != nil {
		t.Fatal(err)
	}
	if err := writeFile("con3", "connector.yaml", `version: 1
controller: {endpoints: [`+controllerURL+`]}
identity_dir: /var/lib/rpmgr/identity
state_dir: /var/lib/rpmgr
policy_file: /var/lib/rpmgr/policy.yaml
listen: {admin: "127.0.0.1:7383"}
`); err != nil {
		t.Fatal(err)
	}
	if err := startRole("con3", "connector"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = signal("con3", "KILL") })
	if err := ready("con3", 7383); err != nil {
		t.Fatal(err)
	}

	addRoute(t, "wss-auto", auto, "auto", "con3")
	addRoute(t, "wss-pinned", pinned, "wss", "con3")
	addRoute(t, "wss-h2", h2, "h2", "con3")
	for _, port := range []int{auto, pinned} {
		for _, gw := range []string{"gw1", "gw2"} {
			eventually(t, 90*time.Second, "the route through "+addr(gw, port), func() error { return client("check", "-addr", addr(gw, port)) })
			if err := client("check", "-addr", addr(gw, port), "-fill", marker); err != nil {
				t.Fatalf("plaintext through %s: %v", addr(gw, port), err)
			}
		}
	}
	for _, gw := range []string{"gw1", "gw2"} {
		if err := client("gone", "-addr", addr(gw, h2), "-duration", "1s"); err != nil {
			t.Fatalf("the route pinned to h2 behind an intercepting proxy: %v", err)
		}
	}
	saw, err := proxySaw()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ctl:8443", "gw1:8443", "wss1.e2e.test:443", "wss2.e2e.test:443"} {
		if !slices.Contains(saw.Connects, want) {
			t.Errorf("the proxy saw no CONNECT to %s: %+v", want, saw)
		}
	}
	for _, want := range []string{"https://wss1.e2e.test/.rpmgr/tunnel", "https://wss2.e2e.test/.rpmgr/tunnel"} {
		if !slices.Contains(saw.Websockets, want) {
			t.Errorf("the proxy relayed no WebSocket at %s: %+v", want, saw)
		}
	}
	// The proxy broke TLS + reverse HTTP/2 to the gateways, and the connector refused it.
	if !slices.ContainsFunc(saw.Refused, func(n string) bool { return strings.Contains(n, ".gateway.") }) {
		t.Errorf("the connector refused no certificate of the proxy for a gateway: %+v", saw)
	}
	// Four plaintext checks of 1 MiB each way passed through the WebSockets.
	if saw.Bytes < 8<<20 || saw.Marker != 0 {
		t.Fatalf("the proxy's view of the WebSockets: %d messages, %d bytes, %d with the plaintext", saw.Messages, saw.Bytes, saw.Marker)
	}

	t.Run("controller intercepted", func(t *testing.T) {
		if err := signal("con3", "KILL"); err != nil {
			t.Fatal(err)
		}
		if err := stopProxy(); err != nil {
			t.Fatal(err)
		}
		if err := startProxy(false); err != nil {
			t.Fatal(err)
		}
		if err := startRole("con3", "connector"); err != nil {
			t.Fatal(err)
		}
		addRoute(t, "wss-late", late, "wss", "con3")
		eventually(t, 120*time.Second, "a route added while the controller is intercepted", func() error {
			return client("check", "-addr", addr("gw1", late))
		})
		saw, err := proxySaw()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(saw.Refused, func(n string) bool { return strings.HasPrefix(n, "controller.") }) {
			t.Fatalf("the connector did not refuse the proxy's certificate for the controller: %+v", saw)
		}
	})

	t.Run("proxy root not trusted", func(t *testing.T) {
		if err := signal("con3", "KILL"); err != nil {
			t.Fatal(err)
		}
		if err := writeFile("con3", "web-ca.pem", string(webCA)); err != nil {
			t.Fatal(err)
		}
		if err := stopProxy(); err != nil {
			t.Fatal(err)
		}
		if err := startProxy(true); err != nil {
			t.Fatal(err)
		}
		if err := startRole("con3", "connector"); err != nil {
			t.Fatal(err)
		}
		if err := ready("con3", 7383); err != nil {
			t.Fatal(err)
		}
		eventually(t, 60*time.Second, "the connector refusing the proxy's certificate for the WSS hostnames", func() error {
			saw, err := proxySaw()
			if err == nil && (!slices.Contains(saw.Refused, "wss1.e2e.test") || !slices.Contains(saw.Refused, "wss2.e2e.test")) {
				err = os.ErrNotExist
			}
			return err
		})
		for _, port := range []int{auto, pinned, late} {
			for _, gw := range []string{"gw1", "gw2"} {
				if err := client("gone", "-addr", addr(gw, port), "-duration", "1s"); err != nil {
					t.Errorf("served without trusting the proxy: %v", err)
				}
			}
		}
		if saw, err := proxySaw(); err != nil || len(saw.Websockets) != 0 {
			t.Fatalf("a WebSocket through an untrusted proxy: %+v %v", saw, err)
		}
	})
}
