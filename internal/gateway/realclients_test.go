// SPDX-License-Identifier: Apache-2.0

//go:build realclients

package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// The names of the real-client run and what each must show: a route's page, or none.
var realNames = []struct{ host, want string }{
	{"app.example.test", "http-route app.example.test"},
	{"api.example.test", "http-route api.example.test"},
	{"pass.example.test", "passthrough-backend"},
	{"panel.example.test", "controller"},
	{"unknown.example.test", ""},
}

// testCA issues TLS server certificates for the real-client run.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "real-client test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k}
}

func (ca *testCA) issue(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: k, Leaf: leaf}
}

// textServer serves body on a new loopback listener, over TLS when cert is set.
func textServer(t *testing.T, cert *tls.Certificate, body func(*http.Request) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if cert != nil {
		ln = tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}})
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, body(r))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// TestRealClients: real clients (Go, curl, Chromium and Firefox) against the gateway's port 443
// router: http routes, a TLS-passthrough route, the controller's UI name and an unknown name each
// reach what they should (docs/12-testing-and-quality.md, "Continuous integration"). Run by
// check-real-clients.sh, which pins the client images.
func TestRealClients(t *testing.T) {
	curlImage, pwImage, pwVersion := os.Getenv("CURL_IMAGE"), os.Getenv("PLAYWRIGHT_IMAGE"), os.Getenv("PLAYWRIGHT_VERSION")
	if curlImage == "" || pwImage == "" || pwVersion == "" {
		t.Skip("run through .github/scripts/check-real-clients.sh")
	}
	ca := newTestCA(t)
	routeCert := ca.issue(t, "app.example.test", "api.example.test")
	passCert, panelCert := ca.issue(t, "pass.example.test"), ca.issue(t, "panel.example.test")

	upstream := textServer(t, nil, func(r *http.Request) string { return "http-route " + strings.Split(r.Host, ":")[0] })
	backend := textServer(t, &passCert, func(*http.Request) string { return "passthrough-backend ok" })
	http1 := newPlaneWith(t, upstream, "none", "rt_app", "rt_api")
	passPlane := newPlaneWith(t, backend, "none", "rt_pass")

	pk, _ := x509.MarshalPKCS8PrivateKey(routeCert.PrivateKey)
	item, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.CertificateItem{Chain: routeCert.Certificate, PrivateKey: pk})
	sum := sha256.Sum256(item)
	certs := gateway.NewCertificates(gateway.CertificatesOptions{Fetch: func(context.Context, string, []byte) ([]byte, error) { return item, nil }})
	if st := certs.Apply(t.Context(), []gateway.CertificateRoute{{ID: "crt_1", ContentSHA256: sum[:],
		Hostnames: []string{"app.example.test", "api.example.test"}}}); len(st) != 0 {
		t.Fatal(st)
	}
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: http1.sessions, Certificates: certs, Default: &def.Certificates[0]})
	t.Cleanup(h.Close)
	h.Apply([]gateway.HTTPRoute{
		{ID: "rt_app", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.test"}}},
		{ID: "rt_api", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "api.example.test"}}},
	})
	pass := gateway.NewPassthrough(passPlane.sessions, nil, nil)
	t.Cleanup(pass.Close)
	pass.Apply([]gateway.PassthroughRoute{{ID: "rt_pass", Hostnames: []string{"pass.example.test"}}})
	controller := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "controller ui")
	})}
	ctlLn := newHandOff()
	go func() {
		_ = controller.Serve(tls.NewListener(ctlLn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{panelCert}}))
	}()
	t.Cleanup(func() { _ = controller.Close() })
	router := &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: gateway.NewRouteTable(pass, h), HTTP: h.Serve,
		HTTPTLS: h.TLSConfig(), DefaultTLS: def, Controller: ctlLn.put, ControllerNames: []string{"panel.example.test"}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = router.Serve(ln) }()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o644); err != nil { //nolint:gosec // G306: a CA certificate the client containers read
		t.Fatal(err)
	}
	hosts := make([]string, len(realNames))
	for i, n := range realNames {
		hosts[i] = n.host
	}

	// Go, with the CA trusted and HTTP/2.
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	goOut := &strings.Builder{}
	for _, host := range hosts {
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, ln.Addr().String())
			}}}
		fmt.Fprintf(goOut, "== https://%s:%s/\n", host, port)
		resp, err := c.Get("https://" + host + ":" + port + "/") //nolint:gosec // G704: the test's own names, to its own router
		if err != nil {
			fmt.Fprintf(goOut, "(no page: %v)\n", err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		fmt.Fprintf(goOut, "%s [%s]\n", b, resp.Proto)
	}
	check(t, "go", goOut.String(), port)

	// curl, with the CA trusted.
	curlOut := &strings.Builder{}
	for _, host := range hosts {
		fmt.Fprintf(curlOut, "== https://%s:%s/\n", host, port)
		out, _ := docker(t, "run", "--rm", "--network", "host", "-v", dir+":/certs:ro", curlImage, "-sS", "--max-time", "10",
			"--cacert", "/certs/ca.pem", "--resolve", host+":"+port+":127.0.0.1", "https://"+host+":"+port+"/")
		curlOut.WriteString(out + "\n")
	}
	check(t, "curl", curlOut.String(), port)

	// The browsers, in the Playwright image.
	scripts, err := filepath.Abs("../../test/realclients")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []struct{ name, cmd string }{{"chromium", "/scripts/chromium.sh"}, {"firefox", "/scripts/firefox.sh"}} {
		out, err := docker(t, append([]string{"run", "--rm", "--network", "host", "-e", "HOME=/tmp", "-e", "PLAYWRIGHT_VERSION=" + pwVersion,
			"-v", scripts + ":/scripts:ro", pwImage, "/bin/bash", b.cmd, port}, hosts...)...)
		if err != nil {
			t.Errorf("%s: %v\n%s", b.name, err, out)
			continue
		}
		check(t, b.name, out, port)
	}
}

// check finds each name's section in a client's output and compares it with what it must show.
func check(t *testing.T, client, out, port string) {
	t.Helper()
	t.Logf("%s:\n%s", client, out)
	for _, n := range realNames {
		header := "== https://" + n.host + ":" + port + "/"
		i := strings.Index(out, header)
		if i < 0 {
			t.Errorf("%s: no result for %s", client, n.host)
			continue
		}
		section := out[i+len(header):]
		if j := strings.Index(section, "\n== "); j >= 0 {
			section = section[:j]
		}
		page := strings.Contains(section, "http-route") || strings.Contains(section, "passthrough-backend") ||
			strings.Contains(section, "controller ui")
		switch {
		case n.want == "" && page:
			t.Errorf("%s: %s got a page: %q", client, n.host, section)
		case n.want != "" && !strings.Contains(section, n.want):
			t.Errorf("%s: %s: %q, want %q", client, n.host, section, n.want)
		}
	}
}

// docker runs the docker command with args and returns its combined output.
func docker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() //nolint:gosec // G204: the test's own arguments
	return strings.TrimSpace(string(out)), err
}

// handOff is a listener fed with the connections the router hands to the controller.
type handOff struct {
	ch   chan net.Conn
	done chan struct{}
}

func newHandOff() *handOff { return &handOff{ch: make(chan net.Conn), done: make(chan struct{})} }

func (l *handOff) put(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *handOff) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handOff) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *handOff) Addr() net.Addr { return &net.TCPAddr{} }
