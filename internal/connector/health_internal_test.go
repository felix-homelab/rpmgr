// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/upstreamtls"
)

// TestTargetHealth_Thresholds: a target turns unhealthy only after the unhealthy threshold of
// failed checks in a row and healthy again only after the healthy threshold of passed ones, so a
// flapping target, whose results alternate, never changes state.
func TestTargetHealth_Thresholds(t *testing.T) {
	c := &HealthCheck{Unhealthy: 3, Healthy: 2}
	run := func(h *targetHealth, results string) string {
		var out strings.Builder
		for _, r := range results {
			h.observe(r == '+', c)
			out.WriteString(map[bool]string{true: "u", false: "h"}[h.unhealthy])
		}
		return out.String()
	}
	for _, tc := range []struct{ results, want string }{
		{"+++", "hhh"},
		{"--", "hh"},
		{"---", "hhu"},
		{"--+-", "hhhh"},         // a pass in between starts the count again
		{"-+-+-+-+", "hhhhhhhh"}, // flapping stays healthy
		{"---+-++", "hhuuuuh"},   // back after two passes in a row
		{"---+-+-+", "hhuuuuuu"}, // flapping stays unhealthy
	} {
		if got := run(&targetHealth{}, tc.results); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.results, got, tc.want)
		}
	}
	h := &targetHealth{}
	if !(h.observe(false, &HealthCheck{Unhealthy: 1, Healthy: 1})) || !h.unhealthy {
		t.Error("a threshold of 1 did not turn the target unhealthy at once")
	}
}

// targetOf is a target at the address of a URL.
func targetOf(t *testing.T, raw string) Target {
	t.Helper()
	u, _ := url.Parse(raw)
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	return Target{ID: "tg_1", Host: host, Port: uint16(p)} //nolint:gosec // G115: a test port
}

func checking(t *testing.T, p *policy.Policy) *Targets {
	t.Helper()
	tg := NewTargets(TargetsOptions{Policy: func() *policy.Policy { return p }})
	t.Cleanup(tg.Close)
	return tg
}

func loopbackPolicy(t *testing.T, ports ...int) *policy.Policy {
	t.Helper()
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = strconv.Itoa(p)
	}
	p, err := policy.Parse([]byte("version: 1\nallow_targets:\n  - cidr: 127.0.0.0/8\n    ports: [" + strings.Join(list, ", ") + "]\n"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestHealthCheck_HTTP: an http check sends a GET of its path with its Host, passes on a status in
// its range, follows no redirect, reads no more than a capped part of the body, and fails on any
// other status; a tcp check passes when the dial does.
func TestHealthCheck_HTTP(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/ok":
		case "/moved":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "/big":
			chunk := strings.Repeat("x", 32<<10)
			for range 1000 { // 32 MB, which the check never reads
				if _, err := w.Write([]byte(chunk)); err != nil {
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	tg := targetOf(t, srv.URL)
	targets := checking(t, loopbackPolicy(t, int(tg.Port)))
	check := func(c HealthCheck) error {
		c.Timeout = 5 * time.Second
		return targets.check(context.Background(), Route{ID: "rt_1", Check: &c}, tg)
	}
	http200to399 := HealthCheck{HTTP: true, Host: "app.example.com", StatusMin: 200, StatusMax: 399}
	for path, ok := range map[string]bool{"/ok": true, "/moved": true, "/missing": false} {
		c := http200to399
		c.Path = path
		if err := check(c); (err == nil) != ok {
			t.Errorf("%s: %v, want passing %t", path, err, ok)
		}
	}
	strict := http200to399
	strict.Path, strict.StatusMax = "/moved", 200
	if err := check(strict); err == nil {
		t.Error("a 302 passed a check of 200 to 200")
	}
	big := http200to399
	big.Path = "/big"
	start := time.Now()
	if err := check(big); err != nil || time.Since(start) > 3*time.Second {
		t.Errorf("a large body: %v after %v", err, time.Since(start))
	}
	if err := check(HealthCheck{}); err != nil {
		t.Errorf("a tcp check: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen {
		if strings.HasSuffix(s, "/elsewhere") || !strings.HasPrefix(s, "app.example.com ") {
			t.Errorf("the service saw %q", s)
		}
	}
}

// TestHealthCheck_HTTPSVerifiesLikeTraffic: an https check verifies the target's certificate by
// the target's own settings, as the gateway verifies the route's traffic: its CA bundle and name,
// its pin, or nothing for a target marked unverified; a target without settings fails.
func TestHealthCheck_HTTPSVerifiesLikeTraffic(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another CA"}, DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	otherCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pin := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	tg := targetOf(t, srv.URL)
	targets := checking(t, loopbackPolicy(t, int(tg.Port)))
	for name, tc := range map[string]struct {
		tls *upstreamtls.Settings
		ok  bool
	}{
		"its CA and name":   {&upstreamtls.Settings{ServerName: "example.com", CAPEM: ca}, true},
		"another CA":        {&upstreamtls.Settings{ServerName: "example.com", CAPEM: otherCA}, false},
		"another name":      {&upstreamtls.Settings{ServerName: "wrong.test", CAPEM: ca}, false},
		"the host's store":  {&upstreamtls.Settings{ServerName: "example.com"}, false},
		"marked unverified": {&upstreamtls.Settings{ServerName: "example.com", Verify: upstreamtls.Nothing}, true},
		"its pinned key":    {&upstreamtls.Settings{ServerName: "example.com", Verify: upstreamtls.PinnedKey, SPKISHA256: pin[:]}, true},
		"another pin":       {&upstreamtls.Settings{ServerName: "example.com", Verify: upstreamtls.PinnedKey, SPKISHA256: make([]byte, 32)}, false},
		"no settings":       {nil, false},
	} {
		target := tg
		target.TLS = tc.tls
		c := &HealthCheck{HTTP: true, HTTPS: true, Path: "/", StatusMin: 200, StatusMax: 399, Timeout: 5 * time.Second}
		if err := targets.check(context.Background(), Route{ID: "rt_1", Check: c}, target); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want passing %t", name, err, tc.ok)
		}
	}
}

// TestHealthCheckOf: a snapshot's check takes the defaults of docs/03 for what it leaves at 0.
func TestHealthCheckOf(t *testing.T) {
	if healthCheckOf(nil) != nil {
		t.Error("no check became one")
	}
	got := healthCheckOf(&agentv1.HealthCheck{Type: "http", Host: "app.example.com"})
	want := HealthCheck{HTTP: true, Path: "/", Host: "app.example.com", StatusMin: 200, StatusMax: 399, Interval: 10 * time.Second,
		Timeout: 5 * time.Second, Unhealthy: 3, Healthy: 2}
	if *got != want {
		t.Errorf("defaults %+v, want %+v", *got, want)
	}
	got = healthCheckOf(&agentv1.HealthCheck{Type: "tcp", Port: 8080, IntervalMs: 3000, TimeoutMs: 1000, UnhealthyThreshold: 5,
		HealthyThreshold: 1, Https: true})
	want = HealthCheck{HTTPS: true, Path: "/", Port: 8080, StatusMin: 200, StatusMax: 399, Interval: 3 * time.Second, Timeout: time.Second,
		Unhealthy: 5, Healthy: 1}
	if *got != want {
		t.Errorf("set %+v, want %+v", *got, want)
	}
}

// rawService answers every connection with answer, then keeps it open, as a keep-alive server
// does, until the test ends.
func rawService(t *testing.T, answer func(net.Conn)) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf) // the request
				answer(c)
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
}

// TestHealthCheck_BoundedAnswer: an http check reads at most a capped header and body: a header
// larger than the cap fails the check at once, and an endless chunked body on a kept-alive
// connection passes once the status is read, without waiting for the timeout.
func TestHealthCheck_BoundedAnswer(t *testing.T) {
	huge := rawService(t, func(c net.Conn) {
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("x", 1<<20) + "\r\n\r\n"))
	})
	endless := rawService(t, func(c net.Conn) {
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"))
		chunk := []byte("1000\r\n" + strings.Repeat("y", 0x1000) + "\r\n")
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	})
	targets := checking(t, loopbackPolicy(t, int(huge), int(endless)))
	c := &HealthCheck{HTTP: true, Path: "/", StatusMin: 200, StatusMax: 399, Timeout: 5 * time.Second}
	start := time.Now()
	if err := targets.check(context.Background(), Route{ID: "rt_1", Check: c}, Target{ID: "tg_1", Host: "127.0.0.1", Port: huge}); err == nil ||
		time.Since(start) > 3*time.Second {
		t.Errorf("a 1 MiB header: %v after %v", err, time.Since(start))
	}
	start = time.Now()
	if err := targets.check(context.Background(), Route{ID: "rt_1", Check: c}, Target{ID: "tg_2", Host: "127.0.0.1", Port: endless}); err != nil ||
		time.Since(start) > 3*time.Second {
		t.Errorf("an endless chunked body: %v after %v", err, time.Since(start))
	}
}

// TestHealthCheck_UnixHost: an http check of a socket target without a Host of its own sends
// "localhost", never the socket's path.
func TestHealthCheck_UnixHost(t *testing.T) {
	path := t.TempDir() + "/app.sock"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	hosts := make(chan string, 1)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case hosts <- r.Host:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	p, err := policy.Parse([]byte("version: 1\nallow_targets: [\"" + path + "\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	targets := checking(t, p)
	c := &HealthCheck{HTTP: true, Path: "/", StatusMin: 200, StatusMax: 399, Timeout: 5 * time.Second}
	if err := targets.check(context.Background(), Route{ID: "rt_1", Check: c}, Target{ID: "tg_1", UnixPath: path}); err != nil {
		t.Fatal(err)
	}
	if h := <-hosts; h != "localhost" {
		t.Errorf("Host %q, want localhost", h)
	}
}
