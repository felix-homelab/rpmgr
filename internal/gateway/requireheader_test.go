// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/gateway"
)

const (
	originA = "origin-secret-a-0123456789abcdefghijkl"
	originB = "origin-secret-b-0123456789abcdefghijkl"
	originC = "origin-secret-c-0123456789abcdefghijkl"
)

// requireRule is a require_header rule of a header with the hashes of values.
func requireRule(name string, values ...string) gateway.RequireHeaderRule {
	r := gateway.RequireHeaderRule{Name: name}
	for _, v := range values {
		r.Sums = append(r.Sums, sha256.Sum256([]byte(v)))
	}
	return r
}

// TestRequireHeader_StrippedAndConstantTime (docs/12, security regression tests; the constant-time
// clause is TestRequireHeaderPasses_ConstantTime): a request without the required header or with
// a wrong value is 403; any of a rule's values admits; every rule must pass; the header never
// reaches the upstream, whatever case the client writes it in; the gateway holds only hashes.
func TestRequireHeader_StrippedAndConstantTime(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "origin=%q edge=%q", r.Header.Values("X-Origin-Token"), r.Header.Values("X-Edge")) //nolint:gosec // G705: plain text echo
	})
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		RequireHeader: []gateway.RequireHeaderRule{requireRule("X-Origin-Token", originA, originB)}}
	e := newHTTPEnv(t, upstream, route)
	c := e.client(false)
	for _, tc := range []struct {
		name   string
		header http.Header
		want   int
	}{
		{"no header", nil, http.StatusForbidden},
		{"a wrong value", http.Header{"X-Origin-Token": {originC}}, http.StatusForbidden},
		{"an empty value", http.Header{"X-Origin-Token": {""}}, http.StatusForbidden},
		{"a prefix of a value", http.Header{"X-Origin-Token": {originA[:32]}}, http.StatusForbidden},
		{"the value in another header", http.Header{"X-Other": {originA}}, http.StatusForbidden},
		{"the first value", http.Header{"X-Origin-Token": {originA}}, http.StatusOK},
		{"the second value", http.Header{"X-Origin-Token": {originB}}, http.StatusOK},
		{"the name in lower case", http.Header{"x-origin-token": {originB}}, http.StatusOK},
		{"a wrong and a right value", http.Header{"X-Origin-Token": {originC, originA}}, http.StatusOK},
	} {
		r := get(t, c, "https://app.example.com/", tc.header)
		if r.status != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, r.status, tc.want)
			continue
		}
		if r.status == http.StatusOK && !strings.HasPrefix(r.body, `origin=[] `) {
			t.Errorf("%s: the upstream saw the header: %s", tc.name, r.body)
		}
		if strings.Contains(r.body, "origin-secret") {
			t.Errorf("%s: a value reached the upstream or the client: %s", tc.name, r.body)
		}
	}
	// Two rules of two policies: each must pass, and both headers stay at the gateway.
	route.RequireHeader = append(route.RequireHeader, requireRule("X-Edge", originC))
	e.routes.Apply([]gateway.HTTPRoute{route})
	if r := get(t, c, "https://app.example.com/", http.Header{"X-Origin-Token": {originA}}); r.status != http.StatusForbidden {
		t.Errorf("one of two rules passed: %d", r.status)
	}
	if r := get(t, c, "https://app.example.com/", http.Header{"X-Origin-Token": {originA}, "X-Edge": {originC}}); r.status != http.StatusOK ||
		r.body != `origin=[] edge=[]` {
		t.Errorf("both rules passed: %d %q", r.status, r.body)
	}
	// The rules come before basic auth: a request without the header never gets a challenge.
	route.RequireHeader = route.RequireHeader[:1]
	route.BasicAuth = []gateway.BasicAuthRule{rule(t, "ap_1", "v1", "alice", "pw")}
	e.routes.Apply([]gateway.HTTPRoute{route})
	if r := get(t, c, "https://app.example.com/", nil); r.status != http.StatusForbidden || r.header.Get("WWW-Authenticate") != "" {
		t.Errorf("no header with basic auth: %d %v", r.status, r.header)
	}
	if r := get(t, c, "https://app.example.com/", http.Header{"X-Origin-Token": {originA}}); r.status != http.StatusUnauthorized {
		t.Errorf("the header without credentials: %d, want 401", r.status)
	}
}

// TestRequireHeader_TighteningClosesUpgrades: a snapshot that drops the value an upgraded
// connection was admitted with ends that connection; one that keeps the value lets it go on.
func TestRequireHeader_TighteningClosesUpgrades(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", WebSocket: true, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		RequireHeader: []gateway.RequireHeaderRule{requireRule("X-Origin-Token", originA)}}
	e := newHTTPEnv(t, websocketEcho, route)
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write([]byte("GET /ws HTTP/1.1\r\nHost: app.example.com\r\nX-Origin-Token: " + originA +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v", resp.Status)
	}
	echo := func() error {
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		b := make([]byte, 4)
		_, err := io.ReadFull(br, b)
		return err
	}
	// A second value for rotation keeps the connection.
	route.RequireHeader = []gateway.RequireHeaderRule{requireRule("X-Origin-Token", originA, originB)}
	e.routes.Apply([]gateway.HTTPRoute{route})
	if err := echo(); err != nil {
		t.Fatalf("the connection after a value was added: %v", err)
	}
	route.RequireHeader = []gateway.RequireHeaderRule{requireRule("X-Origin-Token", originB)}
	e.routes.Apply([]gateway.HTTPRoute{route})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("x"))
	_, err = io.Copy(io.Discard, br)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("an upgraded connection whose value the tightened rule dropped went on")
	}
}
