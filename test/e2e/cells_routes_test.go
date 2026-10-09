// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"strconv"
	"testing"
	"time"
)

// The cells of every Phase 1 route type and of the local policy, access policy and transport
// scenarios (docs/12-testing-and-quality.md, "End-to-end topology matrix"). Their routes use the
// ports from 21001 and the service's ports: TCP echo 7007 and 7009, UDP echo 7008, the HTTP
// upstream 7080 and the TLS backend 7443.

const svcHost = "172.31.0.7"

// asRoot runs a command in node as root, for iptables.
func asRoot(node string, args ...string) (string, error) {
	return compose(append([]string{"exec", "-T", "--user", "0", node}, args...)...)
}

// TestUDP: a udp route carries payloads below and above the datagram limit, through both gateways
// and over IPv4 and IPv6.
func TestUDP(t *testing.T) {
	port := 21001
	if _, err := seed("udp-route", "--name", "udp", "--port", strconv.Itoa(port), "--target", svcHost+":7008",
		"--connector", "con1", "--connector", "con2"); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{addr("gw1", port), addr("gw2", port), addr("[fd00:30::11]", port), addr("[fd00:30::12]", port)} {
		eventually(t, 30*time.Second, "the udp route through "+a, func() error {
			return client("udp", "-addr", a, "-sizes", "100,1200,3000,60000", "-duration", "5s")
		})
	}
}

// TestHTTP: http routes with uploaded certificates serve HTTP/1.1 and HTTP/2 clients from an
// HTTP/1.1 upstream, pass a WebSocket through, pass gRPC to an h2c upstream with its status
// trailers, and reach an HTTPS upstream verified with a CA bundle.
func TestHTTP(t *testing.T) {
	routes := []struct{ name, host, upstream, target, serverName string }{
		{"web", "app.e2e.test", "http", svcHost + ":7080", ""},
		{"grpc", "grpc.e2e.test", "h2c", svcHost + ":7080", ""},
		{"secure", "secure.e2e.test", "https", svcHost + ":7443", "svc"},
	}
	for _, r := range routes {
		args := []string{"--name", r.name, "--hostname", r.host, "--connector", "con1", "--connector", "con2", "--target", r.target,
			"--upstream", r.upstream, "--cert-file", "/var/lib/rpmgr/route-" + r.name + ".crt",
			"--key-file", "/var/lib/rpmgr/route-" + r.name + ".key"}
		if r.serverName != "" {
			args = append(args, "--server-name", r.serverName, "--ca-file", "/var/lib/rpmgr/web-ca.pem")
		}
		if _, err := seed("http-route", args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, gw := range []string{"gw1:8443", "gw2:8443", "[fd00:30::11]:8443"} {
		eventually(t, 30*time.Second, "HTTP/1.1 through "+gw, func() error {
			return client("http", "-addr", gw, "-url", "https://app.e2e.test/page", "-expect", "HTTP/1.1 app.e2e.test /page")
		})
		if err := client("http", "-addr", gw, "-h2", "-url", "https://app.e2e.test/h2", "-expect", "app.e2e.test /h2"); err != nil {
			t.Errorf("HTTP/2 through %s: %v", gw, err)
		}
	}
	if err := client("ws", "-addr", "gw1:8443", "-host", "app.e2e.test"); err != nil {
		t.Errorf("WebSocket: %v", err)
	}
	eventually(t, 30*time.Second, "gRPC to an h2c upstream", func() error { return client("grpc", "-addr", "gw2:8443", "-host", "grpc.e2e.test") })
	eventually(t, 30*time.Second, "an HTTPS upstream", func() error {
		return client("http", "-addr", "gw1:8443", "-h2", "-url", "https://secure.e2e.test/x", "-expect", "HTTP/2.0 secure.e2e.test /x")
	})
}

// TestPassthrough: a tls_passthrough route hands the client's TLS connection to the backend, whose
// certificate the client sees.
func TestPassthrough(t *testing.T) {
	if _, err := seed("passthrough-route", "--name", "pt", "--hostname", "pt.e2e.test", "--connector", "con1",
		"--connector", "con2", "--target", svcHost+":7443"); err != nil {
		t.Fatal(err)
	}
	for _, gw := range []string{"gw1:8443", "gw2:8443"} {
		eventually(t, 30*time.Second, "the passthrough through "+gw, func() error {
			return client("tls", "-addr", gw, "-host", "pt.e2e.test", "-expect", "e2e backend")
		})
	}
}

// TestLocalPolicy: a target the connector's local policy blocks is never served; after the policy
// file is edited the connector reloads it, without a new revision, and the route works.
func TestLocalPolicy(t *testing.T) {
	port := 21002
	if _, err := seed("route", "--name", "blocked", "--port", strconv.Itoa(port), "--target", svcHost+":7009", "--connector", "con1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second) // the snapshot is applied, the route not ready
	if err := client("gone", "-addr", addr("gw1", port), "-duration", "2s"); err != nil {
		t.Fatalf("a target the local policy blocks: %v", err)
	}
	if err := writeFile("con1", "policy.yaml",
		"version: 1\nallow_targets:\n  - cidr: 172.31.0.7/32\n    ports: [7007, 7008, 7009, 7080, 7443]\n"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "the target after the policy reload", func() error { return client("check", "-addr", addr("gw1", port)) })
}

// TestAccess_Tightened: a tightened access policy closes the open connections of the clients it
// no longer allows at once and refuses new ones; clearing it serves them again.
func TestAccess_Tightened(t *testing.T) {
	port := 21003
	addRoute(t, "acl", port, "auto", "con1", "con2")
	eventually(t, 30*time.Second, "the route", func() error { return client("check", "-addr", addr("gw1", port)) })
	held := background(func() error { return client("hold", "-addr", addr("gw1", port), "-duration", "20s") })
	time.Sleep(time.Second)
	if _, err := seed("access", "--route", "acl", "--rule", "deny=172.30.0.30/32,fd00:30::30/128"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-held:
		if err == nil {
			t.Fatal("a connection the tightened policy denies lasted its full time")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a connection the tightened policy denies is still open")
	}
	if err := client("gone", "-addr", addr("gw2", port), "-duration", "10s"); err != nil {
		t.Fatalf("a new connection of a denied client: %v", err)
	}
	if _, err := seed("access", "--route", "acl"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "the route after the rules are cleared", func() error { return client("check", "-addr", addr("gw1", port)) })
}

// TestTransport_Mixed: one connector serves a route pinned to QUIC and one pinned to h2 at once.
func TestTransport_Mixed(t *testing.T) {
	quic, h2 := 21004, 21005
	addRoute(t, "mixed-quic", quic, "quic", "con1")
	addRoute(t, "mixed-h2", h2, "h2", "con1")
	for _, p := range []int{quic, h2} {
		for _, gw := range []string{"gw1", "gw2"} {
			eventually(t, 30*time.Second, "the "+strconv.Itoa(p)+" route through "+gw, func() error { return client("check", "-addr", addr(gw, p)) })
		}
	}
	a := background(func() error { return client("hold", "-addr", addr("gw1", quic), "-duration", "3s") })
	b := background(func() error { return client("hold", "-addr", addr("gw1", h2), "-duration", "3s") })
	for _, done := range []<-chan error{a, b} {
		if err := <-done; err != nil {
			t.Fatalf("both transports at once: %v", err)
		}
	}
}

// TestTransport_UDPBlackholed: when the path between a connector and the gateways stops carrying
// UDP in the middle of a QUIC data session, its auto route moves to TLS and HTTP/2 once the session
// times out. The replies are dropped where they arrive, so the connector's packets still leave as
// on a real blackhole, rather than failing at once as a local rule on the way out makes them. It
// runs on con2, whose only links are auto ones: a connector's window budget leaves no room for
// the TLS sessions of an auto link next to those of a link pinned to h2 to both gateways.
func TestTransport_UDPBlackholed(t *testing.T) {
	port := 21006
	addRoute(t, "blackhole", port, "auto", "con2")
	eventually(t, 30*time.Second, "the route", func() error { return client("check", "-addr", addr("gw1", port)) })
	drop := []string{"INPUT", "-p", "udp", "--sport", "8443", "-j", "DROP"}
	if _, err := asRoot("con2", append([]string{"iptables", "-I"}, drop...)...); err != nil {
		t.Fatal(err)
	}
	if _, err := asRoot("con2", append([]string{"ip6tables", "-I"}, drop...)...); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = asRoot("con2", append([]string{"iptables", "-D"}, drop...)...)
		_, _ = asRoot("con2", append([]string{"ip6tables", "-D"}, drop...)...)
	}()
	start := time.Now()
	for _, gw := range []string{"gw1", "gw2"} {
		eventually(t, 120*time.Second, "the route through "+gw+" after UDP was blackholed", func() error {
			return client("check", "-addr", addr(gw, port))
		})
	}
	t.Logf("served over TLS and HTTP/2 %s after UDP was blackholed", time.Since(start).Round(time.Second))
}
