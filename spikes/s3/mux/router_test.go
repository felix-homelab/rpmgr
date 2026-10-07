// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type testGW struct {
	*Gateway
	addr string
}

func startGateway(t *testing.T, tweak func(*Router)) *testGW {
	t.Helper()
	certs, err := NewCerts()
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGateway(certs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tweak != nil {
		tweak(g.Router)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Router.Serve(l) }()
	t.Cleanup(func() { _ = l.Close(); g.Close() })
	return &testGW{Gateway: g, addr: l.Addr().String()}
}

// lastEvent waits for the router's event for the n-th connection (1-based).
func (g *testGW) eventN(t *testing.T, n int) Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ev := g.Events(); len(ev) >= n {
			return ev[n-1]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no event #%d", n)
	return Event{}
}

// get performs one HTTPS GET through the gateway with the given TLS client configuration.
func (g *testGW) get(t *testing.T, cfg *tls.Config) (string, error) {
	t.Helper()
	tr2 := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, DialContext: (&dialer{addr: g.addr}).DialContext}
	defer tr2.CloseIdleConnections()
	c := &http.Client{Transport: tr2, Timeout: 10 * time.Second}
	resp, err := c.Get("https://" + cfg.ServerName + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestRouter_Controller(t *testing.T) {
	g := startGateway(t, nil)
	c := g.Certs
	td := TestTrustDomain
	agent := &tls.Config{ServerName: "controller." + td, RootCAs: c.Internal.Pool(), Certificates: []tls.Certificate{c.Connector}}
	body, err := g.get(t, agent)
	if err != nil || !strings.Contains(body, "endpoint=agent peer="+c.ConnectorSPIFFE) || !strings.Contains(body, "HTTP/2.0") {
		t.Fatalf("agent endpoint: %q %v", body, err)
	}
	reauth := &tls.Config{ServerName: "reauth.controller." + td, RootCAs: c.Internal.Pool(), Certificates: []tls.Certificate{c.Connector}}
	if body, err := g.get(t, reauth); err != nil || !strings.Contains(body, "endpoint=reauth") {
		t.Fatalf("reauth endpoint: %q %v", body, err)
	}
	ui := &tls.Config{ServerName: TestUIHost, RootCAs: c.Public.Pool()}
	if body, err := g.get(t, ui); err != nil || !strings.Contains(body, "endpoint=ui") {
		t.Fatalf("UI: %q %v", body, err)
	}
	// Error cases: the agent name needs a client certificate from the pinned CA and TLS 1.3, and
	// the UI's public certificate does not satisfy an agent that trusts only the pinned root.
	if _, err := g.get(t, &tls.Config{ServerName: "controller." + td, RootCAs: c.Internal.Pool()}); err == nil {
		t.Fatal("agent endpoint without client certificate succeeded")
	}
	if _, err := g.get(t, &tls.Config{ServerName: "controller." + td, RootCAs: c.Internal.Pool(),
		Certificates: []tls.Certificate{c.Connector}, MaxVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("agent endpoint with TLS 1.2 succeeded")
	}
	if _, err := g.get(t, &tls.Config{ServerName: TestUIHost, RootCAs: c.Internal.Pool()}); err == nil {
		t.Fatal("UI verified against the pinned root")
	}
	for i, ev := range g.Events() {
		if ev.Decision != DecideController {
			t.Fatalf("event %d: %s", i, ev.Decision)
		}
	}
}

func tunnelClient(c *Certs, serverName string, alpn []string, cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{ServerName: serverName, RootCAs: c.Internal.Pool(), NextProtos: alpn,
		MinVersion: tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := SPIFFEFromChain(cs.VerifiedChains)
			if err != nil {
				return err
			}
			if id != c.GatewaySPIFFE {
				return fmt.Errorf("gateway identity %s, want %s", id, c.GatewaySPIFFE)
			}
			return nil
		}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func dialTunnel(addr string, cfg *tls.Config) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	return line, err
}

func TestRouter_TunnelH2(t *testing.T) {
	g := startGateway(t, nil)
	c := g.Certs
	line, err := dialTunnel(g.addr, tunnelClient(c, TunnelName(), []string{ALPNTunnelH2}, &c.Connector))
	if err != nil || !strings.Contains(line, "peer="+c.ConnectorSPIFFE) || !strings.Contains(line, "alpn="+ALPNTunnelH2) {
		t.Fatalf("tunnel: %q %v", line, err)
	}
	if ev := g.eventN(t, 1); ev.Decision != DecideTunnelH2 || ev.SNI != TunnelName() {
		t.Fatalf("event %+v", ev)
	}
	// The SNI carries the upper-case, underscored gateway ID; lower case routes the same.
	if line, err := dialTunnel(g.addr, tunnelClient(c, strings.ToLower(TunnelName()), []string{ALPNTunnelH2}, &c.Connector)); err != nil {
		t.Fatalf("lower-case SNI: %q %v", line, err)
	}

	gatewayCert := c.Gateway
	other := "gw_01JA2Z8Q6W7Y3V9K4M5N6P7Q8Z.gateway." + TestTrustDomain
	for _, tc := range []struct {
		name string
		cfg  *tls.Config
		want Decision
	}{
		{"tunnel name without the tunnel ALPN", tunnelClient(c, TunnelName(), []string{"h2"}, &c.Connector), DecideDefault},
		{"tunnel name without any ALPN", tunnelClient(c, TunnelName(), nil, &c.Connector), DecideDefault},
		{"another gateway's name", tunnelClient(c, other, []string{ALPNTunnelH2}, &c.Connector), DecideDefault},
		{"no client certificate", tunnelClient(c, TunnelName(), []string{ALPNTunnelH2}, nil), DecideTunnelH2},
		{"a gateway certificate instead of a connector's", tunnelClient(c, TunnelName(), []string{ALPNTunnelH2}, &gatewayCert), DecideTunnelH2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := len(g.Events())
			if line, err := dialTunnel(g.addr, tc.cfg); err == nil {
				t.Fatalf("succeeded: %q", line)
			}
			if ev := g.eventN(t, n+1); ev.Decision != tc.want {
				t.Fatalf("decision %s, want %s", ev.Decision, tc.want)
			}
		})
	}
	// A client of another installation (foreign root) is refused by the gateway, and the gateway
	// is refused by a connector that pins another root.
	foreign, _ := NewCerts()
	if _, err := dialTunnel(g.addr, tunnelClient(foreign, TunnelName(), []string{ALPNTunnelH2}, &foreign.Connector)); err == nil {
		t.Fatal("foreign installation accepted")
	}
}

func TestRouter_PassthroughNeverTerminates(t *testing.T) {
	g := startGateway(t, nil)
	c := g.Certs
	var seen *x509.Certificate
	cfg := &tls.Config{ServerName: TestPassHost, RootCAs: c.Public.Pool(),
		VerifyConnection: func(cs tls.ConnectionState) error { seen = cs.PeerCertificates[0]; return nil }}
	body, err := g.get(t, cfg)
	if err != nil || !strings.Contains(body, "passthrough-backend sni="+TestPassHost) {
		t.Fatalf("passthrough: %q %v", body, err)
	}
	if !seen.Equal(c.Pass.Leaf) {
		t.Fatal("client did not see the backend's own certificate")
	}
	if ev := g.eventN(t, 1); ev.Decision != DecidePassthrough {
		t.Fatalf("event %+v", ev)
	}
}

func TestRouter_HTTPPerSNICertificates(t *testing.T) {
	g := startGateway(t, nil)
	c := g.Certs
	for _, tc := range []struct {
		host  string
		cert  tls.Certificate
		proto []string
		want  string
	}{
		{TestHTTPHost, c.HTTP, nil, "HTTP/2.0"},
		{TestHTTPHost2, c.HTTP2, nil, "HTTP/2.0"},
		{TestHTTPHost, c.HTTP, []string{"http/1.1"}, "HTTP/1.1"},
	} {
		var seen *x509.Certificate
		cfg := &tls.Config{ServerName: tc.host, RootCAs: c.Public.Pool(), NextProtos: tc.proto,
			VerifyConnection: func(cs tls.ConnectionState) error { seen = cs.PeerCertificates[0]; return nil }}
		var body string
		var err error
		if tc.proto == nil {
			body, err = g.get(t, cfg)
		} else {
			body, err = getHTTP1(g.addr, cfg)
		}
		if err != nil || !strings.Contains(body, "host="+tc.host) || !strings.Contains(body, tc.want) {
			t.Fatalf("%s: %q %v", tc.host, body, err)
		}
		if !seen.Equal(tc.cert.Leaf) {
			t.Fatalf("%s: wrong certificate %v", tc.host, seen.DNSNames)
		}
	}
}

func getHTTP1(addr string, cfg *tls.Config) (string, error) {
	tr := &http.Transport{TLSClientConfig: cfg, DialContext: (&dialer{addr: addr}).DialContext}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + cfg.ServerName + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestRouter_UnknownAndMissingSNI(t *testing.T) {
	g := startGateway(t, nil)
	c := g.Certs
	// Unknown SNI: the handshake reaches certificate verification with the default certificate.
	_, err := tls.Dial("tcp", g.addr, &tls.Config{ServerName: "unknown.example.test", RootCAs: c.Public.Pool()})
	if err == nil || !strings.Contains(err.Error(), "default.invalid") {
		t.Fatalf("unknown SNI: %v", err)
	}
	// A client that accepts the default certificate completes the handshake and is then closed.
	conn, err := tls.Dial("tcp", g.addr, &tls.Config{ServerName: "default.invalid", RootCAs: c.Public.Pool()})
	if err != nil {
		t.Fatalf("default certificate handshake: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("expected close, got %d bytes %v", n, err)
	}
	conn.Close()
	// No SNI at all (a crafted ClientHello): the gateway answers with a ServerHello, then closes.
	raw, _ := net.Dial("tcp", g.addr)
	defer raw.Close()
	_, _ = raw.Write(records(synthHello(t, "", nil, 0)))
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(raw, hdr); err != nil || hdr[0] != recordTypeHandshake {
		t.Fatalf("no ServerHello for a ClientHello without SNI: % x %v", hdr, err)
	}
	evs := g.Events()
	for i, ev := range evs {
		if ev.Decision != DecideDefault {
			t.Fatalf("event %d: %+v", i, ev)
		}
	}
	if evs[len(evs)-1].SNI != "" {
		t.Fatal("expected an empty SNI in the last event")
	}
}

func TestRouter_NotTLSSlowAndOversize(t *testing.T) {
	g := startGateway(t, func(r *Router) { r.PeekTimeout = 400 * time.Millisecond })
	// Not TLS: closed without a byte in return.
	c1, _ := net.Dial("tcp", g.addr)
	defer c1.Close()
	_, _ = io.WriteString(c1, "GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
	_ = c1.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c1.Read(make([]byte, 64)); n != 0 || err == nil {
		t.Fatalf("plain HTTP got %d bytes (%v)", n, err)
	}
	if ev := g.eventN(t, 1); ev.Decision != DecideNotTLS {
		t.Fatalf("event %+v", ev)
	}
	// Slowloris: closed when the peek timeout expires.
	c2, _ := net.Dial("tcp", g.addr)
	defer c2.Close()
	_, _ = c2.Write(records(synthHello(t, "slow.example.test", nil, 0))[:30])
	start := time.Now()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c2.Read(make([]byte, 1))
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("slow client: %v after %v", err, time.Since(start))
	}
	if ev := g.eventN(t, 2); ev.Decision != DecidePeekFailed {
		t.Fatalf("event %+v", ev)
	}
	// Oversize: one byte above 16 KiB is refused, exactly 16 KiB is routed.
	for i, size := range []int{MaxPeekBytes + 1, MaxPeekBytes} {
		c3, _ := net.Dial("tcp", g.addr)
		_, _ = c3.Write(records(synthHello(t, TestHTTPHost, nil, size-recordHeaderLen), size))
		ev := g.eventN(t, 3+i)
		c3.Close()
		want := DecidePeekFailed
		if size == MaxPeekBytes {
			want = DecideHTTP
		}
		if ev.Decision != want {
			t.Fatalf("size %d: %+v", size, ev)
		}
	}
}

func TestRouter_SegmentedDelivery(t *testing.T) {
	g := startGateway(t, nil)
	c := g.Certs
	// A relay that forwards client bytes one at a time, so every peek spans many reads.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", g.addr)
			if err != nil {
				in.Close()
				continue
			}
			go func() {
				buf := make([]byte, 1)
				for {
					if _, err := io.ReadFull(in, buf); err != nil {
						_ = out.(*net.TCPConn).CloseWrite()
						return
					}
					_ = writeChunks(out, buf, 1, 0)
					time.Sleep(50 * time.Microsecond)
				}
			}()
			go func() { _, _ = io.Copy(in, out); in.Close() }()
		}
	}()
	line, err := dialTunnel(l.Addr().String(), tunnelClient(c, TunnelName(), []string{ALPNTunnelH2}, &c.Connector))
	if err != nil || !strings.Contains(line, "tunnel-h2 peer=") {
		t.Fatalf("tunnel via 1-byte relay: %q %v", line, err)
	}
	ev := g.eventN(t, 1)
	if ev.Decision != DecideTunnelH2 || ev.Reads < 100 {
		t.Fatalf("event %+v", ev)
	}
	t.Logf("ClientHello of %d bytes peeked in %d reads", ev.HelloSize, ev.Reads)
}

func TestRouter_ConcurrentMixedTraffic(t *testing.T) {
	g := startGateway(t, nil)
	c := g.Certs
	cases := []func() error{
		func() error {
			_, err := dialTunnel(g.addr, tunnelClient(c, TunnelName(), []string{ALPNTunnelH2}, &c.Connector))
			return err
		},
		func() error {
			b, err := getHTTP1(g.addr, &tls.Config{ServerName: TestHTTPHost, RootCAs: c.Public.Pool()})
			if err == nil && !strings.Contains(b, "host="+TestHTTPHost) {
				err = fmt.Errorf("body %q", b)
			}
			return err
		},
		func() error {
			b, err := getHTTP1(g.addr, &tls.Config{ServerName: TestPassHost, RootCAs: c.Public.Pool()})
			if err == nil && !strings.Contains(b, "passthrough-backend") {
				err = fmt.Errorf("body %q", b)
			}
			return err
		},
		func() error {
			b, err := getHTTP1(g.addr, &tls.Config{ServerName: "controller." + TestTrustDomain, RootCAs: c.Internal.Pool(), Certificates: []tls.Certificate{c.Connector}})
			if err == nil && !strings.Contains(b, "endpoint=agent") {
				err = fmt.Errorf("body %q", b)
			}
			return err
		},
	}
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for i := range 400 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cases[i%len(cases)](); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// dialer sends every connection to addr, whatever host the client asks for.
type dialer struct{ addr string }

func (d *dialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", d.addr)
}
