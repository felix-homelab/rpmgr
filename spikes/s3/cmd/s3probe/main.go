// SPDX-License-Identifier: Apache-2.0

// Command s3probe is the Go crypto/tls and quic-go client of the real-client runs: it reaches
// every route of a running s3gw over TCP (directly and through the segmenting relay) and over
// UDP (h3 and the QUIC tunnel), and prints one line per attempt.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/felix-homelab/rpmgr/spikes/s3/mux"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "gateway TCP and UDP address")
	relay := flag.String("relay", "127.0.0.1:18444", "segmenting relay address")
	dir := flag.String("certs", "", "directory written by s3gw -certs")
	flag.Parse()
	public := pool(filepath.Join(*dir, "public-ca.pem"))
	internal := pool(filepath.Join(*dir, "internal-ca.pem"))
	conn, err := tls.LoadX509KeyPair(filepath.Join(*dir, "connector.pem"), filepath.Join(*dir, "connector.key"))
	if err != nil {
		log.Fatal(err)
	}
	td := mux.TestTrustDomain
	fmt.Printf("client: Go %s crypto/tls, quic-go v0.63.0\n", runtime.Version())

	for _, target := range []struct{ name, addr string }{{"direct", *addr}, {"relay", *relay}} {
		for _, tc := range []struct {
			host string
			cfg  *tls.Config
			want string
		}{
			{mux.TestHTTPHost, &tls.Config{RootCAs: public}, "http-route host=" + mux.TestHTTPHost},
			{mux.TestHTTPHost2, &tls.Config{RootCAs: public}, "http-route host=" + mux.TestHTTPHost2},
			{mux.TestPassHost, &tls.Config{RootCAs: public}, "passthrough-backend"},
			{mux.TestUIHost, &tls.Config{RootCAs: public}, "endpoint=ui"},
			{"controller." + td, &tls.Config{RootCAs: internal, Certificates: []tls.Certificate{conn}}, "endpoint=agent"},
			{"unknown.example.test", &tls.Config{RootCAs: public}, "(expected failure)"},
		} {
			tc.cfg.ServerName = tc.host
			body, err := get(target.addr, tc.cfg)
			report("tcp-"+target.name, tc.host, body, err, tc.want)
		}
		line, err := tunnelH2(target.addr, internal, conn)
		report("tcp-"+target.name, mux.TunnelName()+" ["+mux.ALPNTunnelH2+"]", line, err, "tunnel-h2 peer=")
	}

	// UDP: h3 and the QUIC tunnel on the same socket.
	h3 := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: public},
		Dial: func(ctx context.Context, _ string, c *tls.Config, q *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, *addr, c, q)
		},
	}
	defer h3.Close()
	for _, host := range []string{mux.TestHTTPHost, mux.TestHTTPHost2} {
		resp, err := (&http.Client{Transport: h3, Timeout: 10 * time.Second}).Get("https://" + host + "/")
		body := ""
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
		}
		report("udp", host+" [h3]", body, err, "h3 host="+host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, *addr, &tls.Config{ServerName: mux.TunnelName(), RootCAs: internal,
		Certificates: []tls.Certificate{conn}, NextProtos: []string{mux.ALPNTunnelQUIC}, MinVersion: tls.VersionTLS13}, nil)
	line := ""
	if err == nil {
		var s *quic.Stream
		if s, err = qc.OpenStreamSync(ctx); err == nil {
			_, _ = io.WriteString(s, "hello\n")
			_ = s.Close()
			line, err = bufio.NewReader(s).ReadString('\n')
		}
		_ = qc.CloseWithError(0, "")
	}
	report("udp", mux.TunnelName()+" ["+mux.ALPNTunnelQUIC+"]", line, err, "tunnel-quic peer=")
}

func get(addr string, cfg *tls.Config) (string, error) {
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
		}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + cfg.ServerName + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func tunnelH2(addr string, roots *x509.CertPool, cert tls.Certificate) (string, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		ServerName: mux.TunnelName(), RootCAs: roots, Certificates: []tls.Certificate{cert},
		NextProtos: []string{mux.ALPNTunnelH2}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "hello\n")
	return bufio.NewReader(c).ReadString('\n')
}

func report(path, target, body string, err error, want string) {
	status := "ok"
	switch {
	case want == "(expected failure)" && err != nil:
		status = "refused-as-expected"
	case err != nil:
		status = "ERROR " + err.Error()
	case !strings.Contains(body, want):
		status = "UNEXPECTED"
	}
	fmt.Printf("%-10s %-55s %-22s %s\n", path, target, status, strings.TrimSpace(firstLine(body, err)))
}

func firstLine(body string, err error) string {
	if err != nil {
		return err.Error()
	}
	return strings.SplitN(body, "\n", 2)[0]
}

func pool(path string) *x509.CertPool {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		log.Fatalf("no certificate in %s", path)
	}
	return p
}
