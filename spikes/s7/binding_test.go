// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// Criterion 6: a CSR bound to the TLS session with exported keying material; a replayed CSR
// fails; the binding also works on resumed sessions and over HTTP/2.
func TestCSRBinding(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	conID := connectorID("org_a", "con_1")
	ctlID := controllerID("node_1")
	con := issue(t, ca, conID, ProfileConnector, AgentLeafLifetime)
	ctl := issue(t, ca, ctlID, ProfileController, ControllerLifetime)
	srv := ServerConfig(ctl.tls, ca.Roots(), Expect{TrustDomain: td, Kinds: []Kind{KindConnector}}, clk.Now)
	cliCfg := func(cache tls.ClientSessionCache) *tls.Config {
		return ClientConfig(con.tls, ca.Roots(), "controller."+td, Expect{TrustDomain: td, Kinds: []Kind{KindController}}, clk.Now, cache)
	}

	t.Run("bound CSR accepted", func(t *testing.T) {
		var got *x509.Certificate
		r := run(t, srv, cliCfg(nil), serveIssue(ca, ProfileConnector), requestIssue(boundCSR(newKey(t)), &got))
		if !r.ok() || got == nil {
			t.Fatalf("server %v, client %v", r.srvErr, r.cliErr)
		}
	})
	t.Run("CSR replayed on another connection", func(t *testing.T) {
		var captured *x509.CertificateRequest
		k := newKey(t)
		capture := func(cs tls.ConnectionState) (*x509.CertificateRequest, error) {
			csr, err := NewBoundCSR(k, cs)
			captured = csr
			return csr, err
		}
		var got *x509.Certificate
		if r := run(t, srv, cliCfg(nil), serveIssue(ca, ProfileConnector), requestIssue(capture, &got)); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		replay := func(tls.ConnectionState) (*x509.CertificateRequest, error) { return captured, nil }
		r := run(t, srv, cliCfg(nil), serveIssue(ca, ProfileConnector), requestIssue(replay, &got))
		if !errIs(r.srvErr, ErrBindingMismatch) {
			t.Fatalf("server %v", r.srvErr)
		}
	})
	t.Run("CSR without a binding", func(t *testing.T) {
		plain := func(tls.ConnectionState) (*x509.CertificateRequest, error) { return plainCSR(t, newKey(t)), nil }
		var got *x509.Certificate
		if r := run(t, srv, cliCfg(nil), serveIssue(ca, ProfileConnector), requestIssue(plain, &got)); !errIs(r.srvErr, ErrNoBinding) {
			t.Fatalf("server %v", r.srvErr)
		}
	})
	t.Run("altered binding, re-signed by the agent's key", func(t *testing.T) {
		k := newKey(t)
		altered := func(cs tls.ConnectionState) (*x509.CertificateRequest, error) {
			b, err := ExportBinding(cs)
			if err != nil {
				return nil, err
			}
			b[0] ^= 1
			return newCSRWithBinding(k, b)
		}
		var got *x509.Certificate
		if r := run(t, srv, cliCfg(nil), serveIssue(ca, ProfileConnector), requestIssue(altered, &got)); !errIs(r.srvErr, ErrBindingMismatch) {
			t.Fatalf("server %v", r.srvErr)
		}
	})
	t.Run("resumed session", func(t *testing.T) {
		cache := tls.NewLRUClientSessionCache(4)
		cfg := cliCfg(cache)
		var first, second []byte
		record := func(dst *[]byte) func(tls.ConnectionState) (*x509.CertificateRequest, error) {
			key := newKey(t)
			return func(cs tls.ConnectionState) (*x509.CertificateRequest, error) {
				b, err := ExportBinding(cs)
				*dst = b
				if err != nil {
					return nil, err
				}
				return NewBoundCSR(key, cs)
			}
		}
		// The first connection must also read the ticket, so the request/response exchange is
		// followed by the default byte exchange.
		var got *x509.Certificate
		srvFn := func(c *tls.Conn) error {
			if err := serveIssue(ca, ProfileConnector)(c); err != nil {
				return err
			}
			_, err := c.Write([]byte{1})
			return err
		}
		cliFn := func(f func(tls.ConnectionState) (*x509.CertificateRequest, error)) func(*tls.Conn) error {
			return func(c *tls.Conn) error {
				if err := requestIssue(f, &got)(c); err != nil {
					return err
				}
				_, err := io.ReadFull(c, make([]byte, 1))
				return err
			}
		}
		if r := run(t, srv, cfg, srvFn, cliFn(record(&first))); !r.ok() || r.cli.DidResume {
			t.Fatalf("first: %v %v", r.srvErr, r.cliErr)
		}
		r := run(t, srv, cfg, srvFn, cliFn(record(&second)))
		if !r.ok() || !r.cli.DidResume || !r.srv.DidResume {
			t.Fatalf("resumed: server %v, client %v, resumed %v", r.srvErr, r.cliErr, r.cli.DidResume)
		}
		if len(first) != BindingLen || bytes.Equal(first, second) {
			t.Fatal("the resumed connection must have its own binding value")
		}
	})
	t.Run("over HTTP/2 (net/http)", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			csr, err := x509.ParseCertificateRequest(body)
			if err == nil {
				err = VerifyBinding(csr, *r.TLS)
			}
			if err != nil {
				http.Error(w, err.Error(), 403)
				return
			}
			w.Write([]byte(r.Proto))
		})
		hs := srv.Clone()
		hs.NextProtos = []string{"h2"}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: mux}
		go server.Serve(tls.NewListener(ln, hs))
		defer server.Close()

		post := func(csrFn func(tls.ConnectionState) (*x509.CertificateRequest, error)) (int, string) {
			cc := cliCfg(nil)
			cc.NextProtos = []string{"h2"}
			conn, err := tls.Dial("tcp", ln.Addr().String(), cc)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := csrFn(conn.ConnectionState())
			if err != nil {
				t.Fatal(err)
			}
			used := false
			tr := &http.Transport{
				ForceAttemptHTTP2: true,
				DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
					if used {
						return nil, errors.New("one connection only")
					}
					used = true
					return conn, nil
				},
			}
			defer tr.CloseIdleConnections()
			resp, err := (&http.Client{Transport: tr}).Post("https://controller."+td+"/enroll", "application/pkcs10", bytes.NewReader(csr.Raw))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, strings.TrimSpace(string(b))
		}
		if code, body := post(boundCSR(newKey(t))); code != 200 || body != "HTTP/2.0" {
			t.Fatalf("bound CSR over HTTP/2: %d %s", code, body)
		}
		plain := func(tls.ConnectionState) (*x509.CertificateRequest, error) { return plainCSR(t, newKey(t)), nil }
		if code, body := post(plain); code != 403 || !strings.Contains(body, ErrNoBinding.Error()) {
			t.Fatalf("unbound CSR over HTTP/2: %d %s", code, body)
		}
	})
	t.Run("no exporter when renegotiation is enabled", func(t *testing.T) {
		cfg := cliCfg(nil)
		cfg.Renegotiation = tls.RenegotiateOnceAsClient
		check := func(c *tls.Conn) error {
			_, err := ExportBinding(c.ConnectionState())
			return err
		}
		r := run(t, srv, cfg, func(c *tls.Conn) error { _, err := io.ReadAll(c); return err }, check)
		if r.cliErr == nil {
			t.Fatal("ExportKeyingMaterial worked with Renegotiation set")
		}
		t.Logf("client: %v", r.cliErr)
	})
}
