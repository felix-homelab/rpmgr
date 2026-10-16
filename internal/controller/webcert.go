// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"

	"github.com/felix-homelab/rpmgr/internal/acme"
)

// webCertReload is how often the certificate files of the public URL are checked for changes; a
// variable for tests.
var webCertReload = time.Minute

// hstsHeader is sent with every web response while the public URL has a certificate clients trust
// (docs/04-security.md, "Controller certificates").
const hstsHeader = "max-age=31536000"

// webCert is the certificate of the public URL (docs/10-operations.md, "Boot files"): from
// tls.cert_file and tls.key_file, read again when either file changes, keeping the previous
// certificate if the new pair does not load; or, without files, the one ACME obtained, and a
// self-signed certificate made at start until then or for a name ACME cannot serve.
type webCert struct {
	certFile, keyFile string
	acme              *acme.Own // nil without ACME
	logger            *slog.Logger

	mu      sync.Mutex
	cur     *tls.Certificate
	checked time.Time
	stamp   string // the files' sizes and modification times at the last load
}

func newWebCert(certFile, keyFile, host string, own *acme.Own, logger *slog.Logger) (*webCert, error) {
	w := &webCert{certFile: certFile, keyFile: keyFile, acme: own, logger: logger}
	if certFile == "" {
		c, err := selfSigned(host)
		if err != nil {
			return nil, err
		}
		if own == nil {
			logger.Warn("the public URL has a self-signed certificate: set tls.cert_file and tls.key_file, or use a public DNS name "+
				"for ACME", "host", host)
		} else {
			logger.Info("the public URL has a self-signed certificate until ACME obtains one", "host", host)
		}
		w.cur = &c
		return w, nil
	}
	c, stamp, err := w.load()
	if err != nil {
		return nil, err
	}
	w.cur, w.stamp, w.checked = &c, stamp, time.Now()
	return w, nil
}

func (w *webCert) load() (tls.Certificate, string, error) {
	stamp := ""
	for _, f := range []string{w.certFile, w.keyFile} {
		st, err := os.Stat(f)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		stamp += fmt.Sprintf("%d/%d;", st.Size(), st.ModTime().UnixNano())
	}
	c, err := tls.LoadX509KeyPair(w.certFile, w.keyFile)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("controller: tls.cert_file and tls.key_file: %w", err)
	}
	return c, stamp, nil
}

// GetCertificate is tls.Config.GetCertificate.
func (w *webCert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if w.acme != nil {
		c, err := w.acme.GetCertificate(hello)
		if err == nil || len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acmez.ACMETLS1Protocol {
			return c, err
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.certFile != "" && time.Since(w.checked) >= webCertReload {
		w.checked = time.Now()
		if c, stamp, err := w.load(); err != nil {
			w.logger.Warn("cannot reload the public URL's certificate; keeping the previous one", "error", err)
		} else if stamp != w.stamp {
			w.cur, w.stamp = &c, stamp
			w.logger.Info("reloaded the public URL's certificate")
		}
	}
	return w.cur, nil
}

// Trusted reports whether the certificate in use is one clients trust: from files or from ACME.
func (w *webCert) Trusted() bool {
	return w.certFile != "" || w.acme != nil && w.acme.Has()
}

// HSTS sets Strict-Transport-Security on every response while the certificate is trusted; a
// browser ignores it over a connection with certificate errors anyway (RFC 6797, section 8.1).
func (w *webCert) HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.Trusted() {
			rw.Header().Set("Strict-Transport-Security", hstsHeader)
		}
		next.ServeHTTP(rw, r)
	})
}

// WebTLS is the TLS configuration of the web server, which serves the UI and the public API
// (docs/07-api.md, "Overview", D92): TLS 1.3, the certificate getCertificate returns, and ALPN h2
// before http/1.1 and http/1.0, so browsers and gRPC clients use HTTP/2 and HTTP/1.x clients still
// connect. With acmeTLS it offers acme-tls/1 as well, last, for the controller's own TLS-ALPN-01
// challenge, whose ClientHello offers nothing else. The configuration is the same wherever TLS ends
// at the controller: on its own port 443, behind all-in-one's gateway and behind a gateway's
// controller.passthrough.
func WebTLS(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), acmeTLS bool) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: getCertificate, NextProtos: []string{"h2", "http/1.1", "http/1.0"}}
	if acmeTLS {
		cfg.NextProtos = append(cfg.NextProtos, acmez.ACMETLS1Protocol)
	}
	return cfg
}

// webMaxStreams is how many requests one HTTP/2 connection may have open at once
// (docs/03-connections.md, "Timeouts, keepalive and backoff").
const webMaxStreams = 100

// webProtocols are the HTTP versions of the web server: HTTP/1.1 and HTTP/2 over TLS.
func webProtocols() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	return p
}

// webHTTP2 are the HTTP/2 settings of the web server; the rest are net/http's defaults.
func webHTTP2() *http.HTTP2Config { return &http.HTTP2Config{MaxConcurrentStreams: webMaxStreams} }

// SelfSignedPEM makes a self-signed certificate for host as selfSigned does, PEM-encoded, for
// `rpmgr setup` to write as the boot file's certificate files.
func SelfSignedPEM(host string) (cert, key []byte, err error) {
	c, err := selfSigned(host)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// selfSigned makes a certificate for host that no client trusts, so a browser warns rather than
// connecting silently.
func selfSigned(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
