// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// webCertReload is how often the certificate files of the public URL are checked for changes; a
// variable for tests.
var webCertReload = time.Minute

// webCert is the certificate of the public URL (docs/10-operations.md, "Boot files"): from
// tls.cert_file and tls.key_file, read again when either file changes, keeping the previous
// certificate if the new pair does not load; or, without files, a self-signed certificate made at
// start until ACME obtains one.
type webCert struct {
	certFile, keyFile string
	logger            *slog.Logger

	mu      sync.Mutex
	cur     *tls.Certificate
	checked time.Time
	stamp   string // the files' sizes and modification times at the last load
}

func newWebCert(certFile, keyFile, host string, logger *slog.Logger) (*webCert, error) {
	w := &webCert{certFile: certFile, keyFile: keyFile, logger: logger}
	if certFile == "" {
		c, err := selfSigned(host)
		if err != nil {
			return nil, err
		}
		logger.Warn("the public URL has a self-signed certificate: set tls.cert_file and tls.key_file", "host", host)
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
func (w *webCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
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
