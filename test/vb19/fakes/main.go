// SPDX-License-Identifier: Apache-2.0

// Command fakes stands in for the internet of the VB-19 rehearsal (../rehearse.sh): the fake
// Cloudflare API of internal/dns/cftest, which rpmgr reaches under the name api.cloudflare.com
// (the rehearsal's /etc/hosts and firewall send that name here), and the authoritative DNS server
// of internal/acme/acmetest, which answers Pebble's and rpmgr's questions about the zone: every
// name resolves to the rehearsal's "public" address, and a TXT record is whatever the fake
// Cloudflare holds. It is a test tool and is not linked into rpmgr.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
)

// cleanup stands in for the testing.T of cftest.New: it runs the registered functions at exit.
type cleanup struct {
	testing.TB
	fns []func()
}

func (c *cleanup) Helper()          {}
func (c *cleanup) Cleanup(f func()) { c.fns = append(c.fns, f) }
func (c *cleanup) Fatal(args ...any) {
	log.Fatal(args...)
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, " ") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal("fakes: ", err)
	}
}

func run() error {
	var (
		dir       = flag.String("dir", "", "the state directory: the fake's CA, its DNS address and the ready file are written there (required)")
		tokenFile = flag.String("token-file", "", "a file with the token the fake Cloudflare accepts (required)")
		zone      = flag.String("zone", "", "the zone of the fake account, which the fake DNS serves (required)")
		public    = flag.String("public", "127.0.0.2", "the address every name of the zone resolves to")
		listen    = flag.String("listen", "127.0.0.1:9443", "where the fake Cloudflare listens, over TLS")
	)
	var foreign multi
	flag.Var(&foreign, "foreign", "a record of someone else in the zone, `type,name,content`; repeat for more")
	flag.Parse()
	if *dir == "" || *tokenFile == "" || *zone == "" {
		return errors.New("-dir, -token-file and -zone are required")
	}
	tok, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	c := &cleanup{}
	defer func() {
		for _, f := range c.fns {
			f()
		}
	}()

	cf := cftest.New(c, strings.TrimSpace(string(tok)))
	z := cf.AddZone(*zone)
	for _, f := range foreign {
		p := strings.SplitN(f, ",", 3)
		if len(p) != 3 {
			return fmt.Errorf("-foreign %q: want type,name,content", f)
		}
		cf.AddRecord(z.ID, cftest.Record{Type: p[0], Name: p[1], Content: p[2], TTL: 300})
	}
	dnsSrv, err := acmetest.StartDNS([]string{*zone}, func(fqdn string) []string {
		var out []string
		for _, r := range cf.Records(z.ID) {
			if r.Type == "TXT" && r.Name == fqdn {
				out = append(out, r.Content)
				fmt.Printf("dns: TXT %s answered, record comment %q\n", fqdn, r.Comment)
			}
		}
		return out
	})
	if err != nil {
		return err
	}
	defer dnsSrv.Close()
	dnsSrv.Default = net.ParseIP(*public)

	// rpmgr dials api.cloudflare.com, over TLS against the system roots plus the rehearsal's CA
	// file; this front end answers with a certificate for that name and passes everything on to the
	// fake, which is the API as it is, and checks the token.
	cert, caPEM, err := apiCertificate()
	if err != nil {
		return err
	}
	target, err := url.Parse(cf.URL())
	if err != nil {
		return err
	}
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(&url.URL{Scheme: "https", Host: target.Host}) },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cf.RootCAs()}},
		ErrorLog:  log.New(os.Stderr, "proxy: ", 0),
	}
	ln, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	if err := os.WriteFile(filepath.Join(*dir, "cloudflare-ca.pem"), caPEM, 0o644); err != nil { //nolint:gosec // G306: a public certificate
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "dns.addr"), []byte(dnsSrv.Addr), 0o644); err != nil { //nolint:gosec // G306: an address
		return err
	}
	fmt.Println("fakes: Cloudflare on", *listen, "and DNS on", dnsSrv.Addr, "for", *zone)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	return nil
}

// apiCertificate returns a certificate for api.cloudflare.com, signed by a new CA, and that CA's
// PEM, which the rehearsal adds to the roots of rpmgr.
func apiCertificate() (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "VB-19 rehearsal Cloudflare CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "api.cloudflare.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"api.cloudflare.com"},
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
