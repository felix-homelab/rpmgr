// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"
)

const td = "rpmgr-7f3k2q9m"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Set(t time.Time)         { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *fakeClock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

func newCA(t *testing.T, clk *fakeClock) *CA {
	t.Helper()
	ca, err := NewCA(td, clk.Now, true)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func plainCSR(t *testing.T, key *ecdsa.PrivateKey) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// leaf bundles what an agent holds: key, certificate, and the tls.Certificate with the chain.
type leaf struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	tls  tls.Certificate
}

func tlsCert(ca *CA, cert *x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{cert.Raw, ca.Intermediate.Raw}, PrivateKey: key, Leaf: cert}
}

func issue(t *testing.T, ca *CA, id Identity, p Profile, lifetime time.Duration) leaf {
	t.Helper()
	k := newKey(t)
	c, err := ca.Issue(plainCSR(t, k), id, p, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	return leaf{key: k, cert: c, tls: tlsCert(ca, c, k)}
}

// forge signs an arbitrary leaf with the issuing intermediate's key, bypassing Issue: what a bug
// in the issuance path or a stolen intermediate key could produce.
func forge(t *testing.T, ca *CA, uris []string, dns []string, ekus []x509.ExtKeyUsage) leaf {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "forged"},
		NotBefore:    ca.Now().Add(-Backdate),
		NotAfter:     ca.Now().Add(AgentLeafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
		DNSNames:     dns,
	}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Intermediate, &k.PublicKey, ca.interKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf{key: k, cert: c, tls: tlsCert(ca, c, k)}
}

func connectorID(org, id string) Identity {
	return Identity{TrustDomain: td, Org: org, Kind: KindConnector, ID: id}
}
func gatewayID(org, id string) Identity {
	return Identity{TrustDomain: td, Org: org, Kind: KindGateway, ID: id}
}
func controllerID(id string) Identity {
	return Identity{TrustDomain: td, Kind: KindController, ID: id}
}

type result struct {
	srv, cli       tls.ConnectionState
	srvErr, cliErr error
}

func (r result) ok() bool { return r.srvErr == nil && r.cliErr == nil }

// run performs one TLS connection over loopback TCP. After the handshake, the default exchange
// (server writes a byte, client reads it, client writes one back) makes the client process the
// server's NewSessionTicket, so a later connection can resume.
func run(t *testing.T, srvCfg, cliCfg *tls.Config, srvFn, cliFn func(*tls.Conn) error) result {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var r result
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			r.srvErr = err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		tc := tls.Server(c, srvCfg)
		if err := tc.Handshake(); err != nil {
			r.srvErr = err
			return
		}
		r.srv = tc.ConnectionState()
		if srvFn != nil {
			r.srvErr = srvFn(tc)
			return
		}
		if _, err := tc.Write([]byte{1}); err != nil {
			r.srvErr = err
			return
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(tc, b); err != nil {
			r.srvErr = err
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(c, cliCfg)
	if err := tc.Handshake(); err != nil {
		r.cliErr = err
	} else {
		r.cli = tc.ConnectionState()
		if cliFn != nil {
			r.cliErr = cliFn(tc)
		} else {
			b := make([]byte, 1)
			if _, err := io.ReadFull(tc, b); err != nil {
				r.cliErr = err
			} else if _, err := tc.Write([]byte{1}); err != nil {
				r.cliErr = err
			}
		}
	}
	_ = tc.Close()
	<-done
	return r
}

// errChain reports whether err (or its text, for errors crypto/tls does not wrap) matches.
func errIs(err, target error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, target)
}
