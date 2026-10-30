// SPDX-License-Identifier: Apache-2.0

// Package syslogtest is an in-process syslog server for tests: TLS on loopback, RFC 5425 octet
// counting, with a certificate of a CA it makes. It is a test double, not evidence for VB-23,
// which needs a real syslog server.
package syslogtest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Server records the messages it receives.
type Server struct {
	// Addr is host:port of the listener; CA is the PEM of the CA that signed its certificate.
	Addr, CA string

	mu    sync.Mutex
	msgs  []string
	conns int
	drop  int
}

// CA is a certificate authority that signs the server certificate for 127.0.0.1.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newAuthority(t *testing.T, name string) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &authority{cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// OtherCA returns the PEM of a CA that signed nothing.
func OtherCA(t *testing.T) string { return newAuthority(t, "another CA").pem }

// New starts a server that resets the connection, as a killed server does, after dropAfter messages of one
// connection (0: never), and stops it with the test.
func New(t *testing.T, dropAfter int) *Server {
	t.Helper()
	ca := newAuthority(t, "test CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Addr: ln.Addr().String(), CA: ca.pem, drop: dropAfter}
	conf := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(tls.Server(c, conf))
		}
	}()
	return s
}

// SetDrop changes after how many messages of a connection the server drops it.
func (s *Server) SetDrop(n int) {
	s.mu.Lock()
	s.drop = n
	s.mu.Unlock()
}

func (s *Server) serve(c *tls.Conn) {
	defer func() { _ = c.Close() }()
	s.mu.Lock()
	s.conns++
	s.mu.Unlock()
	r := bufio.NewReader(c)
	n := 0
	for {
		length, err := r.ReadString(' ')
		if err != nil {
			return
		}
		size, err := strconv.Atoi(length[:len(length)-1])
		if err != nil || size < 1 {
			return
		}
		msg := make([]byte, size)
		if _, err := io.ReadFull(r, msg); err != nil {
			return
		}
		n++
		s.mu.Lock()
		s.msgs = append(s.msgs, string(msg))
		drop := s.drop
		s.mu.Unlock()
		if drop > 0 && n >= drop {
			// A killed server: the connection is reset, with no close_notify.
			if tc, ok := c.NetConn().(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = c.NetConn().Close()
			return
		}
	}
}

// Messages are the messages received so far, each without its frame.
func (s *Server) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

// Connections is how many connections were accepted.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}
