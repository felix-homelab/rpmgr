// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// A minimal length-prefixed exchange that stands in for the Enroll, Renew and Reauth RPCs.

func writeMsg(w io.Writer, b []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readMsg(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	if l := binary.BigEndian.Uint32(n[:]); l > 1<<16 {
		return nil, errors.New("message too large")
	} else {
		b := make([]byte, l)
		_, err := io.ReadFull(r, b)
		return b, err
	}
}

// serveIssue is the server side: read a CSR, check its TLS binding, issue a certificate for the
// identity of the presented client certificate (new key required), and reply "OK"+DER or
// "ERR"+message.
func serveIssue(ca *CA, p Profile) func(*tls.Conn) error {
	return func(c *tls.Conn) error {
		der, err := readMsg(c)
		if err != nil {
			return err
		}
		reply := func(e error) error {
			_ = writeMsg(c, []byte("ERR"+e.Error()))
			return e
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			return reply(err)
		}
		cs := c.ConnectionState()
		if err := VerifyBinding(csr, cs); err != nil {
			return reply(err)
		}
		cert, err := ca.Renew(cs.PeerCertificates[0], csr, p, AgentLeafLifetime)
		if err != nil {
			return reply(err)
		}
		return writeMsg(c, append([]byte("OK"), cert.Raw...))
	}
}

// requestIssue is the client side. csrFn builds the CSR for this connection; got receives the
// issued certificate.
func requestIssue(csrFn func(tls.ConnectionState) (*x509.CertificateRequest, error), got **x509.Certificate) func(*tls.Conn) error {
	return func(c *tls.Conn) error {
		csr, err := csrFn(c.ConnectionState())
		if err != nil {
			return err
		}
		if err := writeMsg(c, csr.Raw); err != nil {
			return err
		}
		b, err := readMsg(c)
		if err != nil {
			return err
		}
		if len(b) >= 3 && string(b[:3]) == "ERR" {
			return fmt.Errorf("server: %s", b[3:])
		}
		cert, err := x509.ParseCertificate(b[2:])
		if err != nil {
			return err
		}
		*got = cert
		return nil
	}
}

func boundCSR(key *ecdsa.PrivateKey) func(tls.ConnectionState) (*x509.CertificateRequest, error) {
	return func(cs tls.ConnectionState) (*x509.CertificateRequest, error) { return NewBoundCSR(key, cs) }
}
