// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// The binding value is the TLS 1.3 "tls-exporter" channel binding of RFC 9266, Section 2: label
// "EXPORTER-Channel-Binding", empty context, 32 bytes. It goes into the CSR, which the agent signs
// with its key after the handshake, so the CSR cannot be replayed on another connection.
const (
	BindingLabel = "EXPORTER-Channel-Binding"
	BindingLen   = 32
)

// OIDCSRBinding is a placeholder under the IANA Private Enterprise Number reserved for
// documentation (32473, RFC 5612). rpmgr needs its own arc before Phase 1.
var OIDCSRBinding = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1, 1}

var (
	ErrNoBinding       = errors.New("CSR carries no TLS binding")
	ErrBindingMismatch = errors.New("CSR is bound to another TLS connection")
)

// ExportBinding returns the connection's tls-exporter value.
func ExportBinding(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(BindingLabel, nil, BindingLen)
}

// NewBoundCSR creates a CSR signed by key that carries the binding of the connection cs.
func NewBoundCSR(key crypto.Signer, cs tls.ConnectionState) (*x509.CertificateRequest, error) {
	b, err := ExportBinding(cs)
	if err != nil {
		return nil, err
	}
	return newCSRWithBinding(key, b)
}

func newCSRWithBinding(key crypto.Signer, binding []byte) (*x509.CertificateRequest, error) {
	val, err := asn1.Marshal(binding)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: OIDCSRBinding, Value: val}}}
	if binding == nil {
		tmpl.ExtraExtensions = nil
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// VerifyBinding checks the CSR's signature and that its binding equals the server's own
// tls-exporter value for this connection.
func VerifyBinding(csr *x509.CertificateRequest, cs tls.ConnectionState) error {
	if err := csr.CheckSignature(); err != nil {
		return err
	}
	want, err := ExportBinding(cs)
	if err != nil {
		return err
	}
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(OIDCSRBinding) {
			continue
		}
		var got []byte
		if rest, err := asn1.Unmarshal(ext.Value, &got); err != nil || len(rest) != 0 {
			return ErrBindingMismatch
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return ErrBindingMismatch
		}
		return nil
	}
	return ErrNoBinding
}
