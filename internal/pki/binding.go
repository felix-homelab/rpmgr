// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
)

// The CSR binding (docs/04-security.md, "Flow"; D62). The agent puts its connection's tls-exporter
// value (RFC 9266, Section 2) into the CSR's PKCS #9 challengePassword attribute, base64-encoded,
// as EST does with tls-unique (RFC 7030, Section 3.5), and signs the request with its key. The
// controller compares it with its own value for the connection that carried the request, so a
// CSR captured on one connection is refused on every other. crypto/x509 neither writes nor exposes
// the attribute, so NewBoundCSR builds the request and VerifyBinding reads it from the signed
// request.

// The tls-exporter parameters: label EXPORTER-Channel-Binding, an empty context, 32 bytes.
const (
	BindingLabel = "EXPORTER-Channel-Binding"
	BindingLen   = 32
)

var (
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// Errors of VerifyBinding.
var (
	ErrNoBinding       = errors.New("pki: the certificate request carries no TLS binding")
	ErrBindingMismatch = errors.New("pki: the certificate request is not bound to this TLS connection")
)

// ExportBinding returns the connection's tls-exporter value.
func ExportBinding(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(BindingLabel, nil, BindingLen)
}

// tbsRequest is a PKCS #10 CertificationRequestInfo, as crypto/x509 encodes it.
type tbsRequest struct {
	Version       int
	Subject       asn1.RawValue
	PublicKey     asn1.RawValue
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type request struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

// NewBoundCSR returns a certificate request for key, bound to the connection cs. Its subject is
// empty: the controller assigns the identity.
func NewBoundCSR(key *ecdsa.PrivateKey, cs tls.ConnectionState) (*x509.CertificateRequest, error) {
	b, err := ExportBinding(cs)
	if err != nil {
		return nil, err
	}
	return newCSR(key, base64.StdEncoding.EncodeToString(b))
}

// newCSR builds and signs a request whose challengePassword is password.
func newCSR(key *ecdsa.PrivateKey, password string) (*x509.CertificateRequest, error) {
	attr, err := asn1.Marshal(attribute{Type: oidChallengePassword,
		Values: []asn1.RawValue{{Tag: asn1.TagPrintableString, Bytes: []byte(password)}}})
	if err != nil {
		return nil, err
	}
	return signRequest(key, []asn1.RawValue{{FullBytes: attr}})
}

// signRequest builds a request with an empty subject and the given attributes, and signs it.
func signRequest(key *ecdsa.PrivateKey, attrs []asn1.RawValue) (*x509.CertificateRequest, error) {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	tbsDER, err := asn1.Marshal(tbsRequest{
		Subject:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}}, // an empty Name
		PublicKey:     asn1.RawValue{FullBytes: spki},
		RawAttributes: append([]asn1.RawValue{}, attrs...),
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(request{TBS: asn1.RawValue{FullBytes: tbsDER},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256},
		Signature: asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// VerifyBinding checks the request's signature and that its binding equals this side's
// tls-exporter value for the connection cs that carried it.
func VerifyBinding(csr *x509.CertificateRequest, cs tls.ConnectionState) error {
	if csr == nil {
		return ErrBadCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	got, err := readBinding(csr.RawTBSCertificateRequest)
	if err != nil {
		return err
	}
	want, err := ExportBinding(cs)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrBindingMismatch
	}
	return nil
}

// readBinding returns the binding in a signed CertificationRequestInfo: exactly one
// challengePassword attribute with exactly one PrintableString or UTF8String value, the base64 of
// BindingLen bytes. Any other shape, and an attribute that does not parse, is refused.
func readBinding(tbsDER []byte) ([]byte, error) {
	var tbs tbsRequest
	if rest, err := asn1.Unmarshal(tbsDER, &tbs); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: malformed request", ErrBindingMismatch)
	}
	var binding []byte
	for _, raw := range tbs.RawAttributes {
		var a attribute
		if rest, err := asn1.Unmarshal(raw.FullBytes, &a); err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("%w: malformed attribute", ErrBindingMismatch)
		}
		if !a.Type.Equal(oidChallengePassword) {
			continue
		}
		if binding != nil || len(a.Values) != 1 {
			return nil, fmt.Errorf("%w: more than one binding", ErrBindingMismatch)
		}
		v := a.Values[0]
		if v.Class != asn1.ClassUniversal || v.IsCompound || (v.Tag != asn1.TagPrintableString && v.Tag != asn1.TagUTF8String) {
			return nil, fmt.Errorf("%w: the binding is not a string", ErrBindingMismatch)
		}
		b, err := base64.StdEncoding.Strict().DecodeString(string(v.Bytes))
		if err != nil || len(b) != BindingLen {
			return nil, fmt.Errorf("%w: the binding is not %d base64-encoded bytes", ErrBindingMismatch, BindingLen)
		}
		binding = b
	}
	if binding == nil {
		return nil, ErrNoBinding
	}
	return binding, nil
}
