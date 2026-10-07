// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// bindingEnv is a controller and an agent that open TLS connections to each other.
type bindingEnv struct {
	c        *ca
	srv, cli *tls.Config
	key      *ecdsa.PrivateKey
}

func newBindingEnv(t *testing.T, sessions tls.ClientSessionCache) bindingEnv {
	t.Helper()
	c := newCA(t, td)
	ctl := c.agent(t, node(ids.New("ctn")), pki.ControllerLifetime)
	con := c.agent(t, connector(orgA, ids.New("con")), pki.DefaultLeafLifetime)
	return bindingEnv{c: c, key: newKey(t),
		srv: pki.ServerConfig(ctl.tls, c.pool(), pki.Expect{TrustDomain: td}, c.clock),
		cli: pki.ClientConfig(con.tls, c.pool(), "controller."+td, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, c.clock, sessions)}
}

func (e bindingEnv) connect(t *testing.T) result {
	t.Helper()
	r := run(t, e.srv, e.cli)
	if !r.ok() {
		t.Fatalf("handshake: server %v, client %v", r.srvErr, r.cliErr)
	}
	return r
}

// TestCSR_BoundToConnection (TLS level): a CSR carries the tls-exporter value of the connection the
// agent sends it on, and the controller accepts it only on that connection, resumed or not.
func TestCSR_BoundToConnection(t *testing.T) {
	e := newBindingEnv(t, tls.NewLRUClientSessionCache(4))
	first := e.connect(t)
	csr, err := pki.NewBoundCSR(e.key, first.cli)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("bound CSR accepted and issued", func(t *testing.T) {
		if err := pki.VerifyBinding(csr, first.srv); err != nil {
			t.Fatal(err)
		}
		cert, err := e.c.is.IssueLeaf(csr, connector(orgA, ids.New("con")), pki.DefaultLeafLifetime)
		if err != nil || len(cert.Subject.Names) != 0 {
			t.Fatalf("issued from a bound CSR: %v, subject %v", err, cert.Subject)
		}
		a, _ := pki.ExportBinding(first.cli)
		b, _ := pki.ExportBinding(first.srv)
		if len(a) != pki.BindingLen || !bytes.Equal(a, b) {
			t.Fatal("client and server export different values")
		}
	})
	second := e.connect(t)
	if !second.cli.DidResume {
		t.Fatal("the second connection did not resume")
	}
	t.Run("CSR replayed on another connection", func(t *testing.T) {
		if err := pki.VerifyBinding(csr, second.srv); !errors.Is(err, pki.ErrBindingMismatch) {
			t.Fatalf("got %v, want ErrBindingMismatch", err)
		}
	})
	t.Run("bound to a resumed connection", func(t *testing.T) {
		resumed, err := pki.NewBoundCSR(e.key, second.cli)
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.VerifyBinding(resumed, second.srv); err != nil {
			t.Fatal(err)
		}
		if err := pki.VerifyBinding(resumed, first.srv); !errors.Is(err, pki.ErrBindingMismatch) {
			t.Fatalf("on the first connection: %v, want ErrBindingMismatch", err)
		}
	})
	t.Run("CSR without a binding", func(t *testing.T) {
		if err := pki.VerifyBinding(csrFor(t, e.key, nil), first.srv); !errors.Is(err, pki.ErrNoBinding) {
			t.Fatalf("got %v, want ErrNoBinding", err)
		}
	})
	t.Run("another binding, signed by the agent's key", func(t *testing.T) {
		other, err := pki.NewCSR(e.key, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, pki.BindingLen)))
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.VerifyBinding(other, first.srv); !errors.Is(err, pki.ErrBindingMismatch) {
			t.Fatalf("got %v, want ErrBindingMismatch", err)
		}
	})
	t.Run("broken signature", func(t *testing.T) {
		broken := *csr
		broken.Signature = bytes.Clone(csr.Signature)
		broken.Signature[len(broken.Signature)-1] ^= 1
		if err := pki.VerifyBinding(&broken, first.srv); !errors.Is(err, pki.ErrBadCSR) {
			t.Fatalf("got %v, want ErrBadCSR", err)
		}
		if err := pki.VerifyBinding(nil, first.srv); !errors.Is(err, pki.ErrBadCSR) {
			t.Fatalf("no CSR: %v, want ErrBadCSR", err)
		}
	})
}

// TestReadBinding_Malformed: every request shape other than one challengePassword holding the
// base64 of 32 bytes is refused, among them an attribute under D47's OID, whose UUID arc Go's
// encoding/asn1 cannot parse (the reason for D62).
func TestReadBinding_Malformed(t *testing.T) {
	key := newKey(t)
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, pki.BindingLen))
	pw := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	attr := func(oid asn1.ObjectIdentifier, values ...asn1.RawValue) asn1.RawValue {
		der, err := asn1.Marshal(struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}{oid, values})
		if err != nil {
			t.Fatal(err)
		}
		return asn1.RawValue{FullBytes: der}
	}
	str := func(tag int, s string) asn1.RawValue { return asn1.RawValue{Tag: tag, Bytes: []byte(s)} }
	cases := map[string][]asn1.RawValue{
		"two attributes":            {attr(pw, str(asn1.TagPrintableString, good)), attr(pw, str(asn1.TagPrintableString, good))},
		"two values":                {attr(pw, str(asn1.TagPrintableString, good), str(asn1.TagPrintableString, good))},
		"no value":                  {attr(pw)},
		"an IA5String":              {attr(pw, str(asn1.TagIA5String, good))},
		"not base64":                {attr(pw, str(asn1.TagUTF8String, strings.Repeat("!", 44)))},
		"31 bytes":                  {attr(pw, str(asn1.TagPrintableString, base64.StdEncoding.EncodeToString(make([]byte, 31))))},
		"unpadded base64":           {attr(pw, str(asn1.TagPrintableString, strings.TrimRight(good, "=")))},
		"an attribute with D47 OID": {{FullBytes: d47Attribute(t)}, attr(pw, str(asn1.TagPrintableString, good))},
	}
	for name, attrs := range cases {
		t.Run(name, func(t *testing.T) {
			csr, err := pki.SignRequest(key, attrs)
			if err != nil {
				t.Fatalf("building the request: %v", err)
			}
			if _, err := pki.ReadBinding(csr.RawTBSCertificateRequest); !errors.Is(err, pki.ErrBindingMismatch) {
				t.Fatalf("got %v, want ErrBindingMismatch", err)
			}
		})
	}
	csr, err := pki.SignRequest(key, []asn1.RawValue{attr(pw, str(asn1.TagUTF8String, good))})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := pki.ReadBinding(csr.RawTBSCertificateRequest); err != nil || !bytes.Equal(b, bytes.Repeat([]byte{1}, pki.BindingLen)) {
		t.Errorf("a UTF8String binding: %x, %v", b, err)
	}
}

// d47Attribute encodes an attribute under D47's OID 2.25.330347968250229846689170632254339943880 by
// hand, because encoding/asn1 cannot, and checks that encoding/asn1 indeed refuses the OID.
func d47Attribute(t *testing.T) []byte {
	t.Helper()
	x, ok := new(big.Int).SetString("330347968250229846689170632254339943880", 10)
	if !ok {
		t.Fatal("bad arc")
	}
	var sub []byte // the arc in base 128, most significant group first
	for x.Sign() > 0 {
		sub = append([]byte{byte(x.Uint64() & 0x7f)}, sub...)
		x.Rsh(x, 7)
	}
	for i := range len(sub) - 1 {
		sub[i] |= 0x80
	}
	// The first octet holds the arcs 2 and 25 together: 2*40 + 25.
	oid, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagOID, Bytes: append([]byte{2*40 + 25}, sub...)})
	if err != nil {
		t.Fatal(err)
	}
	var parsed asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(oid, &parsed); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("encoding/asn1 parsed D47's OID (%v, %v): D62's reason no longer holds", parsed, err)
	}
	attr, err := asn1.Marshal(struct {
		Type   asn1.RawValue
		Values []asn1.RawValue `asn1:"set"`
	}{asn1.RawValue{FullBytes: oid}, []asn1.RawValue{{Tag: asn1.TagNull}}})
	if err != nil {
		t.Fatal(err)
	}
	return attr
}

func FuzzReadBinding(f *testing.F) {
	key, err := pki.NewKey()
	if err != nil {
		f.Fatal(err)
	}
	bound, err := pki.NewCSR(key, base64.StdEncoding.EncodeToString(make([]byte, pki.BindingLen)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bound.RawTBSCertificateRequest)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		f.Fatal(err)
	}
	plain, err := x509.ParseCertificateRequest(der)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(plain.RawTBSCertificateRequest)
	f.Fuzz(func(t *testing.T, tbs []byte) {
		b, err := pki.ReadBinding(tbs)
		if err == nil && len(b) != pki.BindingLen {
			t.Fatalf("accepted a binding of %d bytes", len(b))
		}
	})
}
