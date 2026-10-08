// SPDX-License-Identifier: Apache-2.0

// Package certs keeps the public TLS certificates of http routes (docs/04-security.md, "Route
// certificates"): it checks an uploaded chain and key, stores the key under the KEK, and builds the
// item a gateway fetches by hash.
package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
)

// MaxChain is the longest chain accepted, leaf included (docs/04-security.md, "Route
// certificates").
const MaxChain = 10

// ErrInvalid is returned for a chain or key that cannot serve as a route certificate.
var ErrInvalid = errors.New("certs: not a usable certificate")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Parsed is a checked chain with its key.
type Parsed struct {
	Chain []*x509.Certificate
	Key   crypto.Signer
	// SANs are the leaf's DNS names, normalised.
	SANs []string
}

// Parse checks a PEM chain, leaf first, and the leaf's PEM private key: at most MaxChain
// certificates, each signed by the next; a leaf valid at now, for TLS servers, with at least one
// DNS name; and a key that matches it, ECDSA P-256 or P-384 or RSA of 2048 to 8192 bits.
func Parse(chainPEM, keyPEM []byte, now time.Time) (*Parsed, error) {
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, invalid("the chain has text that is not PEM")
			}
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, invalid("the chain holds a %s block", b.Type)
		}
		if len(chain) == MaxChain {
			return nil, invalid("the chain is longer than %d certificates", MaxChain)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, invalid("certificate %d: %v", len(chain)+1, err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, invalid("no certificate")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, invalid("certificate %d is not signed by certificate %d, the next in the chain", i+1, i+2)
		}
	}
	leaf := chain[0]
	switch {
	case now.Before(leaf.NotBefore):
		return nil, invalid("the certificate is valid only from %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return nil, invalid("the certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	case leaf.IsCA:
		return nil, invalid("the first certificate is a CA, not a leaf")
	case len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny):
		return nil, invalid("the certificate is not for TLS servers")
	case len(leaf.DNSNames) == 0:
		return nil, invalid("the certificate names no DNS name")
	}
	var sans []string
	for _, n := range leaf.DNSNames {
		norm, err := domains.Normalize(n, true)
		if err != nil {
			return nil, invalid("DNS name %q: %v", n, err)
		}
		if !slices.Contains(sans, norm) {
			sans = append(sans, norm)
		}
	}
	slices.Sort(sans)
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !samePublic(key.Public(), leaf.PublicKey) {
		return nil, invalid("the key does not belong to the certificate")
	}
	return &Parsed{Chain: chain, Key: key, SANs: sans}, nil
}

func parseKey(keyPEM []byte) (crypto.Signer, error) {
	b, rest := pem.Decode(keyPEM)
	if b == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, invalid("the key is not one PEM block")
	}
	var (
		k   any
		err error
	)
	switch b.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	default:
		return nil, invalid("the key is a %s block", b.Type)
	}
	if err != nil {
		return nil, invalid("the key: %v", err)
	}
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, invalid("an ECDSA key on %s; P-256 or P-384 only", k.Curve.Params().Name)
		}
		return k, nil
	case *rsa.PrivateKey:
		if n := k.N.BitLen(); n < 2048 || n > 8192 {
			return nil, invalid("an RSA key of %d bits; 2048 to 8192 only", n)
		}
		return k, nil
	}
	return nil, invalid("a %T key; ECDSA or RSA only", k)
}

func samePublic(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// Item is what a gateway fetches for the certificate: its chain and key, deterministically
// encoded, so its SHA-256 identifies it.
func (p *Parsed) Item() ([]byte, error) {
	key, err := x509.MarshalPKCS8PrivateKey(p.Key)
	if err != nil {
		return nil, err
	}
	item := &agentv1.CertificateItem{PrivateKey: key}
	for _, c := range p.Chain {
		item.Chain = append(item.Chain, c.Raw)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(item)
}

// keyContext binds a sealed key to its row.
func keyContext(id string) secret.Context {
	return secret.Context{Table: "certificates", Column: "key_enc", RowID: id}
}

// Upload stores an uploaded certificate of org, checked with Parse, its key sealed with s.
func Upload(ctx context.Context, tx *ent.Tx, s *secret.Sealer, org string, chainPEM, keyPEM []byte, now time.Time) (*ent.Certificate, error) {
	p, err := Parse(chainPEM, keyPEM, now)
	if err != nil {
		return nil, err
	}
	item, err := p.Item()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(item)
	clear(item)
	der, err := x509.MarshalPKCS8PrivateKey(p.Key)
	if err != nil {
		return nil, err
	}
	id := ids.New("crt")
	sealed, err := store.Seal(ctx, tx, s, keyContext(id), secret.FromBytes(der))
	clear(der)
	if err != nil {
		return nil, err
	}
	var chain []byte
	for _, c := range p.Chain {
		chain = append(chain, c.Raw...)
	}
	leaf := p.Chain[0]
	return tx.Certificate.Create().SetID(id).SetOrgID(org).SetSource(certificate.SourceUploaded).SetSans(p.SANs).
		SetNotBefore(leaf.NotBefore).SetNotAfter(leaf.NotAfter).SetChain(chain).SetKeyEnc(sealed).
		SetContentSha256(sum[:]).SetIssuer(leaf.Issuer.String()).Save(ctx)
}

// Item opens a stored certificate's key with s and returns the item a gateway fetches; its
// SHA-256 is the row's content_sha256, or the row was changed outside this package.
func Item(c *ent.Certificate, s *secret.Sealer) ([]byte, error) {
	chain, err := x509.ParseCertificates(c.Chain)
	if err != nil {
		return nil, err
	}
	v, err := s.Open(keyContext(c.ID), c.KeyEnc)
	if err != nil {
		return nil, err
	}
	der := []byte(v.Reveal())
	item := &agentv1.CertificateItem{PrivateKey: der}
	for _, x := range chain {
		item.Chain = append(item.Chain, x.Raw)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	clear(der)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(b); !slices.Equal(sum[:], c.ContentSha256) {
		return nil, fmt.Errorf("certs: certificate %s does not match its content hash", c.ID)
	}
	return b, nil
}

// Covers reports whether a certificate name covers a normalised route hostname, as TLS clients
// match it: exactly, or a wildcard name "*.x" every name one label below x. A wildcard hostname
// is covered only by the same wildcard name.
func Covers(san, hostname string) bool {
	if san == hostname {
		return true
	}
	parent, ok := strings.CutPrefix(san, "*.")
	if !ok || strings.HasPrefix(hostname, "*.") {
		return false
	}
	label, rest, found := strings.Cut(hostname, ".")
	return found && label != "" && rest == parent
}
