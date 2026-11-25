// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"filippo.io/age"
)

// The offline root (docs/04-security.md, "Offline root CA"): the root's key and certificate in an
// age passphrase file, a request for an intermediate, its signature on an offline host, and the
// checks that run when the signed intermediate comes back.

// Errors of the offline root.
var (
	// ErrRootFile is the only thing a file that does not open says: a wrong passphrase, a truncated
	// or an edited file all look the same.
	ErrRootFile = errors.New("pki: the root file does not open")
	// ErrWeakPassphrase is returned for a supplied passphrase that fails the strength check.
	ErrWeakPassphrase = errors.New("pki: the passphrase is too weak")
	// ErrIntermediateRefused is returned for a signed intermediate that may not be imported; the
	// message names the first check that failed.
	ErrIntermediateRefused = errors.New("pki: the intermediate is refused")
)

const (
	passphraseBytes = 16 // 128 random bits
	// Strength of a passphrase the operator supplies (docs/14-open-decisions.md, D181).
	minPassphraseChars = 16
	minPassphraseBits  = 60
	maxRootFileBytes   = 64 << 10
)

// GeneratePassphrase returns 128 random bits as grouped text, `XXXX-XXXX-…`.
func GeneratePassphrase() (string, error) {
	b := make([]byte, passphraseBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	var groups []string
	for len(s) > 4 {
		groups, s = append(groups, s[:4]), s[4:]
	}
	return strings.Join(append(groups, s), "-"), nil
}

// CheckPassphrase refuses a supplied passphrase of fewer than 16 characters or of fewer than 60
// bits by a simple estimate: the distinct characters used, each worth the size of the smallest
// character class (lower case, upper case, digits, other) that holds all it uses together.
func CheckPassphrase(p string) error {
	rs := []rune(p)
	if len(rs) < minPassphraseChars {
		return fmt.Errorf("%w: fewer than %d characters", ErrWeakPassphrase, minPassphraseChars)
	}
	pool, distinct := 0.0, map[rune]bool{}
	var lower, upper, digit, other bool
	for _, r := range rs {
		distinct[r] = true
		switch {
		case unicode.IsLower(r) && r < 128:
			lower = true
		case unicode.IsUpper(r) && r < 128:
			upper = true
		case unicode.IsDigit(r) && r < 128:
			digit = true
		default:
			other = true
		}
	}
	for i, ok := range []bool{lower, upper, digit, other} {
		if ok {
			pool += []float64{26, 26, 10, 33}[i]
		}
	}
	if bits := float64(len(distinct)) * math.Log2(pool); bits < minPassphraseBits {
		return fmt.Errorf("%w: fewer than %d bits", ErrWeakPassphrase, minPassphraseBits)
	}
	return nil
}

// SealRootFile encrypts the root's PKCS #8 key and certificate (one PEM text) with passphrase, as
// age does with `age -p`. The file is complete without the controller.
func SealRootFile(root KeyPair, passphrase string) ([]byte, error) {
	if root.Cert == nil || root.Key == nil || !root.Cert.IsCA {
		return nil, errors.New("pki: not a root")
	}
	der, err := x509.MarshalPKCS8PrivateKey(root.Key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(plain)
	plain = append(plain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Cert.Raw})...)
	rcp, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rcp)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// OpenRootFile decrypts a root file and checks that the key belongs to the certificate. Every
// failure to open it is ErrRootFile and says nothing more.
func OpenRootFile(file []byte, passphrase string) (KeyPair, error) {
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return KeyPair{}, ErrRootFile
	}
	r, err := age.Decrypt(bytes.NewReader(file), id)
	if err != nil {
		return KeyPair{}, ErrRootFile
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxRootFileBytes))
	defer clear(plain)
	if err != nil || len(plain) >= maxRootFileBytes {
		return KeyPair{}, ErrRootFile
	}
	var kp KeyPair
	for rest := plain; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch b.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			ec, ok := k.(*ecdsa.PrivateKey)
			if err != nil || !ok || ec.Curve != elliptic.P256() {
				return KeyPair{}, ErrRootFile
			}
			kp.Key = ec
		case "CERTIFICATE":
			if kp.Cert, err = x509.ParseCertificate(b.Bytes); err != nil {
				return KeyPair{}, ErrRootFile
			}
		}
	}
	if kp.Key == nil || kp.Cert == nil || !kp.Cert.IsCA || !kp.Key.PublicKey.Equal(kp.Cert.PublicKey) {
		return KeyPair{}, ErrRootFile
	}
	return kp, nil
}

// NewIntermediateRequest returns a new key for the next intermediate and its certificate request
// (PEM). The root ignores the request's subject.
func NewIntermediateRequest() (*ecdsa.PrivateKey, []byte, error) {
	key, err := NewKey()
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "rpmgr issuing CA"}}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// SignIntermediate is what `rpmgr ca sign-intermediate` does with the root opened: it checks the
// request's signature and key (ECDSA P-256) and signs an intermediate with the properties of
// NewIntermediate. The request's subject is ignored.
func SignIntermediate(root KeyPair, csrPEM []byte, now time.Time) (*x509.Certificate, error) {
	td, err := TrustDomainOf(root.Cert)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: not a PEM certificate request", ErrBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature: %w", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: the key is not ECDSA P-256", ErrBadCSR)
	}
	if pub.Equal(&root.Key.PublicKey) {
		return nil, fmt.Errorf("%w: the key is the root's", ErrBadCSR)
	}
	return create(intermediateTemplate(td, root.Cert, now), root.Cert, pub, root.Key)
}

// VerifyIntermediate checks a signed intermediate before it is imported, and names the first check
// that fails (ErrIntermediateRefused). It holds when: the certificate carries want, the public key
// of the next key; root's key signed it; it is a CA with certSign and path length 0; its name
// constraints are critical and permit exactly the URI and DNS domain of the trust domain; it is
// valid at now and does not outlast the root; a probe leaf of the trust domain verifies under its
// constraints with Go's chain verification and one of another domain does not.
func VerifyIntermediate(cert, root *x509.Certificate, want *ecdsa.PublicKey, now time.Time) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrIntermediateRefused, fmt.Sprintf(format, a...))
	}
	td, err := TrustDomainOf(root)
	if err != nil {
		return err
	}
	if got, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !got.Equal(want) {
		return fail("it is not for the key that waits for a signature")
	}
	if !bytes.Equal(cert.RawIssuer, root.RawSubject) {
		return fail("it was not issued by the root")
	}
	if err := cert.CheckSignatureFrom(root); err != nil {
		return fail("the root's key did not sign it")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fail("it is not a CA with key usage certSign")
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		return fail("its path length is not 0")
	}
	if !cert.PermittedDNSDomainsCritical {
		return fail("its name constraints are missing or not critical")
	}
	if !slices.Equal(cert.PermittedDNSDomains, []string{td}) || !slices.Equal(cert.PermittedURIDomains, []string{td}) ||
		len(cert.ExcludedDNSDomains)+len(cert.ExcludedURIDomains)+len(cert.PermittedIPRanges)+len(cert.ExcludedIPRanges)+
			len(cert.PermittedEmailAddresses)+len(cert.ExcludedEmailAddresses) != 0 {
		return fail("its name constraints are not exactly the URI and DNS domain %s", td)
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return fail("it is not valid now")
	}
	if cert.NotAfter.After(root.NotAfter) {
		return fail("it outlasts the root")
	}
	if err := probe(cert, td, now); err != nil {
		return fail("%v", err)
	}
	return nil
}

// probe makes a stand-in for the intermediate in memory, with its constraints and a key of our
// own, and has Go verify a leaf of the trust domain and one of another domain under it. The real
// intermediate's key is sealed, and import needs no KEK, so it cannot sign the probe itself.
func probe(cert *x509.Certificate, td string, now time.Time) error {
	rootKey, err := NewKey()
	if err != nil {
		return err
	}
	stand := *cert
	stand.Raw, stand.RawTBSCertificate, stand.RawSubjectPublicKeyInfo, stand.Signature = nil, nil, nil, nil
	stand.RawSubject, stand.RawIssuer, stand.SubjectKeyId, stand.AuthorityKeyId = nil, nil, nil, nil
	standRoot := &x509.Certificate{
		Subject: pkix.Name{CommonName: "probe root"}, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign,
	}
	rootCert, err := create(standRoot, standRoot, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	interKey, err := NewKey()
	if err != nil {
		return err
	}
	inter, err := create(&stand, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	verify := func(domain string) error {
		leafKey, err := NewKey()
		if err != nil {
			return err
		}
		leaf, err := create(&x509.Certificate{
			Subject: pkix.Name{CommonName: "probe"}, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs: []*url.URL{{Scheme: "spiffe", Host: domain, Path: "/probe"}},
		}, inter, &leafKey.PublicKey, interKey)
		if err != nil {
			return err
		}
		pool, roots := x509.NewCertPool(), x509.NewCertPool()
		pool.AddCert(inter)
		roots.AddCert(rootCert)
		_, err = leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		return err
	}
	if err := verify(td); err != nil {
		return fmt.Errorf("a leaf of the trust domain does not verify under it: %w", err)
	}
	if verify("probe-"+td) == nil || verify("other.example") == nil {
		return errors.New("a leaf of another domain verifies under it")
	}
	return nil
}
