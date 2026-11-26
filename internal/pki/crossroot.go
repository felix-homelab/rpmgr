// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"
)

// The cross-certificate of a root rotation (docs/04-security.md, "Root rotation"): the old root R1
// vouches for the new root R2 with a certificate X for R2's public key and subject. An agent takes
// R2 only when X verifies under a root it trusts.

// ErrCrossRootRefused is returned for a cross-certificate that fails a check before it is imported.
var ErrCrossRootRefused = errors.New("pki: the cross-certificate is refused")

// rootSubject is the subject of every root of trust domain td. R2 has R1's subject, so that a
// cross-certificate and the root it vouches for agree byte for byte.
func rootSubject(td string) pkix.Name { return pkix.Name{CommonName: "rpmgr root CA " + td} }

// SignCrossRoot is what `rpmgr ca sign-intermediate --kind cross-root` does with the old root
// opened: it checks the request (its signature and an ECDSA P-256 key that is not the old root's)
// and signs the cross-certificate X for that key. X has the subject and SubjectKeyId of the new
// root, which the request's subject cannot change, and is a CA with a path length of 1 that lasts
// no longer than the old root.
func SignCrossRoot(root KeyPair, csrPEM []byte, now time.Time) (*x509.Certificate, error) {
	td, err := TrustDomainOf(root.Cert)
	if err != nil {
		return nil, err
	}
	pub, err := parseRequest(csrPEM)
	if err != nil {
		return nil, err
	}
	if pub.Equal(&root.Key.PublicKey) {
		return nil, fmt.Errorf("%w: the key is the root's", ErrBadCSR)
	}
	return create(&x509.Certificate{
		Subject:               rootSubject(td),
		NotBefore:             now.Add(-Backdate),
		NotAfter:              capAt(now.Add(RootLifetime), root.Cert),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root.Cert, pub, root.Key)
}

// VerifyCrossRoot checks the cross-certificate x of the new root r2 before it is imported, and
// names the first check that fails (ErrCrossRootRefused). It holds when: x carries r2's public key
// and its Subject and SubjectKeyId byte for byte; root, the old root, signed it; it is a CA with key
// usage certSign and a path length of at least 1, and no critical extension that is not understood;
// it is valid at now and does not outlast root.
func VerifyCrossRoot(x, root, r2 *x509.Certificate, now time.Time) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrCrossRootRefused, fmt.Sprintf(format, a...))
	}
	if _, err := TrustDomainOf(root); err != nil {
		return err
	}
	switch {
	case !bytes.Equal(x.RawSubjectPublicKeyInfo, r2.RawSubjectPublicKeyInfo):
		return fail("it is not for the new root's key")
	case !bytes.Equal(x.RawSubject, r2.RawSubject):
		return fail("its subject is not the new root's, byte for byte")
	case len(r2.SubjectKeyId) == 0 || !bytes.Equal(x.SubjectKeyId, r2.SubjectKeyId):
		return fail("its SubjectKeyId is not the new root's, byte for byte")
	case !bytes.Equal(x.RawIssuer, root.RawSubject) || x.CheckSignatureFrom(root) != nil:
		return fail("the old root's key did not sign it")
	case !x.IsCA || !x.BasicConstraintsValid || x.KeyUsage&x509.KeyUsageCertSign == 0:
		return fail("it is not a CA with key usage certSign")
	case x.MaxPathLen == 0:
		return fail("its path length is 0; it must allow at least 1")
	case len(x.UnhandledCriticalExtensions) != 0:
		return fail("it has a critical extension that is not understood")
	case now.Before(x.NotBefore) || !now.Before(x.NotAfter):
		return fail("it is not valid now")
	case x.NotAfter.After(root.NotAfter):
		return fail("it outlasts the old root")
	}
	return nil
}

// CrossSign makes the certificates of a root rotation that the old root signs when its key is
// online, by the path of the offline root: the cross-certificate X for the new root's key, and Y for
// the new intermediate's key (an ordinary intermediate of the old root, so that a chain
// `leaf <- Y <- old root` exists for an agent that knows only the old root).
func CrossSign(oldRoot KeyPair, newRoot, inter *ecdsa.PrivateKey, now time.Time) (x, y *x509.Certificate, err error) {
	csr, err := RequestFor(newRoot)
	if err != nil {
		return nil, nil, err
	}
	if x, err = SignCrossRoot(oldRoot, csr, now); err != nil {
		return nil, nil, err
	}
	if csr, err = RequestFor(inter); err != nil {
		return nil, nil, err
	}
	if y, err = SignIntermediate(oldRoot, csr, now); err != nil {
		return nil, nil, err
	}
	return x, y, nil
}
