// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

const testPass = "correct horse battery staple 42"

func TestGeneratePassphrase(t *testing.T) {
	a, err := pki.GeneratePassphrase()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pki.GeneratePassphrase()
	if a == b {
		t.Fatal("two generated passphrases are equal")
	}
	groups := strings.Split(a, "-")
	if len(a) != 26+len(groups)-1 || len(groups[0]) != 4 {
		t.Fatalf("passphrase %q is not 128 bits as groups of 4", a)
	}
	if err := pki.CheckPassphrase(a); err != nil {
		t.Fatalf("a generated passphrase fails the check: %v", err)
	}
}

func TestCheckPassphrase(t *testing.T) {
	for _, tc := range []struct {
		name, pass string
		ok         bool
	}{
		{"empty", "", false},
		{"short", "Tr0ub4dor&3", false},
		{"15 characters", "abcdefghijklmno", false},
		{"long but one character", strings.Repeat("a", 40), false},
		{"16 characters of few kinds", "abababababababab", false},
		{"alphabet run", "abcdefghijklmnop", false},
		{"keyboard row", "qwertyuiopasdfgh", false},
		{"upper case run", "ABCDEFGHIJKLMNOP", false},
		{"digit run and keyboard row", "1234567890qwerty", false},
		{"common word with a run and symbols", "Password1234!@#$", false},
		{"descending run", "zyxwvutsrqponmlk", false},
		{"enough", testPass, true},
		{"mixed", "Xk9#mQ2$vL7!pR4z", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := pki.CheckPassphrase(tc.pass)
			if (err == nil) != tc.ok || (err != nil && !errors.Is(err, pki.ErrWeakPassphrase)) {
				t.Fatalf("CheckPassphrase(%q) = %v, want ok %v", tc.pass, err, tc.ok)
			}
		})
	}
}

func TestRootFileRoundTrip(t *testing.T) {
	root := newRootPair(t)
	file, err := pki.SealRootFile(root, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(file, []byte("age-encryption.org/v1\n-> scrypt ")) {
		t.Fatalf("the file is not an age passphrase file: %q", file[:40])
	}
	got, err := pki.OpenRootFile(file, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Cert.Equal(root.Cert) || !got.Key.Equal(root.Key) {
		t.Fatal("the file opened to another root")
	}
}

// A file that does not open says only so, whatever the reason.
func TestRootFileDoesNotOpen(t *testing.T) {
	root := newRootPair(t)
	file, err := pki.SealRootFile(root, testPass)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		b := bytes.Clone(file)
		b[i] ^= 1
		return b
	}
	other := newRootPair(t)
	otherFile, _ := pki.SealRootFile(other, testPass)
	// A key that does not belong to the certificate inside, sealed properly.
	mismatch := mismatchedFile(t, root, other)
	for name, tc := range map[string]struct {
		file []byte
		pass string
	}{
		"wrong passphrase":    {file, testPass + "x"},
		"empty passphrase":    {file, ""},
		"truncated":           {file[:len(file)-10], testPass},
		"header only":         {file[:60], testPass},
		"empty file":          {nil, testPass},
		"tampered payload":    {flip(len(file) - 20), testPass},
		"tampered header":     {flip(60), testPass},
		"extended":            {append(bytes.Clone(file), 0), testPass},
		"not an age file":     {[]byte("-----BEGIN PRIVATE KEY-----"), testPass},
		"key and cert differ": {mismatch, testPass},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pki.OpenRootFile(tc.file, tc.pass)
			if !errors.Is(err, pki.ErrRootFile) || err.Error() != pki.ErrRootFile.Error() {
				t.Fatalf("OpenRootFile = %v, want only ErrRootFile", err)
			}
		})
	}
	if _, err := pki.OpenRootFile(otherFile, testPass); err != nil {
		t.Fatalf("a second root's file does not open: %v", err)
	}
}

func mismatchedFile(t *testing.T, cert, key pki.KeyPair) []byte {
	t.Helper()
	// SealRootFile refuses nothing about the pairing, so seal the key of one root with the
	// certificate of another by building the pair by hand.
	file, err := pki.SealRootFile(pki.KeyPair{Cert: cert.Cert, Key: key.Key}, testPass)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestSignIntermediate(t *testing.T) {
	root := newRootPair(t)
	key, csr, err := pki.NewIntermediateRequest()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.SignIntermediate(root, csr, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.VerifyIntermediate(cert, root.Cert, &key.PublicKey, t0); err != nil {
		t.Fatalf("a signed intermediate does not verify: %v", err)
	}
	if cert.NotAfter.After(root.Cert.NotAfter) || cert.MaxPathLen != 0 || !cert.PermittedDNSDomainsCritical {
		t.Fatal("the intermediate lacks the properties of the CA hierarchy")
	}
	if strings.Contains(cert.Subject.String(), "attacker") {
		t.Fatal("the request's subject was used")
	}
}

func TestSignIntermediateRefusesBadRequests(t *testing.T) {
	root := newRootPair(t)
	rsa := func() []byte {
		// A request for a key of another curve.
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}()
	_, good, _ := pki.NewIntermediateRequest()
	b, _ := pem.Decode(good)
	broken := bytes.Clone(b.Bytes)
	broken[len(broken)-1] ^= 1
	rootDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, root.Key)
	for name, csr := range map[string][]byte{
		"not PEM":        []byte("hello"),
		"wrong block":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes}),
		"garbage":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2, 3}}),
		"bad signature":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: broken}),
		"wrong curve":    rsa,
		"the root's key": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rootDER}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pki.SignIntermediate(root, csr, t0); !errors.Is(err, pki.ErrBadCSR) {
				t.Fatalf("SignIntermediate = %v, want ErrBadCSR", err)
			}
		})
	}
	// The request's subject is ignored.
	key := newKey(t)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker"}}, key)
	cert, err := pki.SignIntermediate(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), t0)
	if err != nil || strings.Contains(cert.Subject.String(), "attacker") {
		t.Fatalf("subject of the request leaked into the certificate: %v %v", cert, err)
	}
}
