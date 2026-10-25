// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// serverName is the name the model gateway's test certificate carries.
const serverName = "gateway.s10.test"

// ensureTLS writes a test CA and a gateway certificate into dir, once (the spike never skips
// verification: clients trust the test CA, as rpmgr's tests do).
func ensureTLS(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "gw.pem")); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "s10 test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serverName},
		DNSNames: []string{serverName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	caCert, _ := x509.ParseCertificate(caDER)
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "gw.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "gw.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func serverTLS(dir string) (*tls.Config, error) {
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, "gw.pem"), filepath.Join(dir, "gw.key"))
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13, NextProtos: []string{"s10"}}, nil
}

func clientTLS(dir string) (*tls.Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("no CA in ca.pem")
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{"s10"}}, nil
}
