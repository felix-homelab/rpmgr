// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
)

// TestProbeTarget_ThroughConnector: the controller asks the route's connector for the certificate
// a TLS target presents (ADR-0017). The connector refuses while its local policy does not allow the
// target, reads the self-signed certificate once the policy is edited, without a new revision, and
// a connector without a control session is reported as such.
func TestProbeTarget_ThroughConnector(t *testing.T) {
	p := newDataPlane(t)
	c := p.dial(t)
	_ = c.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nas.local"}, DNSNames: []string{"nas.local"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	probe := func() ([]byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		return p.c.Sessions.ProbeTarget(ctx, p.connector, &agentv1.ProbeTarget{
			Address: &agentv1.ProbeTarget_HostPort{HostPort: ln.Addr().String()}, ServerName: "nas.local"})
	}

	var failed *apisvc.ProbeFailed
	if _, err := probe(); !errors.As(err, &failed) || !strings.Contains(failed.Message, "local policy does not allow "+ln.Addr().String()) {
		t.Fatalf("a target the policy does not allow: %v", err)
	}
	allowed, err := os.ReadFile(p.conCfg.PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	more := fmt.Sprintf("%s  - cidr: 127.0.0.1/32\n    ports: [%d]\n", allowed, ln.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(p.conCfg.PolicyFile, []byte(more), 0o600); err != nil { //nolint:gosec // G703: the test's own policy file
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, err := probe()
		if err == nil {
			if !bytes.Equal(got, der) {
				t.Fatal("the probe read another certificate")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the policy allowed the target: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	p.stopConnector()
	deadline = time.Now().Add(15 * time.Second)
	for _, err := probe(); !errors.Is(err, apisvc.ErrProbeNotConnected); _, err = probe() {
		if time.Now().After(deadline) {
			t.Fatalf("a stopped connector: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
