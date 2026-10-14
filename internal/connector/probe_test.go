// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/policy"
)

// tlsTarget serves TLS on ln with a self-signed certificate for "nas.local", recording the server
// name of each handshake and whether a client sent anything after it; it returns the certificate.
func tlsTarget(t *testing.T, ln net.Listener) (der []byte, sni *atomic.Value, sent *atomic.Bool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nas.local"}, DNSNames: []string{"nas.local"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sni, sent = &atomic.Value{}, &atomic.Bool{}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { sni.Store(h.ServerName); return nil, nil }}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, cfg)
				if tc.Handshake() != nil {
					return
				}
				_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
				if n, _ := tc.Read(make([]byte, 1)); n > 0 {
					sent.Store(true)
				}
			}()
		}
	}()
	return der, sni, sent
}

// TestTargets_Probe: a probe reads the certificate a TLS target presents, on a port or a Unix
// socket, with the server name given and nothing sent after the handshake. A target the local
// policy does not allow, an unreachable one, one that speaks no TLS, and one that does not finish
// the handshake in time are errors that say so.
func TestTargets_Probe(t *testing.T) {
	connector.SetProbeTimeout(t, 500*time.Millisecond)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	der, sni, sent := tlsTarget(t, ln)
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	sock := filepath.Join(t.TempDir(), "app.sock")
	uln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	uder, _, _ := tlsTarget(t, uln)
	silent, err := net.Listen("tcp", "127.0.0.1:0") // accepts, never answers
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	plain, err := net.Listen("tcp", "127.0.0.1:0") // answers with plain text
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
			_ = c.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gonePort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	var cur atomic.Pointer[policy.Policy]
	cur.Store(policyOf(t, fmt.Sprintf("allow_targets:\n  - cidr: 127.0.0.0/8\n    ports: [%d, %d, %d, %d]\n  - unix: %s\n",
		port, silent.Addr().(*net.TCPAddr).Port, plain.Addr().(*net.TCPAddr).Port, gonePort, sock)))
	tg := connector.NewTargets(connector.TargetsOptions{Policy: cur.Load})

	got, err := tg.Probe(t.Context(), &agentv1.ProbeTarget{Address: &agentv1.ProbeTarget_HostPort{HostPort: ln.Addr().String()}, ServerName: "nas.local"})
	if err != nil || !bytes.Equal(got, der) {
		t.Fatalf("a TLS target: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if sni.Load() != "nas.local" || sent.Load() {
		t.Fatalf("server name %v, sent after the handshake %v", sni.Load(), sent.Load())
	}
	if got, err := tg.Probe(t.Context(), &agentv1.ProbeTarget{Address: &agentv1.ProbeTarget_UnixPath{UnixPath: sock}}); err != nil ||
		!bytes.Equal(got, uder) {
		t.Fatalf("a TLS socket: %v", err)
	}
	for name, c := range map[string]struct {
		p    *agentv1.ProbeTarget
		want string
	}{
		"not allowed":     {&agentv1.ProbeTarget{Address: &agentv1.ProbeTarget_HostPort{HostPort: "127.0.0.1:1"}}, "local policy does not allow 127.0.0.1:1"},
		"a socket denied": {&agentv1.ProbeTarget{Address: &agentv1.ProbeTarget_UnixPath{UnixPath: "/run/other.sock"}}, "local policy does not allow"},
		"unreachable":     {&agentv1.ProbeTarget{Address: &agentv1.ProbeTarget_HostPort{HostPort: fmt.Sprintf("127.0.0.1:%d", gonePort)}}, "cannot reach"},
		"no TLS":          {&agentv1.ProbeTarget{Address: &agentv1.ProbeTarget_HostPort{HostPort: plain.Addr().String()}}, "no TLS handshake"},
		"no answer":       {&agentv1.ProbeTarget{Address: &agentv1.ProbeTarget_HostPort{HostPort: silent.Addr().String()}}, "no TLS handshake"},
		"no target":       {&agentv1.ProbeTarget{}, "names no target"},
	} {
		start := time.Now()
		if _, err := tg.Probe(t.Context(), c.p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}
