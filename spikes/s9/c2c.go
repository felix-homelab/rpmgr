// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The trust domain of the spike's controller identities.
const trustDomain = "s9.test"

func controllerID(node string) string  { return "spiffe://" + trustDomain + "/controller/" + node }
func controllerDNS(node string) string { return node + ".controller." + trustDomain }

// runPKI writes a CA and leaf certificates: one controller node certificate (clientAuth and
// serverAuth, as 10 requires for c2c) per node named, and a connector's for the negative test.
func runPKI(args []string) error {
	fs := flag.NewFlagSet("pki", flag.ExitOnError)
	dir := fs.String("dir", "", "output directory")
	_ = fs.Parse(args)
	return writePKI(*dir, fs.Args())
}

func writePKI(dir string, nodes []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "s9 root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, _ := x509.ParseCertificate(caDER)
	if err := writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER); err != nil {
		return err
	}
	leaf := func(name, spiffe, dns string, serial int64) error {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		u, _ := url.Parse(spiffe)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			URIs: []*url.URL{u}, DNSNames: []string{dns}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		kb, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, name+".pem"), "CERTIFICATE", der); err != nil {
			return err
		}
		return writePEM(filepath.Join(dir, name+"-key.pem"), "EC PRIVATE KEY", kb)
	}
	for i, n := range nodes {
		if err := leaf(n, controllerID(n), controllerDNS(n), int64(10+i)); err != nil {
			return err
		}
	}
	return leaf("connector", "spiffe://"+trustDomain+"/connector/c1", "c1.connector."+trustDomain, 99)
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

// peerIsController checks the peer's leaf: a controller ID of the trust domain, and the node
// expected when want is not empty.
func peerIsController(cs tls.ConnectionState, want string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("no peer certificate")
	}
	l := cs.PeerCertificates[0]
	if len(l.URIs) != 1 {
		return errors.New("the peer has no single SPIFFE ID")
	}
	id := l.URIs[0].String()
	prefix := "spiffe://" + trustDomain + "/controller/"
	if !strings.HasPrefix(id, prefix) {
		return fmt.Errorf("the peer %s is not a controller", id)
	}
	if want != "" && id != controllerID(want) {
		return fmt.Errorf("the peer is %s, not %s", id, controllerID(want))
	}
	return nil
}

func loadPKI(dir, name string) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem"))
	if err != nil {
		return cert, nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "ca.pem")) //nolint:gosec // spike input
	if err != nil {
		return cert, nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)
	return cert, pool, nil
}

// c2cClient returns an HTTP/2 client over mutual TLS that accepts only node as its peer.
func c2cClient(cert tls.Certificate, roots *x509.CertPool, node string) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots,
		ServerName: controllerDNS(node), NextProtos: []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error { return peerIsController(cs, node) }}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

type c2cClients struct {
	mu      sync.Mutex
	cert    tls.Certificate
	roots   *x509.CertPool
	clients map[string]*http.Client
}

func (c *c2cClients) get(node string) *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl := c.clients[node]; cl != nil {
		return cl
	}
	cl := c2cClient(c.cert, c.roots, node)
	c.clients[node] = cl
	return cl
}

var clients *c2cClients

// startC2C starts the internal listener, which accepts only controller identities, and records
// the replica in controller_nodes.
func (r *replica) startC2C(ctx context.Context, addr, dir string) (net.Listener, error) {
	cert, roots, err := loadPKI(dir, r.node)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots,
		ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error { return peerIsController(cs, "") }}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /c2c/probe", func(w http.ResponseWriter, req *http.Request) {
		delay, _ := time.ParseDuration(req.URL.Query().Get("delay"))
		_, err := r.probe(req.Context(), req.URL.Query().Get("agent"), delay, false)
		switch {
		case errors.Is(err, errNotHere):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, TLSConfig: cfg}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	clients = &c2cClients{cert: cert, roots: roots, clients: map[string]*http.Client{}}
	r.c2c = &http.Client{}
	if _, err := r.pool.Exec(ctx, `INSERT INTO controller_nodes VALUES ($1, $2, now())
		ON CONFLICT (node_id) DO UPDATE SET internal_address = excluded.internal_address, last_seen = now()`,
		r.node, ln.Addr().String()); err != nil {
		return nil, err
	}
	return ln, nil
}

// forward sends the probe to node; a 409 means the agent moved, and the registry is read once
// more.
func (r *replica) forward(ctx context.Context, node, addr, agent string, delay time.Duration) error {
	u := fmt.Sprintf("https://%s/c2c/probe?agent=%s&delay=%s", addr, url.QueryEscape(agent), delay)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := clients.get(node).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %d %s", node, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if resp.ProtoMajor != 2 {
		return fmt.Errorf("c2c over %s, not HTTP/2", resp.Proto)
	}
	return nil
}
