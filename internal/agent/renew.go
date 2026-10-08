// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// Certificate renewal (docs/04-security.md, "Leaf certificates"): within the window of 45–55 % of
// the lifetime, over the control session, with a new key every time; with an expired certificate,
// through Reauth.
const (
	renewFrom   = 0.45
	renewWindow = 0.10
	// renewMinInterval separates two renewals, so that a clock far ahead cannot make the agent
	// renew in a loop (docs/03-connections.md, "Timeouts, keepalive and backoff").
	renewMinInterval = 10 * time.Minute
)

// errNoSession is returned by Renew while the client has no control session.
var errNoSession = errors.New("agent: no control session")

// RenewAt returns when to renew leaf: at 45 % of its lifetime plus jitter, a number in [0, 1), of
// another 10 %.
func RenewAt(leaf *x509.Certificate, jitter float64) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotBefore.Add(time.Duration(float64(life) * (renewFrom + renewWindow*jitter)))
}

func randomFraction() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

// Certificate returns the certificate that new connections present.
func (c *Client) Certificate() tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert
}

func (c *Client) setCertificate(cert tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cert = cert
}

// stateCreds are TLS credentials that keep the state of the connection they made, so that a CSR
// can be bound to it.
type stateCreds struct {
	credentials.TransportCredentials
	mu    sync.Mutex
	state *tls.ConnectionState
}

func (s *stateCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := s.TransportCredentials.ClientHandshake(ctx, authority, raw)
	if ti, ok := info.(credentials.TLSInfo); ok && err == nil {
		s.mu.Lock()
		s.state = &ti.State
		s.mu.Unlock()
	}
	return conn, info, err
}

func (s *stateCreds) Clone() credentials.TransportCredentials { return s }

func (s *stateCreds) boundCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, errNoSession
	}
	csr, err := pki.NewBoundCSR(key, *s.state)
	if err != nil {
		return nil, err
	}
	return csr.Raw, nil
}

// credentials are the TLS credentials of a connection to the controller name sni with the current
// certificate.
func (c *Client) credentials(sni string) *stateCreds {
	cfg := pki.ClientConfig(c.Certificate(), c.o.Identity.Roots, sni,
		pki.Expect{TrustDomain: c.o.Identity.TrustDomain, Kinds: []pki.Kind{pki.KindController}}, c.o.Now, nil)
	return &stateCreds{TransportCredentials: credentials.NewTLS(cfg)}
}

// renewLoop renews the certificate in its window, until ctx ends. A failed renewal is retried
// after a backoff; the current certificate stays in use until a new one is stored.
func (c *Client) renewLoop(ctx context.Context) {
	retry := &Backoff{Base: time.Second, Cap: 5 * time.Minute, ResetAfter: time.Hour}
	jitter := c.o.RenewJitter()
	for {
		leaf := c.Certificate().Leaf
		if leaf == nil {
			return
		}
		if wait := RenewAt(leaf, jitter).Sub(c.o.Now()); wait > 0 && !sleep(ctx, wait) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err := c.renewOnce(ctx); err != nil {
			c.o.Logger.Warn("certificate renewal failed; retrying", "error", err)
			if !sleep(ctx, retry.Next(0)) {
				return
			}
			continue
		}
		retry.Healthy(time.Hour)
		jitter = c.o.RenewJitter()
		if !sleep(ctx, renewMinInterval) {
			return
		}
	}
}

// renewOnce renews over the current control session and then reconnects with the new certificate,
// so that the controller sees it and supersedes the old one.
func (c *Client) renewOnce(ctx context.Context) error {
	c.sendMu.Lock()
	conn, creds := c.conn, c.creds
	c.sendMu.Unlock()
	if conn == nil {
		return errNoSession
	}
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := creds.boundCSR(key)
	if err != nil {
		return err
	}
	resp, err := agentv1.NewControlClient(conn).Renew(ctx, &agentv1.RenewRequest{Csr: csr})
	if err != nil {
		return err
	}
	if err := c.adopt(key, resp.GetChain()); err != nil {
		return err
	}
	c.o.Logger.Info("certificate renewed", "not_after", c.Certificate().Leaf.NotAfter)
	c.Reconnect()
	return nil
}

// Reconnect ends the current control session; Run starts the next one.
func (c *Client) Reconnect() {
	c.sendMu.Lock()
	end := c.end
	c.sendMu.Unlock()
	if end != nil {
		end()
	}
}

// adopt checks a new chain against the key and the agent's identity, stores it and makes it the
// certificate of new connections.
func (c *Client) adopt(key *ecdsa.PrivateKey, chain [][]byte) error {
	if len(chain) == 0 {
		return errors.New("agent: the controller returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return fmt.Errorf("agent: the new certificate: %w", err)
	}
	old := c.Certificate().Leaf
	switch {
	case !key.PublicKey.Equal(leaf.PublicKey):
		return errors.New("agent: the new certificate is not for the new key")
	case len(leaf.URIs) != 1 || old == nil || len(old.URIs) != 1 || leaf.URIs[0].String() != old.URIs[0].String():
		return errors.New("agent: the new certificate is for another identity")
	}
	if c.o.SaveCertificate != nil {
		if err := c.o.SaveCertificate(key, chain); err != nil {
			return fmt.Errorf("agent: storing the new certificate: %w", err)
		}
	}
	c.setCertificate(tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf})
	return nil
}

// reauthIfExpired gets a new certificate through Reauth at endpoint if the current one expired,
// which the control endpoint would refuse.
func (c *Client) reauthIfExpired(ctx context.Context, endpoint string) error {
	leaf := c.Certificate().Leaf
	if leaf == nil || !c.o.Now().After(leaf.NotAfter) {
		return nil
	}
	if endpoint == DataSessionEndpoint {
		// A connector with an expired certificate has no data session either.
		return errors.New("agent: the certificate expired; Reauth needs a direct controller endpoint")
	}
	addr, err := dialAddr(endpoint)
	if err != nil {
		return err
	}
	creds := c.credentials("reauth.controller." + c.o.Identity.TrustDomain)
	conn, err := grpc.NewClient("passthrough:///"+addr, append(dialOptions(c.o.Dial), grpc.WithTransportCredentials(creds))...)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn.Connect()
	for s := conn.GetState(); s != connectivity.Ready; s = conn.GetState() {
		if s == connectivity.TransientFailure || !conn.WaitForStateChange(rctx, s) {
			return errors.New("agent: the certificate expired and Reauth is not reachable")
		}
	}
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := creds.boundCSR(key)
	if err != nil {
		return err
	}
	resp, err := agentv1.NewReauthClient(conn).Reauth(rctx, &agentv1.ReauthRequest{Csr: csr})
	if err != nil {
		return fmt.Errorf("agent: Reauth: %w", err)
	}
	if err := c.adopt(key, resp.GetChain()); err != nil {
		return err
	}
	c.o.Logger.Info("expired certificate re-issued through Reauth", "not_after", c.Certificate().Leaf.NotAfter)
	return nil
}
