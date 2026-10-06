// SPDX-License-Identifier: Apache-2.0

package s7

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

// Criterion 5: SNI reauth.controller.<td> selects a verifier that accepts client certificates
// expired at most the grace period ago and nothing older, and refuses revoked and superseded
// serials; the normal SNI never accepts an expired certificate.
func TestReauth(t *testing.T) {
	clk := newClock()
	ca := newCA(t, clk)
	conID := connectorID("org_a", "con_1")
	t0 := clk.Now()
	agent := issue(t, ca, conID, ProfileConnector, AgentLeafLifetime)
	expiry := agent.cert.NotAfter

	// controller returns the controller's configuration at the current fake time, with a fresh
	// controller certificate (the agent still verifies it against the pinned root).
	controller := func(grace time.Duration) (*tls.Config, *Counters) {
		ctl := issue(t, ca, controllerID("node_1"), ProfileController, ControllerLifetime)
		c := &Counters{}
		return ControllerConfig(ctl.tls, ca, Expect{TrustDomain: td, Kinds: []Kind{KindConnector, KindGateway}, Counters: c}, grace), c
	}
	client := func(l leaf, sni string, cache tls.ClientSessionCache) *tls.Config {
		return ClientConfig(l.tls, ca.Roots(), sni, Expect{TrustDomain: td, Kinds: []Kind{KindController}}, clk.Now, cache)
	}
	normalSNI, reauthSNI := "controller."+td, "reauth.controller."+td
	var lastKey *ecdsa.PrivateKey
	reauth := func(l leaf, grace time.Duration) (*x509.Certificate, result) {
		srv, _ := controller(grace)
		var got *x509.Certificate
		lastKey = newKey(t)
		r := run(t, srv, client(l, reauthSNI, nil), serveIssue(ca, ProfileConnector), requestIssue(boundCSR(lastKey), &got))
		return got, r
	}
	reauthErr := func(r result) error {
		if r.srvErr != nil {
			return r.srvErr
		}
		return r.cliErr
	}

	t.Run("expired 29 days ago: normal SNI refuses, reauth SNI re-issues", func(t *testing.T) {
		clk.Set(expiry.Add(29 * 24 * time.Hour))
		srv, _ := controller(DefaultGrace)
		r := run(t, srv, client(agent, normalSNI, nil), nil, nil)
		var cie x509.CertificateInvalidError
		if !errors.As(r.srvErr, &cie) || cie.Reason != x509.Expired {
			t.Fatalf("normal SNI: server %v", r.srvErr)
		}
		got, r := reauth(agent, DefaultGrace)
		if !r.ok() || got == nil {
			t.Fatalf("reauth: server %v, client %v", r.srvErr, r.cliErr)
		}
		if got.URIs[0].String() != conID.String() || !got.NotBefore.Equal(clk.Now().Add(-Backdate)) {
			t.Fatalf("re-issued %v from %v", got.URIs, got.NotBefore)
		}
		// The new certificate works on the normal SNI.
		renewed := leaf{key: lastKey, cert: got, tls: tlsCert(ca, got, lastKey)}
		if r := run(t, srv, client(renewed, normalSNI, nil), nil, nil); !r.ok() {
			t.Fatalf("re-issued certificate on the normal SNI: %v %v", r.srvErr, r.cliErr)
		}
	})
	t.Run("grace boundary", func(t *testing.T) {
		clk.Set(expiry.Add(DefaultGrace))
		if _, r := reauth(agent, DefaultGrace); !r.ok() {
			t.Fatalf("exactly at the end of the grace period: %v %v", r.srvErr, r.cliErr)
		}
		clk.Set(expiry.Add(DefaultGrace + time.Second))
		if _, r := reauth(agent, DefaultGrace); !errIs(r.srvErr, ErrExpiredGrace) {
			t.Fatalf("one second later: %v", reauthErr(r))
		}
	})
	t.Run("grace 0 disables Reauth for expired certificates", func(t *testing.T) {
		clk.Set(expiry.Add(time.Minute))
		if _, r := reauth(agent, 0); !errIs(r.srvErr, ErrExpiredGrace) {
			t.Fatalf("%v", reauthErr(r))
		}
	})
	t.Run("revoked serial and revoked identity", func(t *testing.T) {
		clk.Set(t0)
		a := issue(t, ca, connectorID("org_a", "con_rev1"), ProfileConnector, AgentLeafLifetime)
		b := issue(t, ca, connectorID("org_a", "con_rev2"), ProfileConnector, AgentLeafLifetime)
		ca.RevokeSerial(a.cert.SerialNumber)
		ca.RevokeIdentity(connectorID("org_a", "con_rev2"))
		clk.Set(expiry.Add(24 * time.Hour))
		for _, l := range []leaf{a, b} {
			if _, r := reauth(l, DefaultGrace); !errIs(r.srvErr, ErrRevoked) {
				t.Fatalf("%v", reauthErr(r))
			}
		}
	})
	t.Run("superseded serial", func(t *testing.T) {
		id := connectorID("org_a", "con_sup")
		clk.Set(t0)
		old := issue(t, ca, id, ProfileConnector, AgentLeafLifetime)
		clk.Set(t0.Add(AgentLeafLifetime / 2))
		// Renew succeeded at the controller, but the response was lost: the new serial was
		// never used, so the old certificate may still re-authenticate.
		k := newKey(t)
		newer, err := ca.Renew(old.cert, plainCSR(t, k), ProfileConnector, AgentLeafLifetime)
		if err != nil {
			t.Fatal(err)
		}
		clk.Set(old.cert.NotAfter.Add(24 * time.Hour))
		if _, r := reauth(old, DefaultGrace); !r.ok() {
			t.Fatalf("lost Renew response: %v", reauthErr(r))
		}
		// Once the newer serial was seen in an authenticated session, the old one is superseded:
		// a leaked key or a cloned image cannot obtain a fresh identity with it.
		ca.MarkSeen(newer.SerialNumber)
		if _, r := reauth(old, DefaultGrace); !errIs(r.srvErr, ErrSuperseded) {
			t.Fatalf("superseded: %v", reauthErr(r))
		}
	})
	t.Run("certificate of another CA with the same trust domain", func(t *testing.T) {
		clk.Set(t0)
		other, err := NewCA(td, clk.Now, true)
		if err != nil {
			t.Fatal(err)
		}
		foreign := issue(t, other, conID, ProfileConnector, AgentLeafLifetime)
		clk.Set(expiry.Add(24 * time.Hour))
		_, r := reauth(foreign, DefaultGrace)
		if r.srvErr == nil || !strings.Contains(r.srvErr.Error(), "chain") {
			t.Fatalf("%v", reauthErr(r))
		}
	})
	t.Run("not yet expired certificate", func(t *testing.T) {
		clk.Set(t0)
		fresh := issue(t, ca, connectorID("org_a", "con_fresh"), ProfileConnector, AgentLeafLifetime)
		clk.Set(t0.Add(time.Hour))
		if _, r := reauth(fresh, DefaultGrace); !r.ok() {
			t.Fatalf("%v", reauthErr(r))
		}
	})
	t.Run("reauth sessions issue and accept no tickets", func(t *testing.T) {
		clk.Set(t0)
		fresh := issue(t, ca, connectorID("org_a", "con_tickets"), ProfileConnector, AgentLeafLifetime)
		srv, _ := controller(DefaultGrace)
		normalCache := tls.NewLRUClientSessionCache(4)
		if r := run(t, srv, client(fresh, normalSNI, normalCache), nil, nil); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		normalSession, ok := normalCache.Get(normalSNI)
		if !ok || normalSession == nil {
			t.Fatal("no ticket from the normal endpoint")
		}
		// A client cache that offers the normal endpoint's ticket for the reauth name too.
		cache := &recordingCache{offer: normalSession}
		r := run(t, srv, client(fresh, reauthSNI, cache), nil, nil)
		if !r.ok() || r.srv.DidResume || r.cli.DidResume {
			t.Fatalf("server %v, client %v, resumed %v", r.srvErr, r.cliErr, r.srv.DidResume)
		}
		if !cache.offered || cache.stored != 0 {
			t.Fatalf("ticket offered %v, tickets received %d", cache.offered, cache.stored)
		}
	})
}

// recordingCache offers one session for every key and counts the tickets it receives.
type recordingCache struct {
	offer   *tls.ClientSessionState
	offered bool
	stored  int
}

func (c *recordingCache) Get(string) (*tls.ClientSessionState, bool) {
	c.offered = true
	return c.offer, true
}

func (c *recordingCache) Put(_ string, cs *tls.ClientSessionState) {
	if cs != nil {
		c.stored++
	}
}
