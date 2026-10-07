// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// capture keeps the TLS state of the connection it made, for a CSR bound to it.
type capture struct {
	credentials.TransportCredentials
	mu    sync.Mutex
	state tls.ConnectionState
}

func (c *capture) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	if ti, ok := info.(credentials.TLSInfo); ok && err == nil {
		c.mu.Lock()
		c.state = ti.State
		c.mu.Unlock()
	}
	return conn, info, err
}

func (c *capture) Clone() credentials.TransportCredentials { return c }

// boundCSR is a CSR for a new key, bound to the connection c made.
func (c *capture) boundCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	csr, err := pki.NewBoundCSR(key, c.state)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return key, csr.Raw
}

// dial connects as cert to SNI name, controller.<td> or reauth.controller.<td>; with wait it
// waits for the handshake, so that the connection's TLS state is known.
func (e *sessionEnv) dial(t *testing.T, cert tls.Certificate, name string, wait bool) (*grpc.ClientConn, *capture) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Root())
	cfg := pki.ClientConfig(cert, roots, name, pki.Expect{TrustDomain: e.ca.TrustDomain(), Kinds: []pki.Kind{pki.KindController}}, nil, nil)
	c := &capture{TransportCredentials: credentials.NewTLS(cfg)}
	cc, err := grpc.NewClient("passthrough:///"+e.addr, grpc.WithTransportCredentials(c))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	if wait {
		cc.Connect()
		ctx := testCtx(t)
		for s := cc.GetState(); s != connectivity.Ready; s = cc.GetState() {
			if !cc.WaitForStateChange(ctx, s) {
				t.Fatalf("no connection to %s", name)
			}
		}
	}
	return cc, c
}

// certAt issues a connector certificate for id as the CA would have at time at, recorded like
// every certificate the CA issues.
func (e *sessionEnv) certAt(t *testing.T, id pki.Identity, at time.Time) tls.Certificate {
	t.Helper()
	ca, err := pki.LoadCA(e.sys, e.db, e.sealer, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	var leaf *x509.Certificate
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		leaf, err = ca.Issue(e.sys, tx, csr, id, pki.DefaultLeafLifetime)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Intermediate().Raw}, PrivateKey: key, Leaf: leaf}
}

func (e *sessionEnv) newIdentity() pki.Identity {
	return pki.Identity{TrustDomain: e.ca.TrustDomain(), Org: e.org, Kind: pki.KindConnector, ID: ids.New("con")}
}

func reauthName(e *sessionEnv) string { return "reauth.controller." + e.ca.TrustDomain() }

// renewed checks a returned chain: the leaf is for id, with key, chaining to the CA.
func (e *sessionEnv) renewed(t *testing.T, chain [][]byte, id pki.Identity, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	if len(chain) != 2 {
		t.Fatalf("chain of %d certificates", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.ca.IdentityOf(leaf, time.Now())
	if err != nil || got != id || !key.PublicKey.Equal(leaf.PublicKey) {
		t.Fatalf("renewed leaf: identity %v (%v), key matches %v", got, err, key.PublicKey.Equal(leaf.PublicKey))
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}
}

func (e *sessionEnv) renewable(t *testing.T, cert tls.Certificate) error {
	t.Helper()
	return pki.CheckRenewable(e.sys, e.db.Client(), cert.Leaf)
}

// TestRenew: an agent renews over the control endpoint with a bound CSR and a new key; once the new
// certificate is used in a session, the old one is superseded and can no longer be renewed.
func TestRenew(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.1.0", 0)
		old, id := e.agentCert(t)
		cc, c := e.dial(t, old, "controller."+e.ca.TrustDomain(), true)
		key, csr := c.boundCSR(t)
		resp, err := agentv1.NewControlClient(cc).Renew(testCtx(t), &agentv1.RenewRequest{Csr: csr})
		if err != nil {
			t.Fatal(err)
		}
		next := e.renewed(t, resp.GetChain(), id, key)
		if err := e.renewable(t, old); err != nil {
			t.Fatalf("the old certificate before the new one was used: %v", err)
		}
		st := e.open(t, testCtx(t), next, hello("0.1.0"))
		if recv(t, st).GetWelcome() == nil {
			t.Fatal("no session with the renewed certificate")
		}
		if err := e.renewable(t, old); !errors.Is(err, pki.ErrSuperseded) {
			t.Fatalf("the old certificate after the new one was used: %v", err)
		}
		cc2, c2 := e.dial(t, old, "controller."+e.ca.TrustDomain(), true)
		_, csr2 := c2.boundCSR(t)
		if _, err := agentv1.NewControlClient(cc2).Renew(testCtx(t), &agentv1.RenewRequest{Csr: csr2}); code(err) != codes.PermissionDenied {
			t.Fatalf("renewing a superseded certificate: %v", err)
		}
	})
}

// TestRenew_Binding is the Renew and Reauth clause of TestCSR_BoundToConnection: a CSR without the
// connection's tls-exporter value, or bound to another connection, is refused; so are a CSR that
// does not parse and one for the same key.
func TestRenew_Binding(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	cert, _ := e.agentCert(t)
	cc, _ := e.dial(t, cert, "controller."+e.ca.TrustDomain(), true)
	_, other := e.dial(t, cert, "controller."+e.ca.TrustDomain(), true)
	_, foreign := other.boundCSR(t)
	key, _ := pki.NewKey()
	plainDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	client := agentv1.NewControlClient(cc)
	for name, tt := range map[string]struct {
		csr  []byte
		want codes.Code
	}{
		"bound to another connection": {foreign, codes.PermissionDenied},
		"no binding":                  {plainDER, codes.PermissionDenied},
		"not a CSR":                   {[]byte("junk"), codes.InvalidArgument},
	} {
		if _, err := client.Renew(testCtx(t), &agentv1.RenewRequest{Csr: tt.csr}); code(err) != tt.want {
			t.Errorf("%s: %v, want %s", name, err, tt.want)
		}
	}

	// The same key, bound correctly.
	cc2, c2 := e.dial(t, cert, "controller."+e.ca.TrustDomain(), true)
	c2.mu.Lock()
	same, err := pki.NewBoundCSR(cert.PrivateKey.(*ecdsa.PrivateKey), c2.state)
	c2.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentv1.NewControlClient(cc2).Renew(testCtx(t), &agentv1.RenewRequest{Csr: same.Raw}); code(err) != codes.InvalidArgument {
		t.Errorf("the same key: %v", err)
	}

	// Reauth, with an expired certificate, refuses a CSR of another connection too.
	expired := e.certAt(t, e.newIdentity(), time.Now().Add(-8*24*time.Hour))
	rc, _ := e.dial(t, expired, reauthName(e), true)
	if _, err := agentv1.NewReauthClient(rc).Reauth(testCtx(t), &agentv1.ReauthRequest{Csr: foreign}); code(err) != codes.PermissionDenied {
		t.Errorf("Reauth with a CSR of another connection: %v", err)
	}
}

// TestReauth_ExpiredWithinGrace: a certificate expired within the grace period is re-issued
// through reauth.controller.<td>, also when a newer certificate was issued but its Renew response
// was lost; one expired longer, one with grace 0 and a revoked serial are refused at the TLS layer,
// and the normal control endpoint never accepts an expired certificate. (After a restore: 11.6; a
// revoked identity: 3.13.)
func TestReauth_ExpiredWithinGrace(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.1.0", 0)
		id := e.newIdentity()
		expired := e.certAt(t, id, time.Now().Add(-8*24*time.Hour)) // expired a day ago
		// A newer certificate whose Renew response never arrived: issued, never used.
		e.certAt(t, id, time.Now().Add(-7*24*time.Hour-time.Hour))

		cc, _ := e.dial(t, expired, "controller."+e.ca.TrustDomain(), false)
		st, err := agentv1.NewControlClient(cc).Session(testCtx(t))
		if err == nil {
			_, err = st.Recv()
		}
		if code(err) != codes.Unavailable {
			t.Fatalf("the control endpoint and an expired certificate: %v", err)
		}

		rc, c := e.dial(t, expired, reauthName(e), true)
		key, csr := c.boundCSR(t)
		resp, err := agentv1.NewReauthClient(rc).Reauth(testCtx(t), &agentv1.ReauthRequest{Csr: csr})
		if err != nil {
			t.Fatal(err)
		}
		next := e.renewed(t, resp.GetChain(), id, key)
		st = e.open(t, testCtx(t), next, hello("0.1.0"))
		if recv(t, st).GetWelcome() == nil {
			t.Fatal("no session with the re-issued certificate")
		}

		// Refused by the TLS layer: the connection fails, no handler answers.
		refused := func(name string, cert tls.Certificate) {
			t.Helper()
			rc, _ := e.dial(t, cert, reauthName(e), false)
			key, _ := pki.NewKey()
			der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if _, err := agentv1.NewReauthClient(rc).Reauth(testCtx(t), &agentv1.ReauthRequest{Csr: der}); code(err) != codes.Unavailable {
				t.Errorf("%s: %v, want a refused connection", name, err)
			}
		}
		refused("expired beyond the grace period", e.certAt(t, e.newIdentity(), time.Now().Add(-40*24*time.Hour)))

		revoked := e.certAt(t, e.newIdentity(), time.Now().Add(-8*24*time.Hour))
		e.db.Client().IssuedCertificate.UpdateOneID(pki.SerialHex(revoked.Leaf.SerialNumber)).SetRevokedAt(time.Now()).ExecX(e.sys)
		refused("revoked serial", revoked)

		if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{ExpiredCertificateGrace: durationpb.New(0)},
			&fieldmaskpb.FieldMask{Paths: []string{"expired_certificate_grace"}}, 0); err != nil {
			t.Fatal(err)
		}
		refused("grace 0", e.certAt(t, e.newIdentity(), time.Now().Add(-8*24*time.Hour)))
	})
}

// TestReauth_SupersededSerialRefused: after a newer certificate of the same identity was used in a
// session, Reauth with the older one, as a leaked key or a cloned VM would present it, is refused.
// (After a restore: 11.6.)
func TestReauth_SupersededSerialRefused(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.1.0", 0)
		id := e.newIdentity()
		old := e.certAt(t, id, time.Now().Add(-8*24*time.Hour))
		current := e.certAt(t, id, time.Now().Add(-time.Hour))
		st := e.open(t, testCtx(t), current, hello("0.1.0"))
		if recv(t, st).GetWelcome() == nil {
			t.Fatal("no session")
		}
		if err := e.renewable(t, old); !errors.Is(err, pki.ErrSuperseded) {
			t.Fatalf("the older certificate: %v", err)
		}
		rc, _ := e.dial(t, old, reauthName(e), false)
		key, _ := pki.NewKey()
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if _, err := agentv1.NewReauthClient(rc).Reauth(testCtx(t), &agentv1.ReauthRequest{Csr: der}); code(err) != codes.Unavailable {
			t.Fatalf("Reauth with a superseded certificate: %v, want a refused connection", err)
		}
	})
}
