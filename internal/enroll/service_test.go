// SPDX-License-Identifier: Apache-2.0

package enroll_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
)

// capturingCreds remembers the TLS state of the connection grpc-go opens, so the test client can
// bind its CSR to it, as the agent does.
type capturingCreds struct {
	credentials.TransportCredentials
	mu    sync.Mutex
	state tls.ConnectionState
}

func (c *capturingCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	if err == nil {
		c.mu.Lock()
		c.state = info.(credentials.TLSInfo).State
		c.mu.Unlock()
	}
	return conn, info, err
}

// server starts the agent protocol's server with the Enrollment service on a TCP port.
func (e *env) server(t *testing.T) (string, *enroll.Service) {
	t.Helper()
	node, err := e.ca.NodeCertificate(e.sys, e.db, ids.New("ctn"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Root())
	cfg := pki.AgentEndpointConfig(pki.NewHolder(node), roots, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway}},
		nil, pki.Reauth{})
	srv := controller.NewAgentServer(cfg, td)
	svc := enroll.NewService(e.db, e.ca, []string{"https://panel.example.com"}, func() time.Time { return e.clock })
	agentv1.RegisterEnrollmentServer(srv, svc)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String(), svc
}

// client connects without a certificate, as an enrolling agent does.
func (e *env) client(t *testing.T, addr string) (agentv1.EnrollmentClient, *capturingCreds) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Root())
	cfg := pki.ClientConfig(tls.Certificate{}, roots, "controller."+td,
		pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, nil, nil)
	cfg.Certificates = nil
	creds := &capturingCreds{TransportCredentials: credentials.NewTLS(cfg)}
	cc, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	c := agentv1.NewEnrollmentClient(cc)
	// A first call opens the connection; its outcome does not matter.
	_, _ = c.Enroll(context.Background(), &agentv1.EnrollRequest{})
	return c, creds
}

// boundCSR returns a CSR for a new key bound to the client's current connection.
func boundCSR(t *testing.T, creds *capturingCreds) []byte {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	creds.mu.Lock()
	state := creds.state
	creds.mu.Unlock()
	csr, err := pki.NewBoundCSR(key, state)
	if err != nil {
		t.Fatal(err)
	}
	return csr.Raw
}

func callCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestEnroll_Connector: an enrollment over the agent protocol creates the connector, names it after
// the host, and returns its chain, the trust bundle, the signing certificates and the endpoints.
func TestEnroll_Connector(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		addr, _ := e.server(t)
		c, creds := e.client(t, addr)
		tok := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetEphemeral(true).SetLabels(map[string]string{"site": "home"}) })
		resp, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, creds),
			Host: &agentv1.HostFacts{Hostname: "NAS.local"}, Version: "0.1.0"})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(resp.Chain[0])
		if err != nil {
			t.Fatal(err)
		}
		id, err := e.ca.IdentityOf(leaf, e.clock)
		if err != nil || id.Kind != pki.KindConnector || id.ID != resp.AgentId || id.Org != e.org {
			t.Fatalf("identity %+v, %v", id, err)
		}
		if !resp.Ephemeral || len(resp.TrustBundle) != 1 || len(resp.SigningCertificates) != 2 ||
			resp.ControllerEndpoints[0] != "https://panel.example.com" {
			t.Errorf("response: %+v", resp)
		}
		root, err := x509.ParseCertificate(resp.TrustBundle[0])
		if err != nil || pki.RootPin(root) != pki.RootPin(e.ca.Root()) {
			t.Errorf("trust bundle: %v", err)
		}
		signer, _ := x509.ParseCertificate(resp.SigningCertificates[0])
		inter, _ := x509.ParseCertificate(resp.SigningCertificates[1])
		if err := pki.VerifySigner(signer, []*x509.Certificate{inter}, root, pki.PurposeConfigSigning, e.clock); err != nil {
			t.Errorf("signing certificate: %v", err)
		}
		con := e.db.Client().Connector.GetX(e.sys, resp.AgentId)
		if con.Name != "nas-local" || !con.Ephemeral || con.Labels["site"] != "home" || con.SpiffeID != id.String() {
			t.Errorf("connector row: %+v", con)
		}
		entries := e.db.Client().AuditEntry.Query().Where(auditentry.Action("connector.enroll")).AllX(e.sys)
		if len(entries) != 1 || entries[0].ActorID != resp.AgentId || entries[0].AuthMethod != "enrollment_token" {
			t.Errorf("audit entries: %+v", entries)
		}
		if _, err := audit.Verify(e.sys, e.db, e.org); err != nil {
			t.Error(err)
		}

		// A second host with the same name gets the next free name.
		tok2 := e.mint(t, nil)
		resp2, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok2, Csr: boundCSR(t, creds),
			Host: &agentv1.HostFacts{Hostname: "nas.local"}})
		if err != nil {
			t.Fatal(err)
		}
		if n := e.db.Client().Connector.GetX(e.sys, resp2.AgentId).Name; n != "nas-local-2" {
			t.Errorf("second connector named %q", n)
		}
	})
}

// TestEnroll_Binding: a CSR without a binding, or bound to another connection, is refused and does
// not consume the token.
func TestEnroll_Binding(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		addr, _ := e.server(t)
		c, creds := e.client(t, addr)
		other, otherCreds := e.client(t, addr)
		_ = other
		tok := e.mint(t, nil)
		unbound := newCSR(t)
		if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: unbound.Raw}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("CSR without a binding: %v", err)
		}
		if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, otherCreds)}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("CSR bound to another connection: %v", err)
		}
		if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: []byte("not a CSR")}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("garbage CSR: %v", err)
		}
		if n := e.uses(t, tok); n != 0 {
			t.Fatalf("refused requests consumed the token: %d uses", n)
		}
		if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, creds)}); err != nil {
			t.Fatalf("a bound CSR afterwards: %v", err)
		}
	})
}

// TestEnroll_GatewayToken: a gateway token enrolls exactly the gateway an Admin created, never a
// connector, and a decommissioned gateway cannot be enrolled.
func TestEnroll_GatewayToken(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		addr, _ := e.server(t)
		c, creds := e.client(t, addr)
		group := e.db.Client().GatewayGroup.Create().SetOrgID(e.org).SetName("eu").SaveX(e.sys)
		gw := e.db.Client().Gateway.Create().SetOrgID(e.org).SetGatewayGroupID(group.ID).SetName("edge").
			SetTunnelEndpoints([]string{"edge.example.com:443"}).SaveX(e.sys)
		tok := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetRole("gateway").SetGatewayID(gw.ID) })
		resp, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, creds),
			Host: &agentv1.HostFacts{Hostname: "pretends-to-be-a-connector"}})
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(resp.Chain[0])
		id, err := e.ca.IdentityOf(leaf, e.clock)
		if err != nil || id.Kind != pki.KindGateway || id.ID != gw.ID || resp.AgentId != gw.ID {
			t.Fatalf("a gateway token enrolled %+v, %v", id, err)
		}
		if n := e.db.Client().Connector.Query().CountX(e.sys); n != 0 {
			t.Errorf("a gateway token created %d connectors", n)
		}
		if g := e.db.Client().Gateway.GetX(e.sys, gw.ID); g.SpiffeID != id.String() || g.PubkeySha256 == "" {
			t.Errorf("gateway row: %+v", g)
		}
		e.db.Client().Gateway.UpdateOne(gw).SetDecommissionedAt(e.clock).ExecX(e.sys)
		tok2 := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetRole("gateway").SetGatewayID(gw.ID) })
		if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok2, Csr: boundCSR(t, creds)}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("a decommissioned gateway: %v", err)
		}
		if n := e.uses(t, tok2); n != 0 {
			t.Errorf("the refused enrollment consumed the token")
		}
	})
}

// TestEnroll_ReEnrollment: a token bound to a connector keeps its identity and replaces its key.
func TestEnroll_ReEnrollment(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		addr, _ := e.server(t)
		c, creds := e.client(t, addr)
		first, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: e.mint(t, nil), Csr: boundCSR(t, creds),
			Host: &agentv1.HostFacts{Hostname: "nas"}})
		if err != nil {
			t.Fatal(err)
		}
		before := e.db.Client().Connector.GetX(e.sys, first.AgentId)
		tok := e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetConnectorID(first.AgentId) })
		again, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, creds),
			Host: &agentv1.HostFacts{Hostname: "something-else"}})
		if err != nil {
			t.Fatal(err)
		}
		after := e.db.Client().Connector.GetX(e.sys, first.AgentId)
		if again.AgentId != first.AgentId || after.PubkeySha256 == before.PubkeySha256 || after.Name != "nas" {
			t.Errorf("re-enrollment: id %s, key changed %v, name %q", again.AgentId, after.PubkeySha256 != before.PubkeySha256, after.Name)
		}
		if n := e.db.Client().Connector.Query().Where(connector.OrgID(e.org)).CountX(e.sys); n != 1 {
			t.Errorf("%d connectors after a re-enrollment", n)
		}
	})
}

// TestEnroll_ReplacedCertificatesRevoked: a token bound to an identity that already holds a
// certificate, a connector's re-enrollment or a gateway enrolling again, revokes the old
// certificates by serial, in the revocation log and the audit log, and applies the deny-list; the
// identity and the new certificate stay valid. A first enrollment revokes nothing.
func TestEnroll_ReplacedCertificatesRevoked(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		addr, svc := e.server(t)
		logPath := filepath.Join(t.TempDir(), "revocations.log")
		rl, err := revlog.Open(logPath, func() time.Time { return e.clock })
		if err != nil {
			t.Fatal(err)
		}
		var denied atomic.Int32
		svc.RevLog, svc.Denied = rl, func() { denied.Add(1) }
		c, creds := e.client(t, addr)
		enrol := func(tok string) (*agentv1.EnrollResponse, string) {
			t.Helper()
			r, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, creds), Host: &agentv1.HostFacts{Hostname: "nas"}})
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(r.GetChain()[0])
			if err != nil {
				t.Fatal(err)
			}
			return r, pki.SerialHex(leaf.SerialNumber)
		}
		revoked := func(serial string) bool { return e.db.Client().IssuedCertificate.GetX(e.sys, serial).RevokedAt != nil }

		first, s1 := enrol(e.mint(t, nil))
		if denied.Load() != 0 {
			t.Fatal("a first enrollment applied the deny-list")
		}
		e.clock = e.clock.Add(time.Minute)
		_, s2 := enrol(e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetConnectorID(first.GetAgentId()) }))
		e.clock = e.clock.Add(time.Minute)
		again, s3 := enrol(e.mint(t, func(c *ent.EnrollmentTokenCreate) { c.SetConnectorID(first.GetAgentId()) }))
		if again.GetAgentId() != first.GetAgentId() || !revoked(s1) || !revoked(s2) || revoked(s3) {
			t.Fatalf("after two re-enrollments: id %s, revoked %v %v %v", again.GetAgentId(), revoked(s1), revoked(s2), revoked(s3))
		}
		if r := e.db.Client().IssuedCertificate.GetX(e.sys, s1).RevocationReason; r != "replaced by a re-enrollment" {
			t.Errorf("the reason: %q", r)
		}
		if n := e.db.Client().RevokedIdentity.Query().CountX(e.sys); n != 0 {
			t.Fatalf("%d identities revoked; a re-enrollment revokes certificates only", n)
		}
		if denied.Load() != 2 {
			t.Fatalf("the deny-list was applied %d times", denied.Load())
		}

		group := e.db.Client().GatewayGroup.Create().SetOrgID(e.org).SetName("eu").SaveX(e.sys)
		gw := e.db.Client().Gateway.Create().SetOrgID(e.org).SetGatewayGroupID(group.ID).SetName("gw1").
			SetTunnelEndpoints([]string{"gw1.example.com:443"}).SaveX(e.sys)
		gwToken := func(c *ent.EnrollmentTokenCreate) {
			c.SetRole("gateway").SetGatewayGroupID(group.ID).SetGatewayID(gw.ID)
		}
		_, g1 := enrol(e.mint(t, gwToken))
		_, g2 := enrol(e.mint(t, gwToken))
		if !revoked(g1) || revoked(g2) || revoked(s3) {
			t.Fatalf("a gateway enrolling again: revoked %v %v, the connector's %v", revoked(g1), revoked(g2), revoked(s3))
		}

		entries, err := revlog.Read(logPath)
		if err != nil || len(entries) != 3 {
			t.Fatalf("the revocation log: %v %v", entries, err)
		}
		for i, want := range []string{s1, s2, g1} {
			if entries[i].Kind != revlog.CertificateRevoked || entries[i].Subject != want || entries[i].NotAfter == nil {
				t.Errorf("entry %d: %+v, want %s", i, entries[i], want)
			}
		}
		if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("certificate.revoke")).CountX(e.sys); n != 3 {
			t.Fatalf("%d audit entries of revocations", n)
		}
	})
}

// TestEnroll_RateLimit: an address gets ten enrollments a minute, then ResourceExhausted, before
// the token is even looked at.
func TestEnroll_RateLimit(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		addr, _ := e.server(t)
		c, creds := e.client(t, addr) // its connection's first call used one
		for i := 2; i <= enroll.RateBurst; i++ {
			if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: "bad", Csr: boundCSR(t, creds)}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("request %d: %v, want the invalid token", i, err)
			}
		}
		tok := e.mint(t, nil)
		if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, creds)}); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("request %d: %v, want ResourceExhausted", enroll.RateBurst+1, err)
		}
		e.clock = e.clock.Add(enroll.RateEvery)
		if _, err := c.Enroll(callCtx(t), &agentv1.EnrollRequest{Token: tok, Csr: boundCSR(t, creds)}); err != nil {
			t.Fatalf("after one interval: %v", err)
		}
	})
}

func TestTrustBundleHandler(t *testing.T) {
	setup(t, func(t *testing.T, e *env) {
		srv := httptest.NewServer(enroll.TrustBundleHandler(e.ca.Root()))
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/pem-certificate-chain" ||
			!strings.HasPrefix(string(body), "-----BEGIN CERTIFICATE-----") {
			t.Fatalf("trust bundle: %d %q", resp.StatusCode, body)
		}
		resp, err = http.Post(srv.URL, "text/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST: %d", resp.StatusCode)
		}
	})
}
