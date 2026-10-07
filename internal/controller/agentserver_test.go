// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

const td = "rpmgr-7f3k2q6m"

// testCA issues the certificates of one installation.
type testCA struct {
	is    *pki.Issuer
	roots *x509.CertPool
	now   time.Time
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	now := time.Now()
	root, err := pki.NewRoot(td, now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.NewIntermediate(root, now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := &testCA{roots: x509.NewCertPool(), now: now}
	c.roots.AddCert(root.Cert)
	if c.is, err = pki.NewIssuer(root.Cert, inter, func() time.Time { return c.now }); err != nil {
		t.Fatal(err)
	}
	return c
}

// cert issues a certificate for id that was issued at issued.
func (c *testCA) cert(t *testing.T, id pki.Identity, lifetime time.Duration, issued time.Time) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	saved := c.now
	c.now = issued
	leaf, err := c.is.IssueLeaf(csr, id, lifetime)
	c.now = saved
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, c.is.Intermediate().Raw}, PrivateKey: key, Leaf: leaf}
}

// fakeAgentServices answer every method with the caller's identity.
type fakeAgentServices struct {
	agentv1.UnimplementedEnrollmentServer
	agentv1.UnimplementedControlServer
	agentv1.UnimplementedReauthServer
	calls atomic.Int32
}

func caller(ctx context.Context) []byte {
	if a, ok := controller.AgentFrom(ctx); ok {
		return []byte(a.Identity.String())
	}
	return []byte("anonymous")
}

func (f *fakeAgentServices) Enroll(ctx context.Context, _ *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	f.calls.Add(1)
	return &agentv1.EnrollResponse{AgentId: string(caller(ctx))}, nil
}

func (f *fakeAgentServices) Renew(ctx context.Context, _ *agentv1.RenewRequest) (*agentv1.RenewResponse, error) {
	f.calls.Add(1)
	return &agentv1.RenewResponse{Chain: [][]byte{caller(ctx)}}, nil
}

func (f *fakeAgentServices) Reauth(ctx context.Context, _ *agentv1.ReauthRequest) (*agentv1.ReauthResponse, error) {
	f.calls.Add(1)
	return &agentv1.ReauthResponse{Chain: [][]byte{caller(ctx)}}, nil
}

func (f *fakeAgentServices) Session(st grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ControllerMessage]) error {
	f.calls.Add(1)
	if _, err := st.Recv(); err != nil {
		return err
	}
	return st.Send(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Welcome{
		Welcome: &agentv1.Welcome{MinAgentVersion: string(caller(st.Context()))}}})
}

// controllerEnv is a controller's port 443 with the agent server and a web server behind it.
type controllerEnv struct {
	ca       *testCA
	addr     string
	services *fakeAgentServices
	webHits  atomic.Int32
	uiRoots  *x509.CertPool
}

func startController(t *testing.T) *controllerEnv {
	t.Helper()
	e := &controllerEnv{ca: newTestCA(t), services: &fakeAgentServices{}}
	node := e.ca.cert(t, pki.Identity{TrustDomain: td, Kind: pki.KindController, ID: ids.New("ctn")}, pki.ControllerLifetime, e.ca.now)
	cfg := pki.AgentEndpointConfig(node, e.ca.roots,
		pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway}}, nil,
		pki.Reauth{Grace: func() time.Duration { return 30 * 24 * time.Hour }, Check: func(*x509.Certificate) error { return nil }})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	split := controller.NewSplitter(td, ln.Addr())
	agents := controller.NewAgentServer(cfg, td)
	agentv1.RegisterEnrollmentServer(agents, e.services)
	agentv1.RegisterControlServer(agents, e.services)
	agentv1.RegisterReauthServer(agents, e.services)
	web := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.webHits.Add(1)
		_, _ = io.WriteString(w, "web")
	})}
	uiCert, uiRoots := uiCertificate(t)
	e.uiRoots = uiRoots
	go func() { _ = agents.Serve(split.Agents()) }()
	go func() {
		_ = web.Serve(tls.NewListener(split.Web(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{uiCert}}))
	}()
	go func() { _ = split.Serve(ln) }()
	t.Cleanup(func() { agents.Stop(); _ = web.Close(); _ = ln.Close() })
	return e
}

// dial connects a grpc-go client at sni with own, or without a certificate if own is nil.
func (e *controllerEnv) dial(t *testing.T, sni string, own *tls.Certificate) *grpc.ClientConn {
	t.Helper()
	cfg := pki.ClientConfig(tls.Certificate{}, e.ca.roots, sni, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, nil, nil)
	cfg.Certificates = nil
	if own != nil {
		cfg.Certificates = []tls.Certificate{*own}
	}
	cc, err := grpc.NewClient("passthrough:///"+e.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func code(err error) codes.Code { return status.Code(err) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// TestAgentServer_Access: Enroll is the one method without a certificate; Reauth is reachable only
// at reauth.controller.<td>, and every Control method only at controller.<td>.
func TestAgentServer_Access(t *testing.T) {
	e := startController(t)
	org := ids.New("org")
	conID := pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindConnector, ID: ids.New("con")}
	con := e.ca.cert(t, conID, pki.DefaultLeafLifetime, e.ca.now)
	expired := e.ca.cert(t, conID, pki.MinLeafLifetime, e.ca.now.Add(-2*24*time.Hour))

	anon := e.dial(t, "controller."+td, nil)
	if r, err := agentv1.NewEnrollmentClient(anon).Enroll(ctx(t), &agentv1.EnrollRequest{}); err != nil || r.AgentId != "anonymous" {
		t.Fatalf("Enroll without a certificate: %v, %v", r, err)
	}
	if _, err := agentv1.NewControlClient(anon).Renew(ctx(t), &agentv1.RenewRequest{}); code(err) != codes.Unauthenticated {
		t.Errorf("Renew without a certificate: %v", err)
	}
	st, err := agentv1.NewControlClient(anon).Session(ctx(t))
	if err == nil {
		_, err = st.Recv()
	}
	if code(err) != codes.Unauthenticated {
		t.Errorf("Session without a certificate: %v", err)
	}

	authed := e.dial(t, "controller."+td, &con)
	r, err := agentv1.NewControlClient(authed).Renew(ctx(t), &agentv1.RenewRequest{})
	if err != nil || string(r.Chain[0]) != conID.String() {
		t.Fatalf("Renew with a certificate: %v, %v", r, err)
	}
	st, err = agentv1.NewControlClient(authed).Session(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{}}}); err != nil {
		t.Fatal(err)
	}
	if m, err := st.Recv(); err != nil || m.GetWelcome().GetMinAgentVersion() != conID.String() {
		t.Fatalf("Session with a certificate: %v, %v", m, err)
	}
	if _, err := agentv1.NewReauthClient(authed).Reauth(ctx(t), &agentv1.ReauthRequest{}); code(err) != codes.PermissionDenied {
		t.Errorf("Reauth at controller.<td>: %v", err)
	}

	reauth := e.dial(t, "reauth.controller."+td, &expired)
	if r, err := agentv1.NewReauthClient(reauth).Reauth(ctx(t), &agentv1.ReauthRequest{}); err != nil || string(r.Chain[0]) != conID.String() {
		t.Fatalf("Reauth with an expired certificate: %v, %v", r, err)
	}
	if _, err := agentv1.NewControlClient(reauth).Renew(ctx(t), &agentv1.RenewRequest{}); code(err) != codes.PermissionDenied {
		t.Errorf("Renew at reauth.controller.<td> with an expired certificate: %v", err)
	}
	if _, err := agentv1.NewEnrollmentClient(reauth).Enroll(ctx(t), &agentv1.EnrollRequest{}); code(err) != codes.PermissionDenied {
		t.Errorf("Enroll at reauth.controller.<td>: %v", err)
	}
	if _, err := agentv1.NewControlClient(e.dial(t, "controller."+td, &expired)).Renew(ctx(t), &agentv1.RenewRequest{}); code(err) != codes.Unavailable {
		t.Errorf("an expired certificate at controller.<td>: %v, want a failed handshake", err)
	}
	node := e.ca.cert(t, pki.Identity{TrustDomain: td, Kind: pki.KindController, ID: ids.New("ctn")}, pki.ControllerLifetime, e.ca.now)
	if _, err := agentv1.NewControlClient(e.dial(t, "controller."+td, &node)).Renew(ctx(t), &agentv1.RenewRequest{}); code(err) != codes.Unavailable {
		t.Errorf("a controller node's certificate as an agent: %v, want a failed handshake", err)
	}
}

// TestAgentServer_EveryMethodHasARule: every method of the agent protocol's services is in the
// access table, and a call of a method outside it is refused.
func TestAgentServer_EveryMethodHasARule(t *testing.T) {
	for _, sd := range []grpc.ServiceDesc{agentv1.Control_ServiceDesc, agentv1.Enrollment_ServiceDesc, agentv1.Reauth_ServiceDesc} {
		for _, m := range sd.Methods {
			if !controller.HasAccessRule("/" + sd.ServiceName + "/" + m.MethodName) {
				t.Errorf("%s/%s has no access rule", sd.ServiceName, m.MethodName)
			}
		}
		for _, s := range sd.Streams {
			if !controller.HasAccessRule("/" + sd.ServiceName + "/" + s.StreamName) {
				t.Errorf("%s/%s has no access rule", sd.ServiceName, s.StreamName)
			}
		}
	}
	e := startController(t)
	err := e.dial(t, "controller."+td, nil).Invoke(ctx(t), "/rpmgr.agent.v1.Control/Shell", &agentv1.LeaveRequest{}, &agentv1.LeaveResponse{})
	if c := code(err); c != codes.Unimplemented && c != codes.PermissionDenied {
		t.Errorf("an unknown method: %v", err)
	}
}

// TestAgentServer_MessageLimit: a request above 4 MiB is refused before the handler runs.
func TestAgentServer_MessageLimit(t *testing.T) {
	e := startController(t)
	before := e.services.calls.Load()
	big := &agentv1.EnrollRequest{Csr: make([]byte, agentproto.MaxControlMessage)}
	_, err := agentv1.NewEnrollmentClient(e.dial(t, "controller."+td, nil)).Enroll(ctx(t), big, grpc.MaxCallSendMsgSize(8<<20))
	if code(err) != codes.ResourceExhausted || e.services.calls.Load() != before {
		t.Fatalf("a 4 MiB request: %v", err)
	}
}

// TestSplitter_Routes: the agent names reach grpc-go, every other name and no name the web server,
// and a connection that is not TLS is closed.
func TestSplitter_Routes(t *testing.T) {
	e := startController(t)
	get := func(serverName string) (string, error) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", e.addr,
			&tls.Config{ServerName: serverName, RootCAs: e.uiRoots, MinVersion: tls.VersionTLS13})
		if err != nil {
			return "", err
		}
		defer func() { _ = c.Close() }()
		if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
			return "", err
		}
		b, err := io.ReadAll(c)
		return string(b), err
	}
	// An IP address as ServerName makes crypto/tls send no SNI at all.
	for _, name := range []string{"panel.example.com", "unknown.example.org", "127.0.0.1"} {
		before := e.services.calls.Load()
		body, err := get(name)
		if err != nil || !strings.HasSuffix(body, "web") || e.services.calls.Load() != before {
			t.Errorf("server name %q: %q, %v; want the web server", name, body, err)
		}
	}
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("plain HTTP: read %d bytes, %v; want the connection closed", n, err)
	}
	if e.webHits.Load() != 3 {
		t.Errorf("%d requests reached the web server, want 3", e.webHits.Load())
	}
}

// uiCertificate is a self-signed certificate for the web server's names, as an operator or ACME
// would provide.
func uiCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"panel.example.com", "unknown.example.org"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}
