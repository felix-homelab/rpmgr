// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// fakeProber answers RouteService's probes with der, or err, or not before the request's
// deadline; it records the last probe and its connector.
type fakeProber struct {
	mu        sync.Mutex
	der       []byte
	err       error
	block     bool
	last      *agentv1.ProbeTarget
	connector string
}

func (f *fakeProber) ProbeTarget(ctx context.Context, connectorID string, p *agentv1.ProbeTarget) ([]byte, error) {
	f.mu.Lock()
	f.last, f.connector = p, connectorID
	der, err, block := f.der, f.err, f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return der, err
}

func (f *fakeProber) answer(der []byte, err error, block bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.der, f.err, f.block = der, err, block
}

// selfSigned returns a self-signed certificate for name and ip, DER, and its key pin.
func selfSigned(t *testing.T, name string, ip net.IP) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		IPAddresses: []net.IP{ip}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return der, hex.EncodeToString(pin[:])
}

// TestProbeTargetCertificate: a connector of the org reads the certificate a target presents,
// which comes back with its key pin, names, issuer and validity. A host name is sent as the server
// name unless another one is given; an IP address is not. A connector without a session here, of
// an older version, one whose probe fails or does not answer in time, a decommissioned one, another
// org's, and a certificate that does not parse are refused, and a Viewer may not probe.
func TestProbeTargetCertificate(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	con := e.addConnector(t, org, "nas", nil).ID
	gone := e.addConnector(t, org, "old", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(e.clock) }).ID
	theirs := e.addConnector(t, storetest.Org(t, e.db, "org-b"), "theirs", nil).ID
	der, pin := selfSigned(t, "pve.local", net.ParseIP("10.0.0.5"))
	probe := func(b *browser, req *rpmgrv1.ProbeTargetCertificateRequest) (*rpmgrv1.TargetCertificate, error) {
		r, err := b.rt.ProbeTargetCertificate(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetCertificate(), nil
	}
	at := func(connector, host string, port uint32, serverName string) *rpmgrv1.ProbeTargetCertificateRequest {
		return &rpmgrv1.ProbeTargetCertificateRequest{ConnectorId: connector, ServerName: serverName,
			Address: &rpmgrv1.ProbeTargetCertificateRequest_HostPort{HostPort: &rpmgrv1.HostPort{Host: host, Port: port}}}
	}
	last := func() (*agentv1.ProbeTarget, string) {
		e.probe.mu.Lock()
		defer e.probe.mu.Unlock()
		return e.probe.last, e.probe.connector
	}

	e.probe.answer(der, nil, false)
	c, err := probe(ada, at(con, "pve.local", 8006, ""))
	if err != nil || c.GetSpkiSha256() != pin || !slices.Equal(c.GetDnsNames(), []string{"pve.local"}) ||
		!slices.Equal(c.GetIpAddresses(), []string{"10.0.0.5"}) || !c.GetSelfSigned() || c.GetSubject() != "CN=pve.local" ||
		c.GetIssuer() != "CN=pve.local" || len(c.GetSha256()) != 64 || !c.GetNotAfter().AsTime().After(time.Now()) {
		t.Fatalf("a self-signed certificate: %v %v", c, err)
	}
	if p, id := last(); id != con || p.GetHostPort() != "pve.local:8006" || p.GetServerName() != "pve.local" {
		t.Fatalf("the probe sent: %v to %s", p, id)
	}
	for _, tc := range []struct {
		req       *rpmgrv1.ProbeTargetCertificateRequest
		address   string
		sni, unix string
	}{
		{at(con, "10.0.0.5", 443, ""), "10.0.0.5:443", "", ""},
		{at(con, "10.0.0.5", 443, "nas.internal"), "10.0.0.5:443", "nas.internal", ""},
		{&rpmgrv1.ProbeTargetCertificateRequest{ConnectorId: con, ServerName: "app.internal",
			Address: &rpmgrv1.ProbeTargetCertificateRequest_UnixPath{UnixPath: "/run/app.sock"}}, "", "app.internal", "/run/app.sock"},
	} {
		if _, err := probe(ada, tc.req); err != nil {
			t.Fatal(err)
		}
		if p, _ := last(); p.GetHostPort() != tc.address || p.GetServerName() != tc.sni || p.GetUnixPath() != tc.unix {
			t.Errorf("%v: sent %v", tc.req, p)
		}
	}

	apisvc.SetProbeWait(t, 100*time.Millisecond)
	for name, c := range map[string]struct {
		der   []byte
		err   error
		block bool
		req   *rpmgrv1.ProbeTargetCertificateRequest
		code  connect.Code
		text  string
	}{
		"no session":        {err: apisvc.ErrProbeNotConnected, code: connect.CodeFailedPrecondition, text: "no control session"},
		"an older version":  {err: apisvc.ErrProbeUnsupported, code: connect.CodeFailedPrecondition, text: "upgrade it"},
		"a failed probe":    {err: &apisvc.ProbeFailed{Message: "the connector's local policy does not allow 10.0.0.5:8006"}, code: connect.CodeFailedPrecondition, text: "local policy does not allow"},
		"no answer in time": {block: true, code: connect.CodeDeadlineExceeded, text: "did not answer"},
		"another error":     {err: errors.New("boom"), code: connect.CodeInternal},
		"no certificate":    {der: []byte("not DER"), code: connect.CodeFailedPrecondition, text: "does not parse"},
		"decommissioned":    {der: der, req: at(gone, "pve.local", 8006, ""), code: connect.CodeFailedPrecondition, text: "decommissioned"},
		"another org's":     {der: der, req: at(theirs, "pve.local", 8006, ""), code: connect.CodeNotFound},
		"no address":        {der: der, req: &rpmgrv1.ProbeTargetCertificateRequest{ConnectorId: con}, code: connect.CodeInvalidArgument},
		"a relative socket": {der: der, req: &rpmgrv1.ProbeTargetCertificateRequest{ConnectorId: con,
			Address: &rpmgrv1.ProbeTargetCertificateRequest_UnixPath{UnixPath: "run/app.sock"}}, code: connect.CodeInvalidArgument},
	} {
		e.probe.answer(c.der, c.err, c.block)
		req := c.req
		if req == nil {
			req = at(con, "pve.local", 8006, "")
		}
		_, err := probe(ada, req)
		if code(err) != c.code || c.text != "" && !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: %v, want %v %q", name, err, c.code, c.text)
		}
	}

	e.probe.answer(der, nil, false)
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := probe(vwr, at(con, "pve.local", 8006, "")); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer probes: %v", err)
	}
}
