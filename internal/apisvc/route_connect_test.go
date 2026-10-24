// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// connectTCP is a tcp route in http_connect mode on port, 0 for any listener of the mode.
func connectTCP(name, group string, port uint32, mode rpmgrv1.ConnectAuthMode, authorities ...string) *rpmgrv1.Route {
	return &rpmgrv1.Route{Name: name, GatewayGroupId: group, Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{Port: port,
		ListenerMode: rpmgrv1.ListenerMode_LISTENER_MODE_HTTP_CONNECT, Connect: &rpmgrv1.ConnectSpec{AuthMode: mode, Authorities: authorities}}}}
}

// TestConnectRoutes (docs/03-connections.md, "HTTP CONNECT routes", D130): tcp routes in
// http_connect mode share a CONNECT listener of their org and mode, counted once against the
// quota; a named port with another mode is CONNECT_MODE_MISMATCH and one of a plain route taken;
// authorities are unique on a listener; plain_basic answers with a warning; the listener mode
// cannot change; an auth mode change moves a route to a listener of the new mode; the last route
// closes its listener; another org reaches neither the group nor its ports.
func TestConnectRoutes(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.SetPortQuota(ctx, connect.NewRequest(&rpmgrv1.SetPortQuotaRequest{OrgId: org, GatewayGroupId: group, Protocol: tcp,
		MaxPorts: 2})); err != nil {
		t.Fatal(err)
	}
	none, plainBasic := rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_PLAIN_BASIC
	ssh, err := createRoute(ada, org, connectTCP("ssh", group, 20001, none, "SSH.internal.", "bastion"), "")
	if err != nil || ssh.GetTcp().GetPort() != 20001 || !slices.Equal(ssh.GetTcp().GetConnect().GetAuthorities(), []string{"bastion", "ssh.internal"}) ||
		ssh.GetTcp().GetListenerMode() != rpmgrv1.ListenerMode_LISTENER_MODE_HTTP_CONNECT {
		t.Fatalf("a CONNECT route on a named port: %v %v", ssh, err)
	}
	db, err := createRoute(ada, org, connectTCP("db", group, 0, none, "db.internal"), "")
	if err != nil || db.GetTcp().GetPort() != 20001 {
		t.Fatalf("a CONNECT route joins the org's listener of its mode: %v %v", db, err)
	}
	if _, err := createRoute(ada, org, connectTCP("db2", group, 20001, none, "DB.internal"), ""); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("an authority twice on a listener: %v", err)
	}
	r, err := ada.rt.CreateRoute(ctx, connect.NewRequest(&rpmgrv1.CreateRouteRequest{OrgId: org, Route: connectTCP("legacy", group, 0, plainBasic, "old.internal")}))
	if err != nil || r.Msg.GetRoute().GetTcp().GetPort() == 20001 || len(r.Msg.GetWarnings()) != 1 ||
		!strings.Contains(r.Msg.GetWarnings()[0], "in the clear") {
		t.Fatalf("a plain_basic route: another listener and a warning: %v %v", r, err)
	}
	legacy := r.Msg.GetRoute()
	// The two listeners take the quota of 2: a third listener is refused, a third route on one is not.
	if _, err := createRoute(ada, org, tcpRoute("plain", group, 0), ""); reason(err) != apisvc.ReasonQuotaReached {
		t.Fatalf("a port beyond the quota: %v", err)
	}
	if _, err := createRoute(ada, org, connectTCP("web", group, 0, none, "web.internal"), ""); err != nil {
		t.Fatalf("a route on a listener costs no port: %v", err)
	}
	for name, c := range map[string]struct {
		rt     *rpmgrv1.Route
		code   connect.Code
		reason string
	}{
		"another mode on a listener's port": {connectTCP("x1", group, 20001, plainBasic, "x.internal"), connect.CodeFailedPrecondition, apisvc.ReasonConnectModeMismatch},
		"no authorities":                    {connectTCP("x2", group, 0, none), connect.CodeInvalidArgument, ""},
		"an authority with a port":          {connectTCP("x3", group, 0, none, "x.internal:22"), connect.CodeInvalidArgument, ""},
		"a CONNECT spec on a plain route": {func() *rpmgrv1.Route {
			r := tcpRoute("x4", group, 0)
			r.GetTcp().Connect = &rpmgrv1.ConnectSpec{Authorities: []string{"x.internal"}}
			return r
		}(), connect.CodeInvalidArgument, ""},
		"http_connect without a spec": {func() *rpmgrv1.Route {
			r := tcpRoute("x5", group, 0)
			r.GetTcp().ListenerMode = rpmgrv1.ListenerMode_LISTENER_MODE_HTTP_CONNECT
			return r
		}(), connect.CodeInvalidArgument, ""},
		"tls_basic without a certificate": {func() *rpmgrv1.Route {
			r := connectTCP("x6", group, 0, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC, "x.internal")
			r.GetTcp().GetConnect().Hostname = "proxy.example.com"
			return r
		}(), connect.CodeInvalidArgument, ""},
		"a hostname without TLS": {func() *rpmgrv1.Route {
			r := connectTCP("x7", group, 0, none, "x.internal")
			r.GetTcp().GetConnect().Hostname = "proxy.example.com"
			return r
		}(), connect.CodeInvalidArgument, ""},
	} {
		if _, err := createRoute(ada, org, c.rt, ""); code(err) != c.code || c.reason != "" && reason(err) != c.reason {
			t.Errorf("%s: %v, want %v %s", name, err, c.code, c.reason)
		}
	}
	update := func(rt *rpmgrv1.Route, paths ...string) (*rpmgrv1.UpdateRouteResponse, error) {
		res, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: rt, Etag: rt.GetEtag(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}
	// The listener mode cannot change.
	plain := proto.Clone(db).(*rpmgrv1.Route)
	plain.GetTcp().ListenerMode, plain.GetTcp().Connect = rpmgrv1.ListenerMode_LISTENER_MODE_PLAIN, nil
	if _, err := update(plain, "tcp.listener_mode", "tcp.connect"); reason(err) != apisvc.ReasonListenerModeChange {
		t.Fatalf("a listener mode change: %v", err)
	}
	// The auth mode moves db to the plain_basic listener, with the warning; the authorities change.
	moved := proto.Clone(db).(*rpmgrv1.Route)
	moved.GetTcp().GetConnect().AuthMode, moved.GetTcp().GetConnect().Authorities = plainBasic, []string{"db.internal", "pg.internal"}
	got, err := update(moved, "tcp.connect")
	if err != nil || got.GetRoute().GetTcp().GetPort() != legacy.GetTcp().GetPort() || len(got.GetWarnings()) != 1 ||
		len(got.GetRoute().GetTcp().GetConnect().GetAuthorities()) != 2 {
		t.Fatalf("a mode change moves the route: %v %v", got, err)
	}
	// Deleting the last routes of a listener closes it and frees its port for a plain route.
	del := func(rt *rpmgrv1.Route) {
		t.Helper()
		cur, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: rt.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: rt.GetId(), Etag: cur.Msg.GetRoute().GetEtag()})); err != nil {
			t.Fatal(err)
		}
	}
	del(legacy)
	del(got.GetRoute())
	if p, err := createRoute(ada, org, tcpRoute("plain", group, legacy.GetTcp().GetPort()), ""); err != nil || p.GetTcp().GetPort() != legacy.GetTcp().GetPort() {
		t.Fatalf("the closed listener's port: %v %v", p, err)
	}
	if n := e.db.Client().ConnectListener.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d listeners left, want 1", n)
	}
	// A plain route's port is no listener.
	if _, err := createRoute(ada, org, connectTCP("onplain", group, legacy.GetTcp().GetPort(), none, "p.internal"), ""); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a CONNECT route on a plain route's port: %v", err)
	}
	// Another org reaches neither the group nor its listeners.
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := createRoute(bob, orgB, connectTCP("steal", group, 20001, none, "steal.internal"), ""); code(err) != connect.CodeNotFound {
		t.Fatalf("another org on the listener's port: %v", err)
	}
	// The compiled snapshot of the group's gateway names the listener's org and its routes.
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range []*rpmgrv1.Route{ssh} {
		if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: rt.GetId(),
			Target: addressTarget(e.addConnector(t, org, "nas", nil).ID, "10.0.0.5", 22)})); err != nil {
			t.Fatal(err)
		}
	}
	snap := compileFor(t, e, org, gw.GetId(), gateway.Capabilities)
	var hc *agentv1.HTTPConnect
	for _, r := range snap.GetResources() {
		if r.GetId() == ssh.GetId() {
			hc = r.GetGatewayTcpRoute().GetHttpConnect()
		}
	}
	if hc == nil || hc.GetOrgId() != org || hc.GetAuth() != agentv1.ConnectAuth_CONNECT_AUTH_NONE || !slices.Equal(hc.GetAuthorities(), []string{"bastion", "ssh.internal"}) {
		t.Fatalf("the compiled CONNECT route: %v", hc)
	}
	a, _ := gateway.NewApplier()
	if errs := a.Validate(snap); len(errs) != 0 {
		t.Fatalf("the gateway refuses the compiled routes: %v", errs)
	}
	// A gateway without tcp.http-connect gets no CONNECT route (D113).
	for _, r := range compileFor(t, e, org, gw.GetId(), []string{"tunnel.quic", "tunnel.h2"}).GetResources() {
		if r.GetGatewayTcpRoute().GetHttpConnect() != nil {
			t.Fatalf("an old gateway got the CONNECT route %s", r.GetId())
		}
	}
}

// compileFor compiles the snapshot of gateway gw of org with the capabilities caps.
func compileFor(t *testing.T, e *env, org, gw string, caps []string) *agentv1.Snapshot {
	t.Helper()
	snap := &agentv1.Snapshot{}
	if err := store.ReadTx(e.sys, e.db, func(tx *ent.Tx, _ store.Revision) error {
		a := snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: org, Kind: pki.KindGateway, ID: gw}, Capabilities: caps}
		for _, src := range routes.Sources() {
			rs, err := src(e.sys, tx, a)
			if err != nil {
				return err
			}
			snap.Resources = append(snap.Resources, rs...)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snap
}

// TestConnectRoutes_TLSAndBasicAuth: a tls_basic route names a hostname under a verified domain
// and an uploaded certificate that covers it, which the group's gateways get for the hostname;
// basic-auth policies apply only on a listener of a basic mode, and a route of mode none cannot
// take one, nor move to mode none while it has one.
func TestConnectRoutes_TLSAndBasicAuth(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	ca, caKey := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil, e.clock.Add(-time.Hour), e.clock.Add(365*24*time.Hour))
	leaf, key := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "proxy.example.com"}, DNSNames: []string{"proxy.example.com"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}, ca, caKey,
		e.clock.Add(-time.Hour), e.clock.Add(90*24*time.Hour))
	keyText, _ := keyPEMOf(t, key)
	up, err := ada.crt.UploadCertificate(ctx, connect.NewRequest(&rpmgrv1.UploadCertificateRequest{OrgId: org, ChainPem: certPEM(leaf, ca), PrivateKeyPem: keyText}))
	if err != nil {
		t.Fatal(err)
	}
	certID := up.Msg.GetCertificate().GetId()
	tlsRoute := func(name, hostname, cert string) *rpmgrv1.Route {
		r := connectTCP(name, group, 0, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC, name+".internal")
		r.GetTcp().GetConnect().Hostname, r.GetTcp().GetConnect().CertificateId = hostname, cert
		return r
	}
	if _, err := createRoute(ada, org, tlsRoute("other", "proxy.example.org", certID), ""); reason(err) != apisvc.ReasonDomainNotVerified {
		t.Fatalf("a hostname outside the verified domains: %v", err)
	}
	if _, err := createRoute(ada, org, tlsRoute("notcovered", "vpn.example.com", certID), ""); reason(err) != apisvc.ReasonCertificateNotCovering {
		t.Fatalf("a certificate that does not cover the hostname: %v", err)
	}
	policy, err := ada.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
		AccessPolicy: &rpmgrv1.AccessPolicy{Name: "proxy-users", Rules: []*rpmgrv1.AccessRule{basicAuth(user("ada", "correct horse battery"))}}}))
	if err != nil {
		t.Fatal(err)
	}
	pid := policy.Msg.GetAccessPolicy().GetId()
	vpn := tlsRoute("vpn", "proxy.example.com", certID)
	vpn.PolicyIds = []string{pid}
	vpn, err = createRoute(ada, org, vpn, "")
	if err != nil || vpn.GetTcp().GetConnect().GetCertificateId() != certID {
		t.Fatalf("a tls_basic route with a basic-auth policy: %v %v", vpn, err)
	}
	none := connectTCP("open", group, 0, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE, "open.internal")
	none.PolicyIds = []string{pid}
	if _, err := createRoute(ada, org, none, ""); reason(err) != apisvc.ReasonBasicAuthNotHTTP {
		t.Fatalf("basic auth on a route of mode none: %v", err)
	}
	toNone := proto.Clone(vpn).(*rpmgrv1.Route)
	toNone.GetTcp().Connect = &rpmgrv1.ConnectSpec{AuthMode: rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE, Authorities: []string{"vpn.internal"}}
	if _, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: toNone, Etag: vpn.GetEtag(),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tcp.connect"}}})); reason(err) != apisvc.ReasonBasicAuthNotHTTP {
		t.Fatalf("a move to mode none with a basic-auth policy: %v", err)
	}
	// A policy's basic-auth rule fits a CONNECT route of a basic mode, not one of mode none.
	ips, err := ada.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
		AccessPolicy: &rpmgrv1.AccessPolicy{Name: "office", Rules: []*rpmgrv1.AccessRule{ipAllow("10.0.0.0/8")}}}))
	if err != nil {
		t.Fatal(err)
	}
	none.PolicyIds = []string{ips.Msg.GetAccessPolicy().GetId()}
	if _, err := createRoute(ada, org, none, ""); err != nil {
		t.Fatal(err)
	}
	withUsers := proto.Clone(ips.Msg.GetAccessPolicy()).(*rpmgrv1.AccessPolicy)
	withUsers.Rules = append(withUsers.Rules, basicAuth(user("bob", "correct horse battery")))
	if _, err := ada.pol.UpdateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.UpdateAccessPolicyRequest{AccessPolicy: withUsers,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}}, Etag: withUsers.GetEtag()})); reason(err) != apisvc.ReasonBasicAuthNotHTTP {
		t.Fatalf("a basic-auth rule on a policy of a route of mode none: %v", err)
	}
	more := proto.Clone(policy.Msg.GetAccessPolicy()).(*rpmgrv1.AccessPolicy)
	more.Rules = []*rpmgrv1.AccessRule{basicAuth(user("ada", "correct horse battery"), user("eve", "another long password"))}
	if _, err := ada.pol.UpdateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.UpdateAccessPolicyRequest{AccessPolicy: more,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}}, Etag: more.GetEtag()})); err != nil {
		t.Fatalf("a basic-auth rule on a policy of a tls_basic route: %v", err)
	}
	// The certificate is in use, and the group's gateways get it for the listener's hostname.
	if crt, err := ada.crt.GetCertificate(ctx, connect.NewRequest(&rpmgrv1.GetCertificateRequest{CertificateId: certID})); err != nil ||
		!slices.Contains(crt.Msg.GetCertificate().GetRouteIds(), vpn.GetId()) {
		t.Fatalf("the certificate's routes: %v %v", crt, err)
	}
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := store.ReadTx(e.sys, e.db, func(tx *ent.Tx, _ store.Revision) error {
		rs, err := certs.Gateway(e.sys, tx, snapshot.Agent{Identity: pki.Identity{Org: org, Kind: pki.KindGateway, ID: gw.GetId()}})
		for _, r := range rs {
			names = append(names, r.GetGatewayCertificate().GetHostnames()...)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "proxy.example.com") {
		t.Fatalf("the gateway's certificates name %v, want the listener's hostname", names)
	}
}
