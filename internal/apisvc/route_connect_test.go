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
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
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
	if err != nil || r.Msg.GetRoute().GetTcp().GetPort() == 20001 || len(r.Msg.GetWarnings()) != 2 ||
		!strings.Contains(r.Msg.GetWarnings()[0], "in the clear") || !strings.Contains(r.Msg.GetWarnings()[1], "407") {
		t.Fatalf("a plain_basic route without basic-auth rule: another listener and two warnings: %v %v", r, err)
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
	if err != nil || got.GetRoute().GetTcp().GetPort() != legacy.GetTcp().GetPort() || len(got.GetWarnings()) != 2 ||
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
	res, err := ada.rt.CreateRoute(ctx, connect.NewRequest(&rpmgrv1.CreateRouteRequest{OrgId: org, Route: vpn}))
	if err != nil || res.Msg.GetRoute().GetTcp().GetConnect().GetCertificateId() != certID || len(res.Msg.GetWarnings()) != 0 {
		t.Fatalf("a tls_basic route with a basic-auth policy, without warnings: %v %v", res, err)
	}
	vpn = res.Msg.GetRoute()
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
		rs, err := certs.Gateway(e.sys, tx, snapshot.Agent{Identity: pki.Identity{Org: org, Kind: pki.KindGateway, ID: gw.GetId()},
			Capabilities: gateway.Capabilities})
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

// TestConnectRoutes_Updates (D130): a route's certificate becomes its listener's for every route on
// it and is replaced without moving the port, and only gateways with tcp.http-connect get it; a
// named TLS port with another hostname is CONNECT_MODE_MISMATCH; a taken authority refuses an
// update, which changes nothing; an update that leaves the auth mode unset on a route of a basic
// mode is refused; another org's certificate is not found; routes of a basic mode without a
// basic-auth rule are warned about, in previews too; the domain of a listener's hostname is not
// removed while the listener is open; a mode change frees its old listener's quota.
func TestConnectRoutes_Updates(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	domainID := e.verified(t, org, "example.com", true)
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.SetPortQuota(ctx, connect.NewRequest(&rpmgrv1.SetPortQuotaRequest{OrgId: org, GatewayGroupId: group, Protocol: tcp,
		MaxPorts: 2})); err != nil {
		t.Fatal(err)
	}
	ca, caKey := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil, e.clock.Add(-time.Hour), e.clock.Add(365*24*time.Hour))
	upload := func(b *browser, org string, names ...string) string {
		t.Helper()
		leaf, key := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}, ca, caKey,
			e.clock.Add(-time.Hour), e.clock.Add(90*24*time.Hour))
		keyText, _ := keyPEMOf(t, key)
		up, err := b.crt.UploadCertificate(ctx, connect.NewRequest(&rpmgrv1.UploadCertificateRequest{OrgId: org, ChainPem: certPEM(leaf, ca),
			PrivateKeyPem: keyText}))
		if err != nil {
			t.Fatal(err)
		}
		return up.Msg.GetCertificate().GetId()
	}
	first, second := upload(ada, org, "proxy.example.com"), upload(ada, org, "*.example.com")
	policy, err := ada.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
		AccessPolicy: &rpmgrv1.AccessPolicy{Name: "proxy-users", Rules: []*rpmgrv1.AccessRule{basicAuth(user("ada", "correct horse battery"))}}}))
	if err != nil {
		t.Fatal(err)
	}
	tlsRoute := func(name, hostname, cert string) *rpmgrv1.Route {
		r := connectTCP(name, group, 0, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC, name+".internal")
		r.GetTcp().GetConnect().Hostname, r.GetTcp().GetConnect().CertificateId = hostname, cert
		r.PolicyIds = []string{policy.Msg.GetAccessPolicy().GetId()}
		return r
	}
	update := func(rt *rpmgrv1.Route, paths ...string) (*rpmgrv1.UpdateRouteResponse, error) {
		cur, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: rt.GetId()}))
		if err != nil {
			return nil, err
		}
		res, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: rt, Etag: cur.Msg.GetRoute().GetEtag(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}
	get := func(rt *rpmgrv1.Route) *rpmgrv1.Route {
		t.Helper()
		cur, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: rt.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		return cur.Msg.GetRoute()
	}
	vpn, err := createRoute(ada, org, tlsRoute("vpn", "proxy.example.com", first), "")
	if err != nil {
		t.Fatal(err)
	}
	port := vpn.GetTcp().GetPort()
	noUsers := tlsRoute("git", "proxy.example.com", first)
	noUsers.PolicyIds = nil
	res, err := ada.rt.CreateRoute(ctx, connect.NewRequest(&rpmgrv1.CreateRouteRequest{OrgId: org, Route: noUsers}))
	if err != nil || res.Msg.GetRoute().GetTcp().GetPort() != port || len(res.Msg.GetWarnings()) != 1 ||
		!strings.Contains(res.Msg.GetWarnings()[0], "407") {
		t.Fatalf("a tls_basic route without basic-auth rule: the listener and a warning: %v %v", res, err)
	}
	git := res.Msg.GetRoute()

	// One route's new certificate is the listener's, for both routes, on the same port.
	rotated := proto.Clone(vpn).(*rpmgrv1.Route)
	rotated.GetTcp().GetConnect().CertificateId = second
	got, err := update(rotated, "tcp.connect")
	if err != nil || got.GetRoute().GetTcp().GetPort() != port || got.GetRoute().GetTcp().GetConnect().GetCertificateId() != second {
		t.Fatalf("a certificate rotation: %v %v", got, err)
	}
	if g := get(git); g.GetTcp().GetPort() != port || g.GetTcp().GetConnect().GetCertificateId() != second {
		t.Fatalf("the listener's other route after the rotation: %v", g)
	}
	if n := e.db.Client().ConnectListener.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d listeners after the rotation, want 1", n)
	}
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	served := func(caps []string) map[string][]string {
		t.Helper()
		out := map[string][]string{}
		if err := store.ReadTx(e.sys, e.db, func(tx *ent.Tx, _ store.Revision) error {
			rs, err := certs.Gateway(e.sys, tx, snapshot.Agent{Identity: pki.Identity{Org: org, Kind: pki.KindGateway, ID: gw.GetId()},
				Capabilities: caps})
			for _, r := range rs {
				out[r.GetId()] = r.GetGatewayCertificate().GetHostnames()
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := served(gateway.Capabilities); len(got) != 1 || !slices.Equal(got[second], []string{"proxy.example.com"}) {
		t.Fatalf("the gateway's certificates after the rotation: %v", got)
	}
	if got := served([]string{"tunnel.quic", "tunnel.h2"}); len(got) != 0 {
		t.Fatalf("a gateway without tcp.http-connect got the listener's certificate: %v", got)
	}

	// The listener's port with another hostname is another listener.
	other := tlsRoute("other", "vpn.example.com", second)
	other.GetTcp().Port = port
	if _, err := createRoute(ada, org, other, ""); reason(err) != apisvc.ReasonConnectModeMismatch {
		t.Fatalf("another hostname on the listener's port: %v", err)
	}
	// A taken authority refuses the update, which changes nothing.
	taken := proto.Clone(git).(*rpmgrv1.Route)
	taken.GetTcp().GetConnect().Authorities = []string{"git.internal", "VPN.internal"}
	if _, err := update(taken, "tcp.connect"); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("an update to a taken authority: %v", err)
	}
	if g := get(git); !slices.Equal(g.GetTcp().GetConnect().GetAuthorities(), []string{"git.internal"}) {
		t.Fatalf("the refused update changed the authorities: %v", g.GetTcp().GetConnect().GetAuthorities())
	}
	// An unset auth mode is no move to mode none.
	unset := proto.Clone(git).(*rpmgrv1.Route)
	unset.GetTcp().Connect = &rpmgrv1.ConnectSpec{Authorities: []string{"git.internal"}}
	if _, err := update(unset, "tcp.connect"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("an update with the auth mode unset: %v", err)
	}
	// Another org's certificate, though it covers the hostname, is not found.
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	foreign := upload(bob, orgB, "proxy.example.com")
	if _, err := createRoute(ada, org, tlsRoute("foreign", "proxy.example.com", foreign), ""); code(err) != connect.CodeNotFound {
		t.Fatalf("a route naming another org's certificate: %v", err)
	}
	stolen := proto.Clone(vpn).(*rpmgrv1.Route)
	stolen.GetTcp().GetConnect().CertificateId = foreign
	if _, err := update(stolen, "tcp.connect"); code(err) != connect.CodeNotFound {
		t.Fatalf("an update to another org's certificate: %v", err)
	}
	// A preview warns as a write does and stores nothing.
	pv, err := ada.rt.PreviewRoute(ctx, connect.NewRequest(&rpmgrv1.PreviewRouteRequest{OrgId: org,
		Route: connectTCP("pv", group, 0, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_PLAIN_BASIC, "pv.internal")}))
	if err != nil || len(pv.Msg.GetWarnings()) != 2 || !strings.Contains(pv.Msg.GetWarnings()[0], "in the clear") ||
		!strings.Contains(pv.Msg.GetWarnings()[1], "407") {
		t.Fatalf("the preview of a plain_basic route without basic-auth rule: %v %v", pv, err)
	}
	if n := e.db.Client().ConnectListener.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d listeners after a preview, want 1", n)
	}
	// The listener's hostname keeps its domain.
	if _, err := ada.dom.DeleteDomain(ctx, connect.NewRequest(&rpmgrv1.DeleteDomainRequest{DomainId: domainID})); reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("removing the domain of a listener's hostname: %v", err)
	}
	// With the quota of 2 taken, a mode change frees its old listener's port first.
	open, err := createRoute(ada, org, connectTCP("open", group, 0, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE, "open.internal"), "")
	if err != nil {
		t.Fatal(err)
	}
	// On a route of mode none, an unset mode is that mode.
	more := proto.Clone(open).(*rpmgrv1.Route)
	more.GetTcp().Connect = &rpmgrv1.ConnectSpec{Authorities: []string{"open.internal", "more.internal"}}
	if got, err := update(more, "tcp.connect"); err != nil || got.GetRoute().GetTcp().GetPort() != open.GetTcp().GetPort() ||
		len(got.GetRoute().GetTcp().GetConnect().GetAuthorities()) != 2 {
		t.Fatalf("an update of a route of mode none with the mode unset: %v %v", got, err)
	}
	moved := proto.Clone(open).(*rpmgrv1.Route)
	moved.GetTcp().GetConnect().AuthMode = rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_PLAIN_BASIC
	if got, err := update(moved, "tcp.connect"); err != nil || got.GetRoute().GetTcp().GetConnect().GetAuthMode() != moved.GetTcp().GetConnect().GetAuthMode() {
		t.Fatalf("a mode change at the quota: %v %v", got, err)
	}
	// Once the listener closes with its last route, the domain can go.
	for _, rt := range []*rpmgrv1.Route{vpn, git} {
		if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: rt.GetId()})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ada.dom.DeleteDomain(ctx, connect.NewRequest(&rpmgrv1.DeleteDomainRequest{DomainId: domainID})); err != nil {
		t.Fatalf("removing the domain after the listener closed: %v", err)
	}
}


// TestConnectRoutes_TLSWithoutCertificate (#934): a tls_basic route needs its listener's hostname
// but no certificate; without one its listener presents an uploaded certificate of the org that
// covers the hostname, else the ACME one, and until there is one the route's online gateways
// report CERTIFICATE_PENDING, with the reason of the last ACME attempt.
func TestConnectRoutes_TLSWithoutCertificate(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	e.verified(t, org, "example.com", true)
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	r := connectTCP("vpn", group, 0, rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC, "vpn.internal")
	if _, err := createRoute(ada, org, r, ""); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("tls_basic without a hostname: %v", err)
	}
	r.GetTcp().GetConnect().Hostname = "proxy.example.org"
	if _, err := createRoute(ada, org, r, ""); reason(err) != apisvc.ReasonDomainNotVerified {
		t.Fatalf("a hostname outside the verified domains: %v", err)
	}
	r.GetTcp().GetConnect().Hostname = "Proxy.Example.com"
	vpn, err := createRoute(ada, org, r, "")
	if err != nil {
		t.Fatalf("tls_basic without a certificate: %v", err)
	}
	if c := vpn.GetTcp().GetConnect(); c.GetHostname() != "proxy.example.com" || c.GetCertificateId() != "" {
		t.Fatalf("the CONNECT spec: %v", c)
	}
	notServing := func() []*rpmgrv1.RouteNotServing {
		t.Helper()
		runNewest(t, e, org, gw.GetId())
		c.AgentSession.UpdateOneID(gw.GetId()).SetCapabilities(gateway.Capabilities).ExecX(e.sys)
		got, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: vpn.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		return got.Msg.GetRoute().GetStatus().GetNotServing()
	}
	pending := func(ns []*rpmgrv1.RouteNotServing) *rpmgrv1.RouteNotServing {
		for _, n := range ns {
			if n.GetId() == gw.GetId() && n.GetReason() == "CERTIFICATE_PENDING" {
				return n
			}
		}
		return nil
	}
	if p := pending(notServing()); p == nil || p.GetDetail() != "proxy.example.com" {
		t.Fatalf("no certificate yet: %v", notServing())
	}
	// A failed ACME attempt: its reason is the detail.
	row := c.Certificate.Create().SetOrgID(org).SetSource(certificate.SourceAcme).SetSans([]string{"proxy.example.com"}).
		SetStatus(certificate.StatusFailed).SetLastError("acme: the CA refused").SaveX(e.sys)
	if p := pending(notServing()); p == nil || p.GetDetail() != "proxy.example.com: acme: the CA refused" {
		t.Fatalf("a failed attempt: %v", notServing())
	}
	// Issued: no longer pending.
	c.Certificate.UpdateOne(row).SetStatus(certificate.StatusActive).SetLastError("").SetNotBefore(e.clock).
		SetNotAfter(e.clock.Add(90 * 24 * time.Hour)).SetChain([]byte{1}).SetKeyEnc([]byte{2}).SetContentSha256([]byte{3}).ExecX(e.sys)
	if p := pending(notServing()); p != nil {
		t.Fatalf("an issued certificate: %v", p)
	}
}
