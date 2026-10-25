// SPDX-License-Identifier: Apache-2.0

package manifest_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/manifest"
)

// names is a Resolver over fixed resources.
type names map[string]map[string]string // kind → ID → name

func (n names) Name(_ context.Context, kind, id string) (string, error) {
	if name, ok := n[kind][id]; ok {
		return name, nil
	}
	return "", fmt.Errorf("no %s %s", kind, id)
}

func (n names) ID(_ context.Context, kind, name string) (string, error) {
	for id, nm := range n[kind] {
		if nm == name {
			return id, nil
		}
	}
	return "", fmt.Errorf("no %s named %s", kind, name)
}

var resolver = names{
	"GatewayGroup": {"gwg_1": "eu"}, "AccessPolicy": {"ap_1": "office", "ap_2": "auth"},
	"Connector": {"con_1": "nas"}, "CABundle": {"cab_1": "internal"},
}

// stored is a route as the API returns it, with what the server sets.
func stored() *rpmgrv1.Route {
	return &rpmgrv1.Route{Id: "rt_1", Name: "nas-web", GatewayGroupId: "gwg_1", Enabled: true, Labels: map[string]string{"site": "home"},
		Description: "the NAS", Transport: rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC, PolicyIds: []string{"ap_2", "ap_1"},
		Limits: &rpmgrv1.RouteLimits{MaxConnections: 200, BandwidthBytesPerSecond: 10_000_000_000},
		Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: []string{"nas.example.com"}, TlsMode: rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE,
			CertificateId: "crt_1", RequestHeadersSet: map[string]string{"X-Env": "prod"}, Maintenance: true,
			MaintenanceMessage: "Back at 18:00.\nSorry.", HeaderMatches: []*rpmgrv1.HeaderMatch{
				{Name: "X-Env", Match: &rpmgrv1.HeaderMatch_Exact{Exact: "beta"}}, {Name: "X-Tenant", Match: &rpmgrv1.HeaderMatch_Present{Present: true}}},
			UpstreamResponseHeaderTimeoutSeconds: 300, UpstreamIdleTimeoutSeconds: 30}},
		Targets: []*rpmgrv1.RouteTarget{{Id: "rtt_1", ConnectorId: "con_1", Etag: "3", Enabled: true, Weight: 2,
			Address:          &rpmgrv1.RouteTarget_HostPort{HostPort: &rpmgrv1.HostPort{Host: "192.168.10.20", Port: 5000}},
			UpstreamProtocol: rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS,
			Tls:              &rpmgrv1.UpstreamTLSSettings{ServerName: "nas.internal", CaBundleId: "cab_1"}}},
		HealthCheck: &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, HttpPath: "/healthz", IntervalSeconds: 30},
		Etag:        "7", Status: &rpmgrv1.RouteStatus{State: rpmgrv1.RouteState_ROUTE_STATE_READY, HealthNotChecked: []string{"rtt_1"}}, CreateTime: timestamppb.Now(), UpdateTime: timestamppb.Now(),
		UpdateUserId: "usr_1"}
}

// roundTrip writes a resource's manifest as YAML, reads it back and parses it.
func roundTrip(t *testing.T, m proto.Message) (string, proto.Message) {
	t.Helper()
	d, err := manifest.Of(context.Background(), resolver, m)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := manifest.Write(&b, []*manifest.Doc{d}); err != nil {
		t.Fatal(err)
	}
	docs, err := manifest.Read(strings.NewReader(b.String()))
	if err != nil || len(docs) != 1 {
		t.Fatalf("read %d docs: %v", len(docs), err)
	}
	back, err := manifest.Parse(context.Background(), resolver, docs[0])
	if err != nil {
		t.Fatal(err)
	}
	return b.String(), back
}

// TestRoute (docs/07-api.md, "Declarative manifests"): a route's manifest has its kind, name and
// labels, and a spec in the protobuf JSON mapping that names its group, policies, connectors and CA
// bundles; it reads back to the same route, but for what the server sets.
func TestRoute(t *testing.T) {
	text, back := roundTrip(t, stored())
	for _, want := range []string{"kind: Route\nmetadata:\n  name: nas-web\n  labels:\n    site: home\nspec:\n", "  gatewayGroup: eu\n",
		"  policies:\n    - auth\n    - office\n", "    - connector: nas\n", "        caBundle: internal\n", "    tlsMode: TLS_MODE_CERTIFICATE\n",
		"    certificateId: crt_1\n", "        port: 5000\n", "  limits:\n    bandwidthBytesPerSecond: \"10000000000\"\n    maxConnections: 200\n",
		"    maintenance: true\n", "    maintenanceMessage: |-\n      Back at 18:00.\n      Sorry.\n",
		"    upstreamResponseHeaderTimeoutSeconds: 300\n", "    upstreamIdleTimeoutSeconds: 30\n",
		"    headerMatches:\n      - exact: beta\n        name: X-Env\n      - name: X-Tenant\n        present: true\n",
		"  healthCheck:\n    httpPath: /healthz\n    intervalSeconds: 30\n    type: HEALTH_CHECK_TYPE_HTTP\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("the manifest lacks %q:\n%s", want, text)
		}
	}
	for _, server := range []string{" rt_1", "rtt_1", "etag", "status", "createTime", "updateTime", "updateUserId", "usr_1", "gwg_1", "con_1", "cab_1", "ap_1"} {
		if strings.Contains(text, server) {
			t.Errorf("the manifest holds %q:\n%s", server, text)
		}
	}
	want := stored()
	want.Id, want.Etag, want.Status, want.CreateTime, want.UpdateTime, want.UpdateUserId = "", "", nil, nil, nil, ""
	want.Targets[0].Id, want.Targets[0].Etag = "", ""
	if !proto.Equal(back, want) {
		t.Fatalf("read back:\n%v\nwant\n%v", back, want)
	}
}

// TestKinds: every kind reads back to its resource, without what the server sets; a resource
// without a name is named by its ID; fields marked sensitive, such as a basic-auth password or a
// required header's value, are never written.
func TestKinds(t *testing.T) {
	now := timestamppb.Now()
	for _, c := range []struct{ in, want proto.Message }{
		{&rpmgrv1.AccessPolicy{Id: "ap_1", Name: "office", Etag: "2", RouteIds: []string{"rt_1"}, Rules: []*rpmgrv1.AccessRule{
			{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: []string{"10.0.0.0/8"}}}},
			{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: []*rpmgrv1.BasicAuthCredential{{Name: "alice", Password: "correct horse"}}}}},
			{Rule: &rpmgrv1.AccessRule_RequireHeader{RequireHeader: &rpmgrv1.RequireHeaderRule{Name: "X-Origin-Token",
				Values: []string{"correct horse origin header value 1"}}}},
			{Rule: &rpmgrv1.AccessRule_RateLimit{RateLimit: &rpmgrv1.RateLimitRule{PerSecond: 20, Burst: 50}}}}},
			&rpmgrv1.AccessPolicy{Name: "office", Rules: []*rpmgrv1.AccessRule{
				{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: []string{"10.0.0.0/8"}}}},
				{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: []*rpmgrv1.BasicAuthCredential{{Name: "alice"}}}}},
				{Rule: &rpmgrv1.AccessRule_RequireHeader{RequireHeader: &rpmgrv1.RequireHeaderRule{Name: "X-Origin-Token"}}},
				{Rule: &rpmgrv1.AccessRule_RateLimit{RateLimit: &rpmgrv1.RateLimitRule{PerSecond: 20, Burst: 50}}}}}},
		{&rpmgrv1.GatewayGroup{Id: "gwg_1", Name: "eu", Region: "fra", PublicHostnames: []string{"eu.example.com"}, Etag: "1"},
			&rpmgrv1.GatewayGroup{Name: "eu", Region: "fra", PublicHostnames: []string{"eu.example.com"}}},
		{&rpmgrv1.Gateway{Id: "gw_1", GatewayGroupId: "gwg_1", Name: "gw1", Slot: 2, TunnelEndpoints: []string{"gw1.example.com:443"}, Enabled: true,
			CreateTime: now, Status: &rpmgrv1.GatewayStatus{}, Etag: "4", BuiltIn: true},
			&rpmgrv1.Gateway{GatewayGroupId: "gwg_1", Name: "gw1", TunnelEndpoints: []string{"gw1.example.com:443"}, Enabled: true}},
		{&rpmgrv1.PortPool{Id: "pp_1", GatewayGroupId: "gwg_1", Protocol: rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP, PortFrom: 20000, PortTo: 20099, AllocatedPorts: 3, Etag: "1"},
			&rpmgrv1.PortPool{GatewayGroupId: "gwg_1", Protocol: rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP, PortFrom: 20000, PortTo: 20099}},
		{&rpmgrv1.Domain{Id: "dom_1", Fqdn: "example.com", Wildcard: true, Method: rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP,
			Status: rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED, LastError: "x", VerifyTime: now, Etag: "3"},
			&rpmgrv1.Domain{Fqdn: "example.com", Wildcard: true, Method: rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP}},
		{&rpmgrv1.Connector{Id: "con_1", Name: "nas", Labels: map[string]string{"site": "home"}, Ephemeral: true, Enabled: true, CreateTime: now, Etag: "2", BuiltIn: true},
			&rpmgrv1.Connector{Name: "nas", Labels: map[string]string{"site": "home"}, Enabled: true}},
		{&rpmgrv1.CABundle{Id: "cab_1", Name: "internal", Pem: "-----BEGIN CERTIFICATE-----\n", TargetIds: []string{"rtt_1"},
			Certificates: []*rpmgrv1.CACertificate{{Subject: "CN=x"}}, Etag: "1"},
			&rpmgrv1.CABundle{Name: "internal", Pem: "-----BEGIN CERTIFICATE-----\n"}},
	} {
		text, back := roundTrip(t, c.in)
		if !proto.Equal(back, c.want) {
			t.Errorf("%T read back:\n%v\nwant\n%v\n%s", c.in, back, c.want, text)
		}
		if strings.Contains(text, "correct horse") {
			t.Errorf("a password is written:\n%s", text)
		}
		if _, ok := c.in.(*rpmgrv1.PortPool); ok && !strings.Contains(text, "name: pp_1") {
			t.Errorf("a pool is not named by its ID:\n%s", text)
		}
	}
}

// TestRefused: a message that is not a kind, a kind that does not exist, an ID or a name the
// resolver does not know, and a key a manifest or a spec does not have are errors.
func TestRefused(t *testing.T) {
	ctx := context.Background()
	if _, err := manifest.Of(ctx, resolver, &rpmgrv1.Certificate{Id: "crt_1"}); !errors.Is(err, manifest.ErrKind) {
		t.Errorf("a certificate: %v", err)
	}
	if _, err := manifest.Parse(ctx, resolver, &manifest.Doc{Kind: "Secret"}); !errors.Is(err, manifest.ErrKind) {
		t.Errorf("an unknown kind: %v", err)
	}
	r := stored()
	r.GatewayGroupId = "gwg_9"
	if _, err := manifest.Of(ctx, resolver, r); err == nil || !strings.Contains(err.Error(), "gwg_9") {
		t.Errorf("an unknown gateway group: %v", err)
	}
	for name, text := range map[string]string{
		"a key of no manifest": "kind: Route\nmetadata: {name: x}\nextra: 1\n",
		"a key of no spec":     "kind: GatewayGroup\nmetadata: {name: eu}\nspec: {color: red}\n",
		"an unknown name":      "kind: Gateway\nmetadata: {name: gw1}\nspec: {gatewayGroup: us}\n",
		"a name that is a map": "kind: Gateway\nmetadata: {name: gw1}\nspec: {gatewayGroup: {name: eu}}\n",
	} {
		docs, err := manifest.Read(strings.NewReader(text))
		if err == nil {
			_, err = manifest.Parse(ctx, resolver, docs[0])
		}
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestEmpty: no manifests are written as an empty stream, which reads back as none.
func TestEmpty(t *testing.T) {
	var b strings.Builder
	if err := manifest.Write(&b, nil); err != nil || b.String() != "" {
		t.Fatalf("no manifests: %q %v", b.String(), err)
	}
	if docs, err := manifest.Read(strings.NewReader(b.String())); err != nil || len(docs) != 0 {
		t.Fatalf("read back: %v %v", docs, err)
	}
}

// TestNegativeZero: a -0 anywhere in a spec reads as 0, so the manifest writes and reads back
// unchanged; YAML would write the float -0 as "-0", which reads back as the integer 0.
func TestNegativeZero(t *testing.T) {
	in := "kind: Route\nmetadata: {name: a}\nspec: {a: -0.0, b: [-.0, {c: -0e1}], d: -0, e: -1.5}\n"
	docs, err := manifest.Read(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := manifest.Write(&out, docs); err != nil {
		t.Fatal(err)
	}
	want := "kind: Route\nmetadata:\n  name: a\nspec:\n  a: 0\n  b:\n    - 0\n    - c: 0\n  d: 0\n  e: -1.5\n"
	if out.String() != want {
		t.Fatalf("written:\n%s\nwant:\n%s", out.String(), want)
	}
	again, err := manifest.Read(strings.NewReader(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	var out2 strings.Builder
	if err := manifest.Write(&out2, again); err != nil || out2.String() != want {
		t.Fatalf("written again (%v):\n%s", err, out2.String())
	}
}

// TestKeyNotString: a mapping key in a spec that YAML reads as anything but a string is refused
// when read, deep in lists too; a quoted key and a key at the top of the spec are strings.
// Unquoted, 0 and 0.0 would both be written as 0, which reads back as a duplicate key.
func TestKeyNotString(t *testing.T) {
	for _, in := range []string{
		"kind: Route\nmetadata: {name: a}\nspec: {a: {0: x, 0.0: y}}\n",
		"kind: Route\nmetadata: {name: a}\nspec: {a: {0: x}}\n",
		"kind: Route\nmetadata: {name: a}\nspec: {a: {b: x, true: y}}\n",
		"kind: Route\nmetadata: {name: a}\nspec: {a: [{b: [{~: x}]}]}\n",
		"kind: Route\nmetadata: {name: ok}\nspec: {}\n---\nkind: Route\nmetadata: {name: a}\nspec: {a: {1.5: x}}\n",
	} {
		if docs, err := manifest.Read(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), "is not a string") {
			t.Errorf("%q: %v, %v", in, docs, err)
		}
	}
	in := "kind: Route\nmetadata: {name: a}\nspec: {0: x, a: {\"0\": x, \"0.0\": y, b: [{\"1\": z}]}}\n"
	docs, err := manifest.Read(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := manifest.Write(&out, docs); err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Read(strings.NewReader(out.String())); err != nil {
		t.Fatalf("read back: %v\n%s", err, out.String())
	}
}

// TestConnectRoute: a tcp route in http_connect mode reads back with its listener mode, its
// authorities and its CONNECT listener's mode, hostname and certificate.
func TestConnectRoute(t *testing.T) {
	r := &rpmgrv1.Route{Name: "vpn", GatewayGroupId: "gwg_1", Enabled: true, Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{Port: 20001,
		ListenerMode: rpmgrv1.ListenerMode_LISTENER_MODE_HTTP_CONNECT, Connect: &rpmgrv1.ConnectSpec{Authorities: []string{"bastion", "ssh.internal"},
			AuthMode: rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC, Hostname: "proxy.example.com", CertificateId: "crt_1"}}}}
	text, back := roundTrip(t, r)
	for _, want := range []string{"    listenerMode: LISTENER_MODE_HTTP_CONNECT\n", "      authMode: CONNECT_AUTH_MODE_TLS_BASIC\n",
		"      authorities:\n        - bastion\n        - ssh.internal\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("the manifest lacks %q:\n%s", want, text)
		}
	}
	if !proto.Equal(back, r) {
		t.Fatalf("read back:\n%v\nwant\n%v", back, r)
	}
}
