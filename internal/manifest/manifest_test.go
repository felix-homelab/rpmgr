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
		Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: []string{"nas.example.com"}, TlsMode: rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE,
			CertificateId: "crt_1", RequestHeadersSet: map[string]string{"X-Env": "prod"}}},
		Targets: []*rpmgrv1.RouteTarget{{Id: "rtt_1", ConnectorId: "con_1", Etag: "3", Enabled: true, Weight: 2,
			Address:          &rpmgrv1.RouteTarget_HostPort{HostPort: &rpmgrv1.HostPort{Host: "192.168.10.20", Port: 5000}},
			UpstreamProtocol: rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS,
			Tls:              &rpmgrv1.UpstreamTLSSettings{ServerName: "nas.internal", CaBundleId: "cab_1"}}},
		Etag: "7", Status: &rpmgrv1.RouteStatus{State: rpmgrv1.RouteState_ROUTE_STATE_READY}, CreateTime: timestamppb.Now(), UpdateTime: timestamppb.Now()}
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
		"    certificateId: crt_1\n", "        port: 5000\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("the manifest lacks %q:\n%s", want, text)
		}
	}
	for _, server := range []string{" rt_1", "rtt_1", "etag", "status", "createTime", "updateTime", "gwg_1", "con_1", "cab_1", "ap_1"} {
		if strings.Contains(text, server) {
			t.Errorf("the manifest holds %q:\n%s", server, text)
		}
	}
	want := stored()
	want.Id, want.Etag, want.Status, want.CreateTime, want.UpdateTime = "", "", nil, nil, nil
	want.Targets[0].Id, want.Targets[0].Etag = "", ""
	if !proto.Equal(back, want) {
		t.Fatalf("read back:\n%v\nwant\n%v", back, want)
	}
}

// TestKinds: every kind reads back to its resource, without what the server sets; a resource
// without a name is named by its ID; fields marked sensitive, such as a basic-auth password, are
// never written.
func TestKinds(t *testing.T) {
	now := timestamppb.Now()
	for _, c := range []struct{ in, want proto.Message }{
		{&rpmgrv1.AccessPolicy{Id: "ap_1", Name: "office", Etag: "2", RouteIds: []string{"rt_1"}, Rules: []*rpmgrv1.AccessRule{
			{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: []string{"10.0.0.0/8"}}}},
			{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: []*rpmgrv1.BasicAuthCredential{{Name: "alice", Password: "correct horse"}}}}}}},
			&rpmgrv1.AccessPolicy{Name: "office", Rules: []*rpmgrv1.AccessRule{
				{Rule: &rpmgrv1.AccessRule_IpAllow{IpAllow: &rpmgrv1.IPRuleParams{Cidrs: []string{"10.0.0.0/8"}}}},
				{Rule: &rpmgrv1.AccessRule_BasicAuth{BasicAuth: &rpmgrv1.BasicAuthRule{Users: []*rpmgrv1.BasicAuthCredential{{Name: "alice"}}}}}}}},
		{&rpmgrv1.GatewayGroup{Id: "gwg_1", Name: "eu", Region: "fra", PublicHostnames: []string{"eu.example.com"}, Etag: "1"},
			&rpmgrv1.GatewayGroup{Name: "eu", Region: "fra", PublicHostnames: []string{"eu.example.com"}}},
		{&rpmgrv1.Gateway{Id: "gw_1", GatewayGroupId: "gwg_1", Name: "gw1", Slot: 2, TunnelEndpoints: []string{"gw1.example.com:443"}, Enabled: true,
			CreateTime: now, Status: &rpmgrv1.GatewayStatus{}, Etag: "4"},
			&rpmgrv1.Gateway{GatewayGroupId: "gwg_1", Name: "gw1", TunnelEndpoints: []string{"gw1.example.com:443"}, Enabled: true}},
		{&rpmgrv1.PortPool{Id: "pp_1", GatewayGroupId: "gwg_1", Protocol: rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP, PortFrom: 20000, PortTo: 20099, AllocatedPorts: 3, Etag: "1"},
			&rpmgrv1.PortPool{GatewayGroupId: "gwg_1", Protocol: rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP, PortFrom: 20000, PortTo: 20099}},
		{&rpmgrv1.Domain{Id: "dom_1", Fqdn: "example.com", Wildcard: true, Method: rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP,
			Status: rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED, LastError: "x", VerifyTime: now, Etag: "3"},
			&rpmgrv1.Domain{Fqdn: "example.com", Wildcard: true, Method: rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP}},
		{&rpmgrv1.Connector{Id: "con_1", Name: "nas", Labels: map[string]string{"site": "home"}, Ephemeral: true, Enabled: true, CreateTime: now, Etag: "2"},
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
