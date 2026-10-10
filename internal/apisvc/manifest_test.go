// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/manifest"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestExportManifests (docs/07-api.md, "Declarative manifests"): an org's resources are exported
// as YAML manifests, every kind in order or the kinds or resources named, naming what they refer
// to and never holding a password or its hash; decommissioned agents are left out; another org's
// resource is not found; a Viewer exports.
func TestExportManifests(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	if _, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443"); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	con := e.addConnector(t, org, "nas", nil).ID
	e.addConnector(t, org, "old", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(e.clock) })
	ca, _ := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Upstream CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil, e.clock.Add(-time.Hour), e.clock.Add(time.Hour))
	bundle, err := ada.crt.CreateCABundle(ctx, connect.NewRequest(&rpmgrv1.CreateCABundleRequest{OrgId: org,
		CaBundle: &rpmgrv1.CABundle{Name: "internal", Pem: certPEM(ca)}}))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ada.pol.CreateAccessPolicy(ctx, connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
		AccessPolicy: &rpmgrv1.AccessPolicy{Name: "staff", Rules: []*rpmgrv1.AccessRule{basicAuth(user("alice", "correct horse battery"))}}}))
	if err != nil {
		t.Fatal(err)
	}
	web := httpRoute("web", group, "web.example.com")
	web.PolicyIds = []string{policy.Msg.GetAccessPolicy().GetId()}
	rt, err := createRoute(ada, org, web, "")
	if err != nil {
		t.Fatal(err)
	}
	tg := addressTarget(con, "10.0.0.5", 8443)
	tg.UpstreamProtocol, tg.Tls = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS, &rpmgrv1.UpstreamTLSSettings{ServerName: "web.internal",
		CaBundleId: bundle.Msg.GetCaBundle().GetId()}
	if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: rt.GetId(), Target: tg})); err != nil {
		t.Fatal(err)
	}

	export := func(b *browser, req *rpmgrv1.ExportManifestsRequest) ([]*manifest.Doc, string, error) {
		req.OrgId = org
		r, err := b.man.ExportManifests(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, "", err
		}
		docs, err := manifest.Read(strings.NewReader(r.Msg.GetYaml()))
		if err != nil || int(r.Msg.GetCount()) != len(docs) {
			t.Fatalf("the YAML of %d manifests: %d, %v", r.Msg.GetCount(), len(docs), err)
		}
		return docs, r.Msg.GetYaml(), nil
	}
	docs, text, err := export(ada, &rpmgrv1.ExportManifestsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, d := range docs {
		kinds = append(kinds, d.Kind+"/"+d.Metadata.Name)
	}
	if got := strings.Join(kinds, " "); !strings.HasPrefix(got, "GatewayGroup/eu Gateway/gw1 PortPool/pp_") ||
		!strings.HasSuffix(got, "Domain/example.com CABundle/internal AccessPolicy/staff Connector/nas Route/web") {
		t.Fatalf("exported %s", got)
	}
	for _, want := range []string{"gatewayGroup: eu", "connector: nas", "caBundle: internal", "- staff", "name: alice"} {
		if !strings.Contains(text, want) {
			t.Errorf("the manifests lack %q:\n%s", want, text)
		}
	}
	for _, never := range []string{"correct horse", "$argon2id", "PRIVATE KEY", con} {
		if strings.Contains(text, never) {
			t.Errorf("the manifests hold %q", never)
		}
	}
	if docs, _, err := export(ada, &rpmgrv1.ExportManifestsRequest{Kinds: []string{"Route", "Connector"}}); err != nil || len(docs) != 2 ||
		docs[0].Kind != "Route" || docs[1].Kind != "Connector" {
		t.Fatalf("two kinds: %v %v", docs, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if docs, _, err := export(vwr, &rpmgrv1.ExportManifestsRequest{ResourceIds: []string{rt.GetId()}}); err != nil || len(docs) != 1 || docs[0].Metadata.Name != "web" {
		t.Fatalf("one route, by a Viewer: %v %v", docs, err)
	}

	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	theirs, err := bob.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: orgB,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "b"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := export(ada, &rpmgrv1.ExportManifestsRequest{ResourceIds: []string{rt.GetId(), theirs.Msg.GetGatewayGroup().GetId()}}); code(err) != connect.CodeNotFound {
		t.Errorf("another org's resource: %v", err)
	}
	if _, _, err := export(ada, &rpmgrv1.ExportManifestsRequest{Kinds: []string{"Secret"}}); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a kind of no manifest: %v", err)
	}
}
