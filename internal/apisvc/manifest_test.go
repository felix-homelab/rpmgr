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
// to and never holding a password or its hash, or a field the server sets; decommissioned agents
// are left out; another org's resource is not found; a Viewer exports; an export that matches
// nothing is an empty stream.
func TestExportManifests(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	gw1, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	con := e.addConnector(t, org, "nas", func(c *ent.ConnectorCreate) { c.SetBuiltIn(true) }).ID
	old := e.addConnector(t, org, "old", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(e.clock) }).ID
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
	if err != nil || rt.GetUpdateUserId() == "" {
		t.Fatalf("a route with the user who made it: %v %v", rt, err)
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
	for _, never := range []string{"correct horse", "$argon2id", "PRIVATE KEY", con, "updateUserId", rt.GetUpdateUserId(), "builtIn", "etag"} {
		if strings.Contains(text, never) {
			t.Errorf("the manifests hold %q", never)
		}
	}
	if docs, _, err := export(ada, &rpmgrv1.ExportManifestsRequest{Kinds: []string{"Route", "Connector"}}); err != nil || len(docs) != 2 ||
		docs[0].Kind != "Route" || docs[1].Kind != "Connector" {
		t.Fatalf("two kinds: %v %v", docs, err)
	}
	exportByID(t, ada, org, export, byIDResources{route: rt.GetId(), connector: con, old: old, group: group, gateway: gw1.GetId(),
		policy: policy.Msg.GetAccessPolicy().GetId(), bundle: bundle.Msg.GetCaBundle().GetId()})
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
	if r, err := bob.man.ExportManifests(ctx, connect.NewRequest(&rpmgrv1.ExportManifestsRequest{OrgId: orgB, Kinds: []string{"Route"}})); err != nil ||
		r.Msg.GetYaml() != "" || r.Msg.GetCount() != 0 {
		t.Errorf("an org without routes: %v %v", r, err)
	}
	if _, _, err := export(ada, &rpmgrv1.ExportManifestsRequest{ResourceIds: []string{rt.GetId(), theirs.Msg.GetGatewayGroup().GetId()}}); code(err) != connect.CodeNotFound {
		t.Errorf("another org's resource: %v", err)
	}
	if _, _, err := export(ada, &rpmgrv1.ExportManifestsRequest{Kinds: []string{"Secret"}}); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a kind of no manifest: %v", err)
	}
}

// byIDResources are the IDs of the resources TestExportManifests made.
type byIDResources struct{ route, connector, old, group, gateway, policy, bundle string }

// exportByID: a request that names resources gets exactly those, in the order of the kinds, also
// when more resources of their kinds follow them: the YAML of one route, one connector, or one
// gateway group with its gateways. A resource named that the org does not have, that is not of a
// kind named, or that is decommissioned is not found.
func exportByID(t *testing.T, ada *browser, org string,
	export func(*browser, *rpmgrv1.ExportManifestsRequest) ([]*manifest.Doc, string, error), r byIDResources) {
	t.Helper()
	ctx := context.Background()
	us, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "us"}}))
	if err != nil {
		t.Fatal(err)
	}
	api, err := createRoute(ada, org, httpRoute("api", r.group, "api.example.com"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ids, kinds []string
		want       string
	}{
		{[]string{r.route}, nil, "Route/web"},
		{[]string{api.GetId()}, nil, "Route/api"},
		{[]string{r.connector}, nil, "Connector/nas"},
		{[]string{r.group, r.gateway}, nil, "GatewayGroup/eu Gateway/gw1"},
		{[]string{r.group}, nil, "GatewayGroup/eu"},
		{[]string{us.Msg.GetGatewayGroup().GetId()}, nil, "GatewayGroup/us"},
		{[]string{r.route, r.connector, r.policy, r.bundle}, nil, "CABundle/internal AccessPolicy/staff Connector/nas Route/web"},
		{[]string{r.connector, r.route}, []string{"Route", "Connector"}, "Route/web Connector/nas"},
	} {
		docs, _, err := export(ada, &rpmgrv1.ExportManifestsRequest{ResourceIds: c.ids, Kinds: c.kinds})
		var got []string
		for _, d := range docs {
			got = append(got, d.Kind+"/"+d.Metadata.Name)
		}
		if err != nil || strings.Join(got, " ") != c.want {
			t.Errorf("%v of %v: %v %v, want %s", c.ids, c.kinds, got, err, c.want)
		}
	}
	for name, req := range map[string]*rpmgrv1.ExportManifestsRequest{
		"an unknown ID":                  {ResourceIds: []string{"rt_unknown"}},
		"an unknown ID among known ones": {ResourceIds: []string{r.route, "con_unknown"}},
		"a resource of a kind not named": {ResourceIds: []string{r.connector}, Kinds: []string{"Route"}},
		"a decommissioned connector":     {ResourceIds: []string{r.old}},
	} {
		if docs, _, err := export(ada, req); code(err) != connect.CodeNotFound {
			t.Errorf("%s: %v %v", name, docs, err)
		}
	}
}
