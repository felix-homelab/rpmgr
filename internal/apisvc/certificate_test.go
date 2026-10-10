// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
)

// testCert is a certificate signed by parent, or self-signed, valid from notBefore to notAfter.
func testCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey crypto.Signer, notBefore, notAfter time.Time) (
	*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber, tmpl.NotBefore, tmpl.NotAfter = big.NewInt(time.Now().UnixNano()), notBefore, notAfter
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func certPEM(cs ...*x509.Certificate) string {
	var b bytes.Buffer
	for _, c := range cs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}

func keyPEMOf(t *testing.T, k crypto.Signer) (string, []byte) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), der
}

// TestCertificates (docs/04-security.md, "Controller certificates"): an uploaded chain and key
// are checked, stored with the key under the KEK, and shown without it; an expired leaf, a key of
// another certificate or text that is not PEM is refused; a route serves only an uploaded
// certificate that covers its hostnames; a certificate a route serves, or an ACME one, is not
// deleted; a deleted one leaves no record of its sealed key; only Owners and Admins upload.
func TestCertificates(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	ca, caKey := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil, e.clock.Add(-time.Hour), e.clock.Add(365*24*time.Hour))
	leafOf := func(notAfter time.Time) (*x509.Certificate, crypto.Signer) {
		return testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "app.example.com"}, DNSNames: []string{"WWW.example.com", "app.example.com"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}, ca, caKey,
			e.clock.Add(-time.Hour), notAfter)
	}
	leaf, key := leafOf(e.clock.Add(90 * 24 * time.Hour))
	keyText, keyDER := keyPEMOf(t, key)
	upload := func(b *browser, chain, key string) (*rpmgrv1.UploadCertificateResponse, error) {
		r, err := b.crt.UploadCertificate(ctx, connect.NewRequest(&rpmgrv1.UploadCertificateRequest{OrgId: org, ChainPem: chain, PrivateKeyPem: key}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	up, err := upload(ada, certPEM(leaf, ca), keyText)
	if err != nil {
		t.Fatal(err)
	}
	crt := up.GetCertificate()
	if !strings.HasPrefix(crt.GetId(), "crt_") || crt.GetSource() != rpmgrv1.CertificateSource_CERTIFICATE_SOURCE_UPLOADED ||
		strings.Join(crt.GetSans(), ",") != "app.example.com,www.example.com" || !crt.GetNotAfter().AsTime().Equal(leaf.NotAfter) ||
		crt.GetStatus() != rpmgrv1.CertificateStatus_CERTIFICATE_STATUS_ACTIVE || crt.GetIssuer() != "CN=Test CA" || crt.GetEtag() != "1" ||
		up.GetRevision().GetSeq() == 0 {
		t.Fatalf("uploaded: %v", up)
	}
	row := c.Certificate.GetX(e.sys, crt.GetId())
	sealed := c.SecretMeta.Query().Where(secretmeta.TableName("certificates"), secretmeta.RowID(crt.GetId())).CountX(e.sys)
	if len(row.KeyEnc) == 0 || bytes.Contains(row.KeyEnc, keyDER) || sealed != 1 {
		t.Fatalf("the stored key: %d bytes, plain %t, %d records", len(row.KeyEnc), bytes.Contains(row.KeyEnc, keyDER), sealed)
	}

	// Refused uploads.
	expired, expiredKey := leafOf(e.clock.Add(-time.Minute))
	expiredText, _ := keyPEMOf(t, expiredKey)
	for name, in := range map[string][2]string{
		"an expired leaf":            {certPEM(expired, ca), expiredText},
		"the key of another leaf":    {certPEM(leaf, ca), expiredText},
		"a chain that is not PEM":    {"not a certificate", keyText},
		"a CA as the leaf":           {certPEM(ca), keyText},
		"a chain in the wrong order": {certPEM(ca, leaf), keyText},
	} {
		if _, err := upload(ada, in[0], in[1]); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	if _, err := upload(op, certPEM(leaf, ca), keyText); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator uploads: %v", err)
	}

	// An ACME certificate the job could not obtain yet.
	acme := c.Certificate.Create().SetOrgID(org).SetSource("acme").SetSans([]string{"shop.example.com"}).SetStatus("failed").
		SetLastError("the CA could not reach the name").SaveX(e.sys)
	list, err := op.crt.ListCertificates(ctx, connect.NewRequest(&rpmgrv1.ListCertificatesRequest{OrgId: org}))
	if err != nil || len(list.Msg.GetCertificates()) != 2 {
		t.Fatalf("listed: %v %v", list, err)
	}
	for _, l := range list.Msg.GetCertificates() {
		if l.GetId() == acme.ID && (l.GetStatus() != rpmgrv1.CertificateStatus_CERTIFICATE_STATUS_FAILED || l.GetLastError() == "" ||
			l.GetNotAfter() != nil || l.GetSource() != rpmgrv1.CertificateSource_CERTIFICATE_SOURCE_ACME) {
			t.Errorf("the ACME certificate: %v", l)
		}
	}
	del := func(id string) error {
		_, err := ada.crt.DeleteCertificate(ctx, connect.NewRequest(&rpmgrv1.DeleteCertificateRequest{CertificateId: id}))
		return err
	}
	if err := del(acme.ID); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("an ACME certificate deleted: %v", err)
	}

	// A route serves it: it shows the route, and stays.
	e.verified(t, org, "example.com", true)
	rt := httpRoute("app", group, "app.example.com")
	rt.GetHttp().TlsMode, rt.GetHttp().CertificateId = rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE, crt.GetId()
	route, err := createRoute(ada, org, rt, "")
	if err != nil {
		t.Fatal(err)
	}
	// Only an uploaded certificate that covers every hostname of the route.
	for name, c := range map[string]struct{ host, cert string }{"a name it does not cover": {"shop.example.com", crt.GetId()},
		"an ACME certificate": {"shop.example.com", acme.ID}} {
		bad := httpRoute("bad", group, "app.example.com", c.host)
		bad.GetHttp().TlsMode, bad.GetHttp().CertificateId = rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE, c.cert
		if _, err := createRoute(ada, org, bad, ""); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonCertificateNotCovering {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: &rpmgrv1.Route{Id: route.GetId(),
		Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: []string{"app.example.com", "shop.example.com"}}}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"http.hostnames"}}})); reason(err) != apisvc.ReasonCertificateNotCovering {
		t.Errorf("a hostname the certificate does not cover, added: %v", err)
	}
	got, err := ada.crt.GetCertificate(ctx, connect.NewRequest(&rpmgrv1.GetCertificateRequest{CertificateId: crt.GetId()}))
	if err != nil || len(got.Msg.GetCertificate().GetRouteIds()) != 1 || got.Msg.GetCertificate().GetRouteIds()[0] != route.GetId() {
		t.Fatalf("the routes that serve it: %v %v", got, err)
	}
	if err := del(crt.GetId()); code(err) != connect.CodeFailedPrecondition || reason(err) != "DEPENDANTS_EXIST" {
		t.Errorf("a certificate a route serves deleted: %v", err)
	}
	if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: route.GetId()})); err != nil {
		t.Fatal(err)
	}
	if err := del(crt.GetId()); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.crt.GetCertificate(ctx, connect.NewRequest(&rpmgrv1.GetCertificateRequest{CertificateId: crt.GetId()})); code(err) != connect.CodeNotFound ||
		c.SecretMeta.Query().Where(secretmeta.RowID(crt.GetId())).CountX(e.sys) != 0 {
		t.Fatalf("after the delete: %v", err)
	}

	// The audit log records the upload without the key.
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.CertificateService.UploadCertificate"), auditentry.ResultEQ(auditentry.ResultSuccess)).
		CountX(e.sys); n != 1 {
		t.Fatalf("%d audit entries of the upload", n)
	}
	for _, a := range c.AuditEntry.Query().AllX(e.sys) {
		if strings.Contains(a.Diff, "PRIVATE KEY") {
			t.Fatalf("audit entry %s holds a key", a.Action)
		}
	}
}

// renewals is a Renewer that records what it is asked to renew.
type renewals struct {
	mu      sync.Mutex
	names   []string
	running bool  // a renewal runs already
	err     error // the answer
}

func (r *renewals) RenewAsync(_ context.Context, org, name string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return false, r.err
	}
	r.names = append(r.names, org+"/"+name)
	return !r.running, nil
}

// TestRenewCertificate (docs/07-api.md, "Services"): an ACME certificate's renewal starts in the
// background and the answer comes at once, saying whether this request started it; an uploaded
// certificate, a hostname no route in acme mode has and a controller without ACME are refused;
// only Owners and Admins renew.
func TestRenewCertificate(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	acmeCert := c.Certificate.Create().SetOrgID(org).SetSource("acme").SetSans([]string{"shop.example.com"}).SetStatus("failed").
		SetLastError("timeout").SaveX(e.sys)
	uploaded := c.Certificate.Create().SetOrgID(org).SetSource("uploaded").SetSans([]string{"app.example.com"}).SaveX(e.sys)
	renew := func(b *browser, id string) (*rpmgrv1.RenewCertificateResponse, error) {
		r, err := b.crt.RenewCertificate(ctx, connect.NewRequest(&rpmgrv1.RenewCertificateRequest{CertificateId: id}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	r, err := renew(ada, acmeCert.ID)
	if err != nil || !r.GetStarted() || r.GetCertificate().GetId() != acmeCert.ID || len(e.renew.names) != 1 || e.renew.names[0] != org+"/shop.example.com" {
		t.Fatalf("a renewal: %v %v %v", r, err, e.renew.names)
	}
	e.renew.running = true
	if r, err := renew(ada, acmeCert.ID); err != nil || r.GetStarted() {
		t.Fatalf("a renewal while one runs: %v %v", r, err)
	}
	if _, err := renew(ada, uploaded.ID); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("an uploaded certificate: %v", err)
	}
	e.renew.err = acme.ErrNotWanted
	if _, err := renew(ada, acmeCert.ID); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a hostname no route wants: %v", err)
	}
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	if _, err := renew(op, acmeCert.ID); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator renews: %v", err)
	}
	if _, err := (&apisvc.Certificates{DB: e.db}).RenewCertificate(e.sys, connect.NewRequest(&rpmgrv1.RenewCertificateRequest{
		CertificateId: acmeCert.ID})); code(err) != connect.CodeUnavailable {
		t.Errorf("a controller without ACME: %v", err)
	}
}

// TestCABundles (docs/04-security.md, "Controller certificates"): a CA bundle holds 1 to 100 PEM
// certificates, shown with their subjects and expiry; a bundle that is not one is refused; the
// targets that use it are shown, a change of it names them in its revision, and it is not deleted
// while one does; only Owners and Admins change bundles.
func TestCABundles(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	ca, _ := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Upstream CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil, e.clock.Add(-time.Hour), e.clock.Add(365*24*time.Hour))
	other, _ := testCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Other CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil, nil, e.clock.Add(-time.Hour), e.clock.Add(30*24*time.Hour))
	create := func(b *browser, name, pemText string) (*rpmgrv1.CreateCABundleResponse, error) {
		r, err := b.crt.CreateCABundle(ctx, connect.NewRequest(&rpmgrv1.CreateCABundleRequest{OrgId: org,
			CaBundle: &rpmgrv1.CABundle{Name: name, Pem: pemText}}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	created, err := create(ada, "internal", certPEM(ca))
	bundle := created.GetCaBundle()
	if err != nil || !strings.HasPrefix(bundle.GetId(), "cab_") || len(bundle.GetCertificates()) != 1 ||
		bundle.GetCertificates()[0].GetSubject() != "CN=Upstream CA" || !bundle.GetCertificates()[0].GetNotAfter().AsTime().Equal(ca.NotAfter) ||
		bundle.GetEtag() != "1" || created.GetRevision().GetSeq() == 0 {
		t.Fatalf("created: %v %v", created, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyText, _ := keyPEMOf(t, key)
	for name, in := range map[string][2]string{"not PEM": {"x", "not a certificate"}, "a key": {"y", keyText},
		"no name": {"", certPEM(ca)}} {
		if _, err := create(ada, in[0], in[1]); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}
	if _, err := create(ada, "internal", certPEM(ca)); code(err) != connect.CodeAlreadyExists {
		t.Errorf("a taken name: %v", err)
	}
	op, _ := e.join(t, ada, org, "op@example.com", "operator")
	if _, err := create(op, "mine", certPEM(ca)); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator creates: %v", err)
	}

	// An HTTPS target uses it.
	e.verified(t, org, "example.com", true)
	rt, err := createRoute(ada, org, httpRoute("app", group, "app.example.com"), "")
	if err != nil {
		t.Fatal(err)
	}
	tg := addressTarget(e.addConnector(t, org, "nas", nil).ID, "10.0.0.5", 8443)
	tg.UpstreamProtocol, tg.Tls = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS, &rpmgrv1.UpstreamTLSSettings{ServerName: "app.internal",
		CaBundleId: bundle.GetId()}
	target, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: rt.GetId(), Target: tg}))
	if err != nil {
		t.Fatal(err)
	}
	targetID := target.Msg.GetTarget().GetId()
	got, err := op.crt.GetCABundle(ctx, connect.NewRequest(&rpmgrv1.GetCABundleRequest{CaBundleId: bundle.GetId()}))
	if err != nil || len(got.Msg.GetCaBundle().GetTargetIds()) != 1 || got.Msg.GetCaBundle().GetTargetIds()[0] != targetID {
		t.Fatalf("the targets that use it: %v %v", got, err)
	}
	update := func(paths []string, in *rpmgrv1.CABundle, etag string) (*rpmgrv1.UpdateCABundleResponse, error) {
		in.Id = bundle.GetId()
		r, err := ada.crt.UpdateCABundle(ctx, connect.NewRequest(&rpmgrv1.UpdateCABundleRequest{CaBundle: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	up, err := update([]string{"pem"}, &rpmgrv1.CABundle{Pem: certPEM(ca, other)}, "1")
	if err != nil || len(up.GetCaBundle().GetCertificates()) != 2 || up.GetCaBundle().GetName() != "internal" || up.GetCaBundle().GetEtag() != "2" {
		t.Fatalf("a second CA: %v %v", up, err)
	}
	if changed := c.ConfigRevision.GetX(e.sys, up.GetRevision().GetSeq()).ChangedResources; !slices.Contains(changed, targetID) {
		t.Errorf("the revision of the change names %v, not the target", changed)
	}
	if _, err := update([]string{"pem"}, &rpmgrv1.CABundle{Pem: "not PEM"}, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a broken bundle: %v", err)
	}
	if _, err := update([]string{"name"}, &rpmgrv1.CABundle{Name: "renamed"}, "1"); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stale etag: %v", err)
	}
	if _, err := update([]string{"target_ids"}, &rpmgrv1.CABundle{TargetIds: []string{"rtt_x"}}, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("an output-only field: %v", err)
	}
	del := func(b *browser) error {
		_, err := b.crt.DeleteCABundle(ctx, connect.NewRequest(&rpmgrv1.DeleteCABundleRequest{CaBundleId: bundle.GetId()}))
		return err
	}
	if err := del(ada); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDependantsExist {
		t.Errorf("a bundle a target uses deleted: %v", err)
	}
	if err := del(op); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Operator deletes: %v", err)
	}
	if _, err := ada.rt.DeleteRouteTarget(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteTargetRequest{RouteTargetId: targetID})); err != nil {
		t.Fatal(err)
	}
	if err := del(ada); err != nil {
		t.Fatal(err)
	}
	if list, err := ada.crt.ListCABundles(ctx, connect.NewRequest(&rpmgrv1.ListCABundlesRequest{OrgId: org})); err != nil || len(list.Msg.GetCaBundles()) != 0 {
		t.Fatalf("after the delete: %v %v", list, err)
	}
}
