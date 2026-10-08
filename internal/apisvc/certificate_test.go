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
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
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
// another certificate or text that is not PEM is refused; a certificate a route serves, or an ACME
// one, is not deleted; a deleted one leaves no record of its sealed key; only Owners and Admins
// upload.
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
