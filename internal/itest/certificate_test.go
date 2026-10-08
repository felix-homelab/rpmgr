// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
)

// TestRouteCertificate_ReachesGateway: the uploaded certificate an http route names reaches the
// gateway through its snapshot and FetchResource, and the gateway keeps it in its
// state directory, readable by itself only; once no route needs it, the copy goes.
func TestRouteCertificate_ReachesGateway(t *testing.T) {
	p := newDataPlane(t)
	c := p.c
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	var (
		crt     *ent.Certificate
		routeID string
	)
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		tcp, err := tx.Route.Get(c.Sys, p.routeID)
		if err != nil {
			return nil, err
		}
		d, err := domains.Claim(c.Sys, tx, c.Org, "example.com", true)
		if err != nil {
			return nil, err
		}
		if err := tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(c.Sys); err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("web").SetType("http").SetGatewayGroupID(tcp.GatewayGroupID).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		routeID = r.ID
		if _, err := routes.AddHostname(c.Sys, tx, r.ID, "app.example.com", ""); err != nil {
			return nil, err
		}
		crt, err = certs.Upload(c.Sys, tx, c.Sealer(), c.Org, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), time.Now())
		if err != nil {
			return nil, err
		}
		return []string{r.ID, crt.ID}, tx.RouteHTTP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetTLSMode(routehttp.TLSModeCertificate).
			SetCertificateID(crt.ID).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(p.gwCfg.StateDir, gateway.ResourcesDir, hex.EncodeToString(crt.ContentSha256))
	waitFor(t, "the certificate did not reach the gateway", func() bool {
		fi, err := os.Stat(kept)
		return err == nil && fi.Mode().Perm() == 0o600
	})

	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		return []string{routeID}, tx.Route.UpdateOneID(routeID).SetEnabled(false).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the gateway kept a certificate no route needs", func() bool {
		_, err := os.Stat(kept)
		return os.IsNotExist(err)
	})
}
