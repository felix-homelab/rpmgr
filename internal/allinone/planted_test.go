// SPDX-License-Identifier: Apache-2.0

package allinone_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
)

// plant writes into dir a key and a certificate for the SPIFFE ID id, issued by a CA of its own,
// as someone who can write the identity directory but holds no key of the installation's CA could.
func plant(t *testing.T, dir string, id pki.Identity) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "planted CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(id.String())
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.SaveCertificate(dir, key, [][]byte{der, caDER}); err != nil {
		t.Fatal(err)
	}
}

// TestAllInOne_PlantedIdentityNeverAdopted (#599 review): on a database that marks no gateway built
// in, as before ADR-0019, the all-in-one takes the gateway its identity names only if this
// database's CA issued that identity. A certificate planted in the identity directory, naming
// another org's gateway whose identity is revoked, or the database's own gateway, or one of another
// trust domain, is never adopted: the start stops, and no gateway is marked built in, decommissioned
// or created.
func TestAllInOne_PlantedIdentityNeverAdopted(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, group := h.db(t)
	gwDir := h.cfg.Gateway().IdentityDir
	id, err := agent.Load(gwDir)
	if err != nil {
		t.Fatal(err)
	}
	td := id.TrustDomain
	db.Client().Gateway.UpdateOneID(r.GatewayID).SetBuiltIn(false).ExecX(sys)
	other := db.Client().Org.Create().SetName("Other").SetSlug("other").SaveX(sys)
	otherGroup := db.Client().GatewayGroup.Create().SetOrgID(other.ID).SetName("theirs").SaveX(sys)
	victimID := pki.Identity{TrustDomain: td, Org: other.ID, Kind: pki.KindGateway, ID: ids.New("gw")}
	db.Client().Gateway.Create().SetID(victimID.ID).SetOrgID(other.ID).SetGatewayGroupID(otherGroup.ID).SetName("theirs").
		SetTunnelEndpoints([]string{"gw.other.example:443"}).SetSpiffeID(victimID.String()).ExecX(sys)
	revokeIdentity(t, db, sys, victimID)
	before := db.Client().Gateway.Query().CountX(sys)

	for name, planted := range map[string]pki.Identity{
		"another org's revoked gateway": victimID,
		"the database's own gateway":    {TrustDomain: td, Org: group.OrgID, Kind: pki.KindGateway, ID: r.GatewayID},
		"another trust domain":          {TrustDomain: "other.rpmgr.internal", Org: other.ID, Kind: pki.KindGateway, ID: victimID.ID},
	} {
		plant(t, gwDir, planted)
		if err := h.runErr(t); err == nil || !strings.Contains(err.Error(), "no built-in gateway in service") {
			t.Errorf("%s: %v", name, err)
		}
		if n := db.Client().Gateway.Query().CountX(sys); n != before {
			t.Errorf("%s: %d gateways, want %d", name, n, before)
		}
		if n := db.Client().Gateway.Query().Where(gateway.Or(gateway.BuiltIn(true), gateway.DecommissionedAtNotNil())).CountX(sys); n != 0 {
			t.Errorf("%s: %d gateways marked built in or decommissioned", name, n)
		}
	}
}

// TestAllInOne_ReplacementFailsClosed (#599 review): a database error while the all-in-one looks for
// built-in agents whose identities are revoked stops the start, and changes nothing: no revision, no
// gateway or connector decommissioned or created, no token.
func TestAllInOne_ReplacementFailsClosed(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, _ := h.db(t)
	gateways, connectors := db.Client().Gateway.Query().CountX(sys), db.Client().Connector.Query().CountX(sys)
	tokens, revisions := db.Client().EnrollmentToken.Query().CountX(sys), db.Client().ConfigRevision.Query().CountX(sys)
	ctx := context.Background()
	if _, err := db.Writer.ExecContext(ctx, "ALTER TABLE revoked_identities RENAME TO revoked_identities_gone"); err != nil {
		t.Fatal(err)
	}
	if err := allinone.Prepare(ctx, h.cfg); err == nil || !strings.Contains(err.Error(), "revoked_identities") {
		t.Errorf("Prepare with the revoked identities unreadable: %v", err)
	}
	if _, err := db.Writer.ExecContext(ctx, "ALTER TABLE revoked_identities_gone RENAME TO revoked_identities"); err != nil {
		t.Fatal(err)
	}
	if g, c := db.Client().Gateway.Query().CountX(sys), db.Client().Connector.Query().CountX(sys); g != gateways || c != connectors {
		t.Errorf("%d gateways and %d connectors after the failure, want %d and %d", g, c, gateways, connectors)
	}
	if n, m := db.Client().EnrollmentToken.Query().CountX(sys), db.Client().ConfigRevision.Query().CountX(sys); n != tokens || m != revisions {
		t.Errorf("%d tokens and %d revisions after the failure, want %d and %d", n, m, tokens, revisions)
	}
	if g := db.Client().Gateway.GetX(sys, r.GatewayID); g.DecommissionedAt != nil || !g.BuiltIn {
		t.Errorf("the built-in gateway after the failure: %+v", g)
	}
}
