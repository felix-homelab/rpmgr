// SPDX-License-Identifier: Apache-2.0

package allinone_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedidentity"
)

// TestAllInOne_RecoversItsGateway (#555): Run enrolls the built-in gateway again, as the same
// gateway and before it runs, when its identity is missing, as after a restore on a new host, and
// when the database does not know its certificate, as after a restore of a backup older than the
// certificate. Each enrollment revokes the certificate it replaces and leaves an audit entry with
// the reason; a plain restart enrolls nothing, and the API still makes no token for the gateway.
func TestAllInOne_RecoversItsGateway(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, _ := h.db(t)
	identity := h.cfg.Gateway().IdentityDir
	serial := func() string {
		t.Helper()
		id, err := agent.Load(identity)
		if err != nil {
			t.Fatal(err)
		}
		if id.AgentID != r.GatewayID {
			t.Fatalf("the gateway enrolled as %s, want %s", id.AgentID, r.GatewayID)
		}
		return pki.SerialHex(id.Certificate.Leaf.SerialNumber)
	}
	tokens := func() int {
		return db.Client().EnrollmentToken.Query().Where(enrollmenttoken.RoleEQ(enrollmenttoken.RoleGateway)).CountX(sys)
	}
	reasons := func() []string {
		var out []string
		for _, e := range db.Client().AuditEntry.Query().Where(auditentry.Action("enrollment_token.create")).AllX(sys) {
			if strings.HasPrefix(e.Reason, "all-in-one's own gateway: ") {
				out = append(out, strings.TrimPrefix(e.Reason, "all-in-one's own gateway: "))
			}
		}
		return out
	}
	first := serial()
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := db.VacuumInto(context.Background(), backup); err != nil {
		t.Fatal(err)
	}

	// A restore on a new host: no identity.
	if err := os.RemoveAll(identity); err != nil {
		t.Fatal(err)
	}
	stop := h.run(t)
	waitFor(t, "not ready without the gateway's identity", h.ready)
	stop()
	second := serial()
	if second == first || tokens() != 2 {
		t.Fatalf("serial %s after %s, %d gateway tokens", second, first, tokens())
	}
	if c := db.Client().IssuedCertificate.GetX(sys, first); c.RevokedAt == nil {
		t.Error("the replaced certificate is not revoked")
	}
	if got := reasons(); len(got) != 1 || got[0] != "its identity is missing" {
		t.Errorf("audit reasons %q", got)
	}

	// A plain restart enrolls nothing.
	h.run(t)()
	if serial() != second || tokens() != 2 {
		t.Fatalf("a plain restart enrolled the gateway again: %d gateway tokens", tokens())
	}

	// The API makes no token for the built-in gateway, which only all-in-one enrolls.
	org := db.Client().Gateway.GetX(sys, r.GatewayID).OrgID
	tx, err := db.Client().Tx(sys)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = enroll.MintToken(sys, tx, enroll.Mint{Org: org, GatewayID: r.GatewayID}, time.Now())
	_ = tx.Rollback()
	if !errors.Is(err, enroll.ErrBuiltIn) {
		t.Errorf("a token for the built-in gateway through the API: %v", err)
	}

	// A restore of the older backup: the database does not know the gateway's certificate.
	_ = db.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(h.cfg.Database.DSN + suffix); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(backup) //nolint:gosec // G304: the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.cfg.Database.DSN, data, 0o600); err != nil { //nolint:gosec // G703: the test's own database path
		t.Fatal(err)
	}
	stop = h.run(t)
	waitFor(t, "not ready after the restore of an older backup", h.ready)
	stop()
	db, sys, _ = h.db(t)
	third := serial()
	if third == second || third == first {
		t.Fatalf("the gateway kept the certificate %s the database does not know", third)
	}
	// The enrollment revokes the certificate the restored database records, the backup's; the one
	// issued after the backup, which it does not record, stays valid until it expires.
	if c := db.Client().IssuedCertificate.GetX(sys, first); c.RevokedAt == nil {
		t.Error("the backup's certificate is not revoked")
	}
	if got := reasons(); len(got) != 1 || !strings.HasPrefix(got[0], "its certificate cannot be renewed: ") {
		t.Errorf("audit reasons after the restore %q", got)
	}
}

// TestAllInOne_UnusableIdentity (#555): an agent's identity is unusable when it is missing, names
// another agent, its certificate is revoked or superseded, or it expired longer ago than the grace
// period; it stays in use within the grace period. A revoked identity of the agent itself is an
// error, which stops the start: enrolling again as the same agent cannot lift it.
func TestAllInOne_UnusableIdentity(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, group := h.db(t)
	identity := h.cfg.Gateway().IdentityDir
	id, err := agent.Load(identity)
	if err != nil {
		t.Fatal(err)
	}
	want := pki.Identity{TrustDomain: id.TrustDomain, Org: group.OrgID, Kind: pki.KindGateway, ID: r.GatewayID}
	other := want
	other.ID = "gw_other"
	notAfter, grace := id.Certificate.Leaf.NotAfter, 24*time.Hour
	for name, tc := range map[string]struct {
		dir   string
		want  pki.Identity
		now   time.Time
		match string
	}{
		"in use":                 {identity, want, time.Now(), ""},
		"within the grace":       {identity, want, notAfter.Add(grace - time.Minute), ""},
		"beyond the grace":       {identity, want, notAfter.Add(grace + time.Minute), "its certificate expired at "},
		"a missing identity":     {filepath.Join(t.TempDir(), "none"), want, time.Now(), "its identity is missing"},
		"another gateway's":      {identity, other, time.Now(), "its identity names another agent"},
		"a connector's":          {h.cfg.Connector().IdentityDir, want, time.Now(), "its identity names another agent"},
		"another trust domain's": {identity, pki.Identity{TrustDomain: "other.rpmgr.internal", Org: want.Org, Kind: want.Kind, ID: want.ID}, time.Now(), "its identity names another agent"},
	} {
		got, err := allinone.Unusable(sys, db.Client(), tc.dir, tc.want, tc.now, grace)
		if err != nil || (tc.match == "") != (got == "") || !strings.HasPrefix(got, tc.match) {
			t.Errorf("%s: %q %v, want %q", name, got, err, tc.match)
		}
	}
	serial := pki.SerialHex(id.Certificate.Leaf.SerialNumber)
	for name, edit := range map[string]func(){
		"a superseded certificate": func() { db.Client().IssuedCertificate.UpdateOneID(serial).SetSupersededAt(time.Now()).ExecX(sys) },
		"a revoked certificate":    func() { db.Client().IssuedCertificate.UpdateOneID(serial).SetRevokedAt(time.Now()).ExecX(sys) },
	} {
		edit()
		if got, err := allinone.Unusable(sys, db.Client(), identity, want, time.Now(), grace); err != nil || !strings.HasPrefix(got, "its certificate cannot be renewed: ") {
			t.Errorf("%s: %q %v", name, got, err)
		}
		db.Client().IssuedCertificate.UpdateOneID(serial).ClearSupersededAt().ClearRevokedAt().ExecX(sys)
	}
	revokeIdentity(t, db, sys, want)
	if got, err := allinone.Unusable(sys, db.Client(), identity, want, time.Now(), grace); err == nil || !strings.Contains(err.Error(), "is revoked") {
		t.Errorf("a revoked identity: %q %v", got, err)
	}
}

// revokeIdentity revokes an identity in the database.
func revokeIdentity(t *testing.T, db *store.DB, sys context.Context, id pki.Identity) {
	t.Helper()
	db.Client().RevokedIdentity.Create().SetID(id.String()).SetSubjectType(revokedidentity.SubjectType(id.Kind)).SetSubjectID(id.ID).
		SetOrgID(id.Org).SetRevokedAt(time.Now()).SetReason("test").SetNotAfter(time.Now().Add(time.Hour)).ExecX(sys)
}

// runErr runs the installation once and returns why Run stopped before it listened.
func (h *host) runErr(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return allinone.Run(ctx, allinone.RunOptions{Config: h.cfg, Getenv: func(string) string { return "" },
		Listening: func() { t.Error("Run started") }})
}

// TestAllInOne_RecoveryRefuses (#555): the start stops, enrolling nothing, when the built-in
// gateway's identity is revoked, when the built-in gateway was decommissioned, and when the
// database is missing, which Run never creates.
func TestAllInOne_RecoveryRefuses(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, group := h.db(t)
	id, err := agent.Load(h.cfg.Gateway().IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := func() int { return db.Client().EnrollmentToken.Query().CountX(sys) }
	before := tokens()
	revokeIdentity(t, db, sys, pki.Identity{TrustDomain: id.TrustDomain, Org: group.OrgID, Kind: pki.KindGateway, ID: r.GatewayID})
	if err := h.runErr(t); err == nil || !strings.Contains(err.Error(), "identity "+r.GatewayID+" is revoked") || tokens() != before {
		t.Errorf("a revoked identity: %v, %d tokens after %d", err, tokens(), before)
	}
	db.Client().RevokedIdentity.Delete().ExecX(sys)

	db.Client().Gateway.UpdateOneID(r.GatewayID).SetDecommissionedAt(time.Now()).ExecX(sys)
	if err := h.runErr(t); err == nil || !strings.Contains(err.Error(), "no built-in gateway in service") {
		t.Errorf("a decommissioned built-in gateway: %v", err)
	}
	db.Client().Gateway.UpdateOneID(r.GatewayID).ClearDecommissionedAt().ExecX(sys)

	_ = db.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(h.cfg.Database.DSN + suffix); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := h.runErr(t); err == nil || !strings.Contains(err.Error(), "rpmgr all-in-one init") {
		t.Errorf("an installed host without its database: %v", err)
	}
	if _, err := os.Stat(h.cfg.Database.DSN); !os.IsNotExist(err) {
		t.Errorf("Run created %s: %v", h.cfg.Database.DSN, err)
	}
}

// TestAllInOne_RecoversFromForeignIdentities (#555): the identities count by their certificates,
// not by agent.json: a gateway identity whose agent.json names another, ordinary gateway enrolls
// again as the built-in one, leaving the other alone, and a connector's identity in the gateway's
// place is replaced. A connector whose certificate cannot be renewed enrolls again as itself.
func TestAllInOne_RecoversFromForeignIdentities(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	db, sys, group := h.db(t)
	gwDir, conDir := h.cfg.Gateway().IdentityDir, h.cfg.Connector().IdentityDir
	remote := db.Client().Gateway.Create().SetOrgID(group.OrgID).SetGatewayGroupID(group.ID).SetName("remote").
		SetTunnelEndpoints([]string{"gw2.example.com:443"}).SaveX(sys)
	// agent.json names the remote gateway; the certificate is the built-in one's, now revoked.
	path := filepath.Join(gwDir, "agent.json")
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(b), r.GatewayID, remote.ID)), 0o600); err != nil { //nolint:gosec // G703: the test's own file
		t.Fatal(err)
	}
	gw, err := agent.Load(gwDir)
	if err != nil {
		t.Fatal(err)
	}
	db.Client().IssuedCertificate.UpdateOneID(pki.SerialHex(gw.Certificate.Leaf.SerialNumber)).SetRevokedAt(time.Now()).ExecX(sys)
	con, err := agent.Load(conDir)
	if err != nil {
		t.Fatal(err)
	}
	conSerial := pki.SerialHex(con.Certificate.Leaf.SerialNumber)
	db.Client().IssuedCertificate.UpdateOneID(conSerial).SetRevokedAt(time.Now()).ExecX(sys)

	stop := h.run(t)
	waitFor(t, "not ready", h.ready)
	stop()
	if id, err := agent.ReadIdentity(gwDir); err != nil || id.AgentID != r.GatewayID {
		t.Fatalf("the gateway enrolled as %+v, %v; want %s", id, err, r.GatewayID)
	}
	if g := db.Client().Gateway.GetX(sys, remote.ID); g.BuiltIn || g.SpiffeID != "" {
		t.Errorf("the remote gateway was taken over: %+v", g)
	}
	if n := db.Client().Gateway.Query().Where(gateway.BuiltIn(true)).CountX(sys); n != 1 {
		t.Errorf("%d built-in gateways", n)
	}
	con2, err := agent.Load(conDir)
	if err != nil || con2.AgentID != r.ConnectorID || pki.SerialHex(con2.Certificate.Leaf.SerialNumber) == conSerial {
		t.Fatalf("the connector: %+v %v", con2.Identity, err)
	}

	// A connector's identity in the gateway's place is replaced; the connector keeps its own.
	if err := os.RemoveAll(gwDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(gwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(conDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(conDir, f.Name())) //nolint:gosec // G304: the test's own files
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(gwDir, f.Name()), b, 0o600); err != nil { //nolint:gosec // G703: the test's own files
			t.Fatal(err)
		}
	}
	stop = h.run(t)
	waitFor(t, "not ready with a connector's identity in the gateway's place", h.ready)
	stop()
	if id, err := agent.ReadIdentity(gwDir); err != nil || id.AgentID != r.GatewayID {
		t.Fatalf("the gateway enrolled as %+v, %v; want %s", id, err, r.GatewayID)
	}
	if id, err := agent.ReadIdentity(conDir); err != nil || id.AgentID != r.ConnectorID {
		t.Fatalf("the connector: %+v %v", id, err)
	}
}
