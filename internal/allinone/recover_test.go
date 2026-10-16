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
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
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
	if c := db.Client().IssuedCertificate.GetX(sys, first); c.RevokedAt == nil {
		t.Error("the backup's certificate is not revoked")
	}
	if got := reasons(); len(got) != 1 || !strings.HasPrefix(got[0], "its certificate cannot be renewed: ") {
		t.Errorf("audit reasons after the restore %q", got)
	}
}

// TestAllInOne_UnusableIdentity (#555): an agent's identity is unusable when it is missing, its
// certificate is revoked, or it expired longer ago than the grace period; it stays in use within
// the grace period.
func TestAllInOne_UnusableIdentity(t *testing.T) {
	h := newHost(t)
	h.init(t)
	db, sys, _ := h.db(t)
	identity := h.cfg.Gateway().IdentityDir
	id, err := agent.Load(identity)
	if err != nil {
		t.Fatal(err)
	}
	notAfter, grace := id.Certificate.Leaf.NotAfter, 24*time.Hour
	for name, tc := range map[string]struct {
		dir  string
		now  time.Time
		want string
	}{
		"in use":             {identity, time.Now(), ""},
		"within the grace":   {identity, notAfter.Add(grace - time.Minute), ""},
		"beyond the grace":   {identity, notAfter.Add(grace + time.Minute), "its certificate expired at "},
		"a missing identity": {filepath.Join(t.TempDir(), "none"), time.Now(), "its identity is missing"},
	} {
		got, err := allinone.Unusable(sys, db.Client(), tc.dir, tc.now, grace)
		if err != nil || (tc.want == "") != (got == "") || !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: %q %v, want %q", name, got, err, tc.want)
		}
	}
	db.Client().IssuedCertificate.UpdateOneID(pki.SerialHex(id.Certificate.Leaf.SerialNumber)).SetRevokedAt(time.Now()).ExecX(sys)
	if got, err := allinone.Unusable(sys, db.Client(), identity, time.Now(), grace); err != nil || !strings.HasPrefix(got, "its certificate cannot be renewed: ") {
		t.Errorf("a revoked certificate: %q %v", got, err)
	}
}

// TestAllInOne_NeedsItsDatabase: Run refuses to start on a host that holds no installation, rather
// than create an empty database, whatever the agents' identities.
func TestAllInOne_NeedsItsDatabase(t *testing.T) {
	h := newHost(t)
	if err := config.Load(h.boot, &h.cfg); err != nil {
		t.Fatal(err)
	}
	err := allinone.Run(context.Background(), allinone.RunOptions{Config: h.cfg, Getenv: func(string) string { return "" }})
	if err == nil || !strings.Contains(err.Error(), "rpmgr all-in-one init") {
		t.Fatalf("Run without a database: %v", err)
	}
	if _, err := os.Stat(h.cfg.Database.DSN); !os.IsNotExist(err) {
		t.Errorf("Run created %s: %v", h.cfg.Database.DSN, err)
	}
}
