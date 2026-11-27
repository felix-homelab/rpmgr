// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// fleet is what seedFleet records in a host's database: agents of each kind and certificates in each state.
type fleet struct {
	org                  string
	gateway, connector   string // the agents that get a token
	builtInGateway       string
	builtInConn, ephConn string
	goneConn             string
	liveCert, expired    string // serials of an unrevoked certificate and an expired one
	revokedCert          string
	unusedToken          string // the ID of an enrollment token nobody has used
}

// seedFleet records agents and certificates in the database of h, which holds no controller.
func seedFleet(t *testing.T, h host) fleet {
	t.Helper()
	ctx := context.Background()
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	now := time.Now()
	f := fleet{org: storetest.Org(t, db, "org-a")}
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		grp := tx.GatewayGroup.Create().SetOrgID(f.org).SetName("edge").SaveX(sys)
		gw := tx.Gateway.Create().SetOrgID(f.org).SetGatewayGroupID(grp.ID).SetName("gw-1").SetTunnelEndpoints([]string{"gw.example.com:443"}).SaveX(sys)
		f.gateway = gw.ID
		f.builtInGateway = tx.Gateway.Create().SetOrgID(f.org).SetGatewayGroupID(grp.ID).SetName("gw-2").SetTunnelEndpoints([]string{"x:1"}).
			SetBuiltIn(true).SaveX(sys).ID
		con := func(name string, set func(*ent.ConnectorCreate)) string {
			id := ids.New("con")
			c := tx.Connector.Create().SetID(id).SetOrgID(f.org).SetName(name).SetSpiffeID("spiffe://x/" + id).SetPubkeySha256("00")
			if set != nil {
				set(c)
			}
			c.ExecX(sys)
			return id
		}
		f.connector = con("site-a", nil)
		f.builtInConn = con("local", func(c *ent.ConnectorCreate) { c.SetBuiltIn(true) })
		f.ephConn = con("job-1", func(c *ent.ConnectorCreate) { c.SetEphemeral(true) })
		f.goneConn = con("old", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(now.Add(-time.Hour)) })
		cert := func(notAfter time.Time, revoked bool) string {
			id := ids.New("ser")
			c := tx.IssuedCertificate.Create().SetID(id).SetOrgID(f.org).SetSubjectType("connector").SetSubjectID(f.connector).
				SetSpiffeID("spiffe://x/" + f.connector).SetPubkeySha256("00").SetNotBefore(now.Add(-48 * time.Hour)).SetNotAfter(notAfter)
			if revoked {
				c.SetRevokedAt(now.Add(-time.Hour)).SetRevocationReason("key_compromise")
			}
			c.ExecX(sys)
			return id
		}
		f.liveCert, f.expired, f.revokedCert = cert(now.Add(time.Hour), false), cert(now.Add(-time.Hour), false), cert(now.Add(time.Hour), true)
		tok, err := token.New(token.Enrollment)
		if err != nil {
			return err
		}
		f.unusedToken = tx.EnrollmentToken.Create().SetOrgID(f.org).SetRole("connector").SetTokenHash(token.Hash(tok)).
			SetExpiresAt(now.Add(time.Hour)).SetCreatedBy("usr_x").SaveX(sys).ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// caRows reads the CA's keys of the database of h: how many each status holds, and how many of the key
// columns still hold a sealed key.
func caRows(t *testing.T, h host) (status map[cakey.Status]int, sealed int) {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	status = map[cakey.Status]int{}
	for _, r := range db.Client().CAKey.Query().AllX(storetest.SystemCtx(t)) {
		status[r.Status]++
		if r.KeyEnc != nil && len(*r.KeyEnc) > 0 {
			sealed++
		}
	}
	return status, sealed
}

// compromiseState is what a replacement changes or leaves: the CA's keys, the revoked certificates and the
// enrollment tokens, as one comparable string.
func compromiseState(t *testing.T, h host) string {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	var b strings.Builder
	for _, r := range db.Client().CAKey.Query().Order(ent.Asc(cakey.FieldID)).AllX(sys) {
		b.WriteString(r.ID + string(r.Status) + "|")
	}
	b.WriteString(strings.Repeat("c", db.Client().IssuedCertificate.Query().Where(issuedcertificate.RevokedAtNotNil()).CountX(sys)))
	b.WriteString(strings.Repeat("t", db.Client().EnrollmentToken.Query().CountX(sys)))
	b.WriteString(strings.Repeat("u", db.Client().EnrollmentToken.Query().Where(enrollmenttoken.RevokedAtIsNil()).CountX(sys)))
	return b.String()
}

func compromiseOpts(h host, out string) controller.CompromiseOptions {
	return controller.CompromiseOptions{ConfigPath: h.cfg, TokensOut: out, Getenv: noEnv}
}

// TestReplaceCompromisedRoot: the replacement ends every old CA key and wipes its sealed key, makes new
// active keys in the same trust domain, revokes every unexpired certificate that was not revoked (and
// touches no other), invalidates the unused token, writes one token per connector and gateway that is
// not built in, ephemeral or decommissioned into a file of mode 0600, records the audit entry of every
// chain with a checkpoint of the new key, logs the marker last, and leaves no token anywhere but the file.
func TestReplaceCompromisedRoot(t *testing.T) {
	ctx := context.Background()
	h, init := initHost(t)
	f := seedFleet(t, h)
	out := filepath.Join(t.TempDir(), "tokens")
	res, err := controller.ReplaceCompromisedRoot(ctx, compromiseOpts(h, out))
	if err != nil {
		t.Fatal(err)
	}
	if res.Pin == "" || res.Pin == init.RootPin {
		t.Fatalf("pin %q, old %q: want a new one", res.Pin, init.RootPin)
	}
	if res.Keys != 4 || res.Certificates != 1 || res.InvalidatedTokens != 1 || res.Connectors != 1 || res.Gateways != 1 || res.Skipped != 3 {
		t.Fatalf("result %+v", res)
	}

	status, sealed := caRows(t, h)
	if status[cakey.StatusCompromised] != 4 || status[cakey.StatusActive] != 4 || len(status) != 2 || sealed != 4 {
		t.Fatalf("CA keys by status %v, %d sealed: want 4 compromised and wiped, 4 active and sealed", status, sealed)
	}
	if st, err := controller.CAStatus(ctx, h.cfg); err != nil || st.GetRootPin() != res.Pin {
		t.Fatalf("status pin %q, %v; want the new root's", st.GetRootPin(), err)
	}

	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	cert := func(id string) *ent.IssuedCertificate { return db.Client().IssuedCertificate.GetX(sys, id) }
	if c := cert(f.liveCert); c.RevokedAt == nil || c.RevocationReason != castore.ReasonCACompromised {
		t.Errorf("the live certificate: %+v", c)
	}
	if c := cert(f.expired); c.RevokedAt != nil {
		t.Errorf("an expired certificate was revoked: %+v", c)
	}
	if c := cert(f.revokedCert); c.RevocationReason != "key_compromise" {
		t.Errorf("a certificate revoked before lost its reason: %+v", c)
	}
	if db.Client().EnrollmentToken.GetX(sys, f.unusedToken).RevokedAt == nil {
		t.Error("the unused token was not invalidated")
	}

	// The tokens file: mode 0600, one line per connector and gateway, each a valid single-use token bound
	// to its agent, no other token.
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("tokens file: %v, %v", st, err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var toks []string
	bound := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		fs := strings.Split(l, "\t")
		if len(fs) != 5 || !strings.HasPrefix(fs[4], "rpmgr_enr_") {
			t.Fatalf("line %q", l)
		}
		bound[fs[0]+" "+fs[2]] = fs[4]
		toks = append(toks, fs[4])
	}
	if len(toks) != 2 || bound["gateway "+f.gateway] == "" || bound["connector "+f.connector] == "" {
		t.Fatalf("tokens of %v", bound)
	}
	for _, tok := range toks {
		row := db.Client().EnrollmentToken.Query().Where(enrollmenttoken.TokenHash(token.Hash(tok))).OnlyX(sys)
		if row.RevokedAt != nil || row.UseCount != 0 || row.MaxUses == nil || *row.MaxUses != 1 || row.Ephemeral || row.BuiltIn || row.CreatedBy != "local-cli" ||
			row.ExpiresAt.Sub(time.Now().Add(controller.DefaultCompromiseTokenTTL)).Abs() > time.Minute {
			t.Errorf("token row %+v: want a fresh single-use token that lasts the default", row)
		}
		if (row.GatewayID == nil) == (row.ConnectorID == nil) {
			t.Errorf("a token bound to neither one agent nor both: %+v", row)
		}
	}
	// No token is in the database, the revocation log, the audit log or the result: only hashes are stored.
	dbFile, err := os.ReadFile(h.db)
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.ReadFile(filepath.Join(filepath.Dir(h.db), "revocations.log"))
	if err != nil {
		t.Fatal(err)
	}
	audits := ""
	for _, e := range db.Client().AuditEntry.Query().AllX(sys) {
		audits += e.Reason + e.Diff + e.TargetID
	}
	for _, tok := range toks {
		for what, hay := range map[string]string{"database": string(dbFile), "revocation log": string(logFile), "audit log": audits, "result": res.Pin + strings.Join(res.Warnings, "")} {
			if strings.Contains(hay, tok) {
				t.Errorf("a token is in the %s", what)
			}
		}
	}

	// The audit entry is in the instance chain and the org's, and a checkpoint of the new key anchors both.
	entries := db.Client().AuditEntry.Query().Where(auditentry.Action("ca.root_compromised")).AllX(sys)
	if len(entries) != 1 {
		t.Fatalf("%d audit entries of the replacement, want one in the instance chain (the org has no entries yet)", len(entries))
	}
	if n := db.Client().AuditEntry.Query().Where(auditentry.ActorID("local-cli")).CountX(sys); n == 0 {
		t.Error("no audit entry of local-cli")
	}

	// `ca status` warns of the agents that have not enrolled again, until each holds a certificate that is valid.
	warns, err := controller.CAStatusWarnings(ctx, h.cfg)
	if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "2 connector(s) and gateway(s) have not enrolled again") ||
		!strings.Contains(warns[0], f.gateway) || !strings.Contains(warns[0], f.connector) {
		t.Fatalf("status warnings %q, %v", warns, err)
	}
	for _, id := range []string{f.gateway, f.connector} {
		typ := map[bool]string{true: "gateway", false: "connector"}[id == f.gateway]
		db.Client().IssuedCertificate.Create().SetID(ids.New("ser")).SetOrgID(f.org).SetSubjectType(issuedcertificate.SubjectType(typ)).SetSubjectID(id).
			SetSpiffeID("spiffe://x/" + id).SetPubkeySha256("00").SetNotBefore(time.Now()).SetNotAfter(time.Now().Add(time.Hour)).ExecX(sys)
	}
	if warns, err := controller.CAStatusWarnings(ctx, h.cfg); err != nil || len(warns) != 0 {
		t.Fatalf("status warnings after both enrolled again: %q, %v", warns, err)
	}

	// The marker is logged for each root that was in service, naming the new root.
	marks := rootMarkers(t, filepath.Join(filepath.Dir(h.db), "revocations.log"))
	if len(marks) != 1 || marks[0].Kind != revlog.RootCompromised || marks[0].Subject == "" || marks[0].Detail == "" || marks[0].Subject == marks[0].Detail {
		t.Fatalf("markers %+v", marks)
	}
	if want := pki.PublicKeyHash(db.Client().CAKey.Query().Where(cakey.StatusEQ(cakey.StatusActive), cakey.KindEQ(cakey.KindRoot)).OnlyX(sys).PublicKey); marks[0].Detail != want {
		t.Errorf("the marker names %s as the new root, want %s", marks[0].Detail, want)
	}
}

// TestReplaceCompromisedRoot_Refusals: a replacement that is refused changes nothing: no tokens file, an
// existing one, a lifetime beyond the longest, and a controller that runs.
func TestReplaceCompromisedRoot_Refusals(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	seedFleet(t, h)
	before := compromiseState(t, h)
	dir := t.TempDir()
	existing := filepath.Join(dir, "tokens")
	if err := os.WriteFile(existing, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	long := compromiseOpts(h, filepath.Join(dir, "long"))
	long.TokenTTL = enroll.MaxTokenTTL + time.Hour
	neg := compromiseOpts(h, filepath.Join(dir, "neg"))
	neg.TokenTTL = -time.Hour
	for name, o := range map[string]controller.CompromiseOptions{
		"no file":        compromiseOpts(h, ""),
		"existing file":  compromiseOpts(h, existing),
		"no directory":   compromiseOpts(h, filepath.Join(dir, "missing", "tokens")),
		"too long":       long,
		"negative":       neg,
		"another config": {ConfigPath: filepath.Join(dir, "none.yaml"), TokensOut: filepath.Join(dir, "x"), Getenv: noEnv},
	} {
		if _, err := controller.ReplaceCompromisedRoot(ctx, o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if b, err := os.ReadFile(existing); err != nil || string(b) != "keep me" {
		t.Errorf("the existing file: %q, %v", b, err)
	}
	for _, n := range []string{"long", "neg", "x", "missing"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s was created by a refused run", n)
		}
	}
	// A running controller holds the lock.
	unlock, err := store.HoldLock(h.db)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "running")
	_, err = controller.ReplaceCompromisedRoot(ctx, compromiseOpts(h, out))
	_ = unlock()
	if !errors.Is(err, controller.ErrStopController) {
		t.Fatalf("with a controller running: %v, want ErrStopController", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a file was written beside a running controller")
	}
	if after := compromiseState(t, h); after != before {
		t.Fatalf("a refused run changed the state:\n%s\n%s", before, after)
	}
	if marks := rootMarkers(t, filepath.Join(filepath.Dir(h.db), "revocations.log")); len(marks) != 0 {
		t.Fatalf("a refused run logged markers %+v", marks)
	}
}

// TestReplaceCompromisedRoot_RestoreRefusesOlderArchives: a backup from before the replacement would bring
// the compromised root back as the issuing one, so the restore refuses it and changes nothing, whether the
// marker is in the log given or only the host's; a backup taken after restores. A second replacement makes
// the first one's backup refuse too.
func TestReplaceCompromisedRoot_RestoreRefusesOlderArchives(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	seedFleet(t, h)
	before := backupOf(t, h)
	if _, err := controller.ReplaceCompromisedRoot(ctx, compromiseOpts(h, filepath.Join(t.TempDir(), "tokens"))); err != nil {
		t.Fatal(err)
	}
	after := backupOf(t, h)
	state := compromiseState(t, h)
	_, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: before})
	if !errors.Is(err, controller.ErrOlderThanRootChange) || !strings.Contains(err.Error(), "compromised") {
		t.Fatalf("a restore from before the replacement = %v", err)
	}
	if got := compromiseState(t, h); got != state {
		t.Fatalf("the refused restore changed the state")
	}
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: after}); err != nil {
		t.Fatalf("a restore from after it: %v", err)
	}
	// The restored database still holds the compromised keys as such and issues under the new root alone.
	if status, sealed := caRows(t, h); status[cakey.StatusCompromised] != 4 || status[cakey.StatusActive] != 4 || sealed != 4 {
		t.Fatalf("after the restore: %v, %d sealed", status, sealed)
	}
	// A second replacement, of the new root, and a restore of the archive taken between the two.
	if _, err := controller.ReplaceCompromisedRoot(ctx, compromiseOpts(h, filepath.Join(t.TempDir(), "tokens2"))); err != nil {
		t.Fatal(err)
	}
	_, err = controller.Restore(ctx, controller.RestoreOptions{ConfigPath: h.cfg, Archive: after})
	if !errors.Is(err, controller.ErrOlderThanRootChange) {
		t.Fatalf("a restore from between two replacements = %v", err)
	}
}
