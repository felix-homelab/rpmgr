// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const rotationDay = 24 * time.Hour

// newRootOnline runs `ca new-root` against the env's database: planned outside a transaction, applied in a
// configuration transaction as the command does.
func (e *sessionEnv) newRootOnline(t *testing.T, at time.Time) {
	t.Helper()
	plan, err := castore.PlanNewRoot(e.sys, e.db.ReadClient().CAKey, e.sealer, at)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Config() {
		t.Fatal("a rotation that moves issuing is not a configuration change")
	}
	if _, err := store.ConfigTx(e.sys, e.db, func(tx *ent.Tx) ([]string, error) {
		_, err := plan.Apply(e.sys, tx)
		return []string{"pki"}, err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ca.Reload(e.sys, e.db, e.sealer, func() time.Time { return at }); err != nil {
		t.Fatal(err)
	}
}

// fleetAgent records an agent of the env's org, enabled or not, with a session last seen at seen that
// reported the roots digest of roots.
func (e *sessionEnv) fleetAgent(t *testing.T, enabled bool, seen time.Time, digest []byte, decommissioned bool) string {
	t.Helper()
	id := ids.New("con")
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		c := tx.Connector.Create().SetID(id).SetOrgID(e.org).SetName("con-" + strings.ToLower(id[len(id)-6:])).SetSpiffeID("spiffe://x/" + id).
			SetPubkeySha256("00").SetEnabled(enabled)
		if decommissioned {
			c.SetDecommissionedAt(seen)
		}
		if err := c.Exec(e.sys); err != nil {
			return err
		}
		d := ""
		if digest != nil {
			d = hex.EncodeToString(digest)
		}
		return tx.AgentSession.Create().SetID(id).SetOrgID(e.org).SetSessionEpoch(1).SetControllerNode("ctn_test").SetLastSeenAt(seen).
			SetConnectedAt(seen).SetRootsDigest(d).Exec(e.sys)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestStragglers: an enabled agent seen since the overlap began that does not hold the new root, as its
// Hello digest says, is a straggler; one that holds it, alone or with the old root, is not, nor is one that
// is disabled, decommissioned or was not seen since.
func TestStragglers(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	r1 := e.ca.Root()
	at := time.Now()
	e.newRootOnline(t, at)
	r2 := e.ca.Root()
	since := at
	seen := at.Add(time.Hour)

	both := pki.RootsDigest([]*x509.Certificate{r1, r2})
	only2 := pki.RootsDigest([]*x509.Certificate{r2})
	only1 := pki.RootsDigest([]*x509.Certificate{r1})
	_ = e.fleetAgent(t, true, seen, both, false)
	_ = e.fleetAgent(t, true, seen, only2, false)
	old := e.fleetAgent(t, true, seen, only1, false)
	noCap := e.fleetAgent(t, true, seen, nil, false) // an agent without "trust.roots" never learns it
	_ = e.fleetAgent(t, false, seen, only1, false)   // disabled
	_ = e.fleetAgent(t, true, seen, only1, true)     // decommissioned
	_ = e.fleetAgent(t, true, since.Add(-time.Hour), only1, false)

	var got []string
	if err := store.ReadTx(e.sys, e.db, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		got, err = controller.Stragglers(e.sys, tx, since)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{old, noCap}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("stragglers %v, want %v", got, want)
	}
}

// TestCARotationRootRotation: the rotation job moves issuing to the new root when both certificates of
// an offline old root are imported, as a configuration change that gets a revision, and drops the old
// root once the overlap has passed unless enabled agents still lack the new one, which it logs.
func TestCARotationRootRotation(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	leases := lease.New(db, "ctn_test", nil)
	at := time.Now()
	var logs bytes.Buffer
	o := controller.CAOptions{DB: db, CA: e.ca, Sealer: e.sealer, Leases: leases, Now: func() time.Time { return at },
		Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	run := func() {
		t.Helper()
		if err := runOnce(t, leases, controller.CARotation(o)); err != nil {
			t.Fatalf("job errors: %v", err)
		}
	}
	revisions := func() int { return e.db.Client().ConfigRevision.Query().CountX(e.sys) }
	r1 := e.ca.Root()

	// The old root goes offline; the new root's requests are signed on its host and imported.
	plan, err := castore.PlanRootExport(e.sys, db.ReadClient().CAKey, e.sealer)
	if err != nil {
		t.Fatal(err)
	}
	var file []byte
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error {
		_, err := plan.Apply(e.sys, tx, "correct horse battery staple 42", func(f []byte) ([]byte, error) { file = bytes.Clone(f); return f, nil })
		return err
	}); err != nil {
		t.Fatal(err)
	}
	offline, err := pki.OpenRootFile(file, "correct horse battery staple 42")
	if err != nil {
		t.Fatal(err)
	}
	rp, err := castore.PlanNewRoot(e.sys, db.ReadClient().CAKey, e.sealer, at)
	if err != nil || rp.Requests() == nil {
		t.Fatalf("new-root with an offline root: %v, %v", rp, err)
	}
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error { _, err := rp.Apply(e.sys, tx); return err }); err != nil {
		t.Fatal(err)
	}
	req := rp.Requests()
	x, err := pki.SignCrossRoot(offline, req.Cross, at)
	if err != nil {
		t.Fatal(err)
	}
	y, err := pki.SignIntermediate(offline, req.Intermediate, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*x509.Certificate{x, y} {
		if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error { return castore.ImportIntermediate(e.sys, tx, c.Raw, at) }); err != nil {
			t.Fatal(err)
		}
	}

	before := revisions()
	run()
	if e.ca.Root().Equal(r1) {
		t.Fatal("the job did not move issuing to the new root")
	}
	if revisions() != before+1 {
		t.Fatalf("%d revisions after the switch, want one more than %d: the bundle changed", revisions(), before)
	}
	if rev := e.db.Client().ConfigRevision.Query().Order(ent.Desc(configrevision.FieldID)).FirstX(e.sys); !slices.Equal(rev.ChangedResources, []string{"pki"}) {
		t.Fatalf("the revision changed %v", rev.ChangedResources)
	}
	// A snapshot compiled in a transaction reads the new bundle with its revision.
	var bundle [][]byte
	if err := store.ReadTx(e.sys, db, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		bundle, err = castore.TrustRootsOf(e.sys, tx.CAKey)
		return err
	}); err != nil || len(bundle) != 3 {
		t.Fatalf("the bundle of a snapshot holds %d certificates, %v; want {R1, R2, X}", len(bundle), err)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("ca.rotate"), auditentry.ActorID("ca-rotation")).CountX(e.sys); n < 2 {
		t.Fatalf("%d audit records of the switch", n)
	}

	// Within the overlap the job drops nothing.
	switchedAt := at
	at = switchedAt.Add(30 * rotationDay)
	run()
	if len(e.ca.Roots()) != 2 {
		t.Fatal("the job dropped the old root before the overlap had passed")
	}
	// After it, an enabled agent that was seen and lacks the new root holds the old root back.
	at = switchedAt.Add(38 * rotationDay)
	straggler := e.fleetAgent(t, true, at.Add(-rotationDay), pki.RootsDigest([]*x509.Certificate{r1}), false)
	logs.Reset()
	before = revisions()
	run()
	if len(e.ca.Roots()) != 2 || revisions() != before {
		t.Fatal("the job dropped the old root although an enabled agent lacks the new one")
	}
	if !strings.Contains(logs.String(), "root rotation stalled") {
		t.Fatalf("the stalled rotation was not logged:\n%s", logs.String())
	}
	// Decommissioned, it no longer holds the root back.
	if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error {
		return tx.Connector.UpdateOneID(straggler).SetDecommissionedAt(at).Exec(e.sys)
	}); err != nil {
		t.Fatal(err)
	}
	run()
	if got := e.ca.TrustBundle(); len(got) != 1 || !got[0].Equal(e.ca.Root()) {
		t.Fatalf("the bundle after the drop holds %d certificates", len(got))
	}
	if revisions() != before+1 {
		t.Fatal("the drop was no configuration change")
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("ca.drop_root"), auditentry.ActorID("ca-rotation")).CountX(e.sys); n != 1 {
		t.Fatalf("%d audit records of the drop", n)
	}
}

// TestRootRotationCommands: `ca new-root` and `ca drop-root` on a host with a controller database. The
// root is online: the new root issues at once, a second rotation and an early drop are refused with
// their reasons, and the status says where the rotation stands.
func TestRootRotationCommands(t *testing.T) {
	ctx := context.Background()
	h, init := initHost(t)
	now := time.Now()
	res, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if res.Pin == "" || res.Pin == init.RootPin || res.Requests != nil {
		t.Fatalf("new-root: pin %q (old %q), requests %v", res.Pin, init.RootPin, res.Requests)
	}
	// New agents keep enrolling with the old pin during the overlap, so that they hold both roots.
	if st, err := controller.CAStatus(ctx, h.cfg); err != nil || st.GetRootPin() != init.RootPin {
		t.Fatalf("status pin %q, %v; want the old root's during the overlap", st.GetRootPin(), err)
	}
	rs, err := controller.CARotationStatus(ctx, h.cfg, func() time.Time { return now })
	if err != nil || !rs.Overlap || len(rs.Roots) != 2 || !rs.Roots[0].Issuing || rs.Roots[1].Issuing || len(rs.Stragglers) != 0 {
		t.Fatalf("rotation status %+v, %v", rs, err)
	}
	if want := now.Add(37 * rotationDay); rs.DropAfter.Sub(want).Abs() > time.Minute {
		t.Fatalf("the old root can be dropped from %v, want about %v", rs.DropAfter, want)
	}
	if got := auditOf(t, h, "ca.new_root"); len(got) != 1 || !strings.HasPrefix(got[0], "local-cli|") {
		t.Fatalf("audit of new-root: %v", got)
	}

	if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); !errors.Is(err, castore.ErrRotationInProgress) {
		t.Fatalf("a second new-root = %v, want ErrRotationInProgress", err)
	}
	var early *castore.DropEarlyError
	if _, err := controller.DropRoot(ctx, h.cfg, false, false, func() time.Time { return now.Add(36 * rotationDay) }); !errors.As(err, &early) {
		t.Fatalf("an early drop = %v, want DropEarlyError", err)
	}
	if _, err := controller.DropRoot(ctx, h.cfg, false, false, func() time.Time { return now.Add(38 * rotationDay) }); err != nil {
		t.Fatalf("the drop after the overlap: %v", err)
	}
	if got := auditOf(t, h, "ca.drop_root"); len(got) != 1 {
		t.Fatalf("audit of the drop: %v", got)
	}
	if st, err := controller.CAStatus(ctx, h.cfg); err != nil || st.GetRootPin() != res.Pin {
		t.Fatalf("status pin %q, %v; want the new root's after the drop", st.GetRootPin(), err)
	}
	if _, err := controller.DropRoot(ctx, h.cfg, false, false, func() time.Time { return now.Add(38 * rotationDay) }); !errors.Is(err, castore.ErrNoRotation) {
		t.Fatalf("a second drop = %v, want ErrNoRotation", err)
	}
}

// TestRootRotationCommandsOffline: with the old root offline, `ca new-root` needs --csr-out and writes both
// requests, never over a file; the offline host signs the cross-certificate and the intermediate; the imports
// are checked; and the status says what waits, all without the old root's key in the database.
func TestRootRotationCommandsOffline(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.age")
	if _, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: h.cfg, Out: rootFile, Passphrase: suppliedPass, Getenv: noEnv}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	clock := func() time.Time { return now }
	if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, clock); !errors.Is(err, castore.ErrRootOffline) {
		t.Fatalf("new-root without --csr-out = %v, want ErrRootOffline", err)
	}
	csr := filepath.Join(dir, "r2.csr")
	if err := os.WriteFile(csr+controller.IntermediateSuffix, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.NewRoot(ctx, h.cfg, csr, noEnv, clock); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("new-root over an existing file = %v", err)
	}
	if err := os.Remove(csr + controller.IntermediateSuffix); err != nil {
		t.Fatal(err)
	}
	res, err := controller.NewRoot(ctx, h.cfg, csr, noEnv, clock)
	if err != nil || res.Requests == nil || res.Pin != "" {
		t.Fatalf("new-root --csr-out: %+v, %v", res, err)
	}
	for _, f := range []string{csr, csr + controller.IntermediateSuffix} {
		if b, err := os.ReadFile(f); err != nil || !bytes.Contains(b, []byte("CERTIFICATE REQUEST")) {
			t.Fatalf("%s: %v", f, err)
		}
	}
	rs, err := controller.CARotationStatus(ctx, h.cfg, clock)
	if err != nil || !rs.Waiting || rs.Overlap || !rs.NeedsCross || !rs.NeedsInter || len(rs.KeyHashes) != 2 {
		t.Fatalf("status of a rotation that waits: %+v, %v", rs, err)
	}

	sign := func(in string, cross bool, hash string) string {
		out := filepath.Join(dir, filepath.Base(in)+".crt")
		if _, err := controller.SignIntermediate(controller.SignOptions{RootFile: rootFile, CSR: in, Out: out, Passphrase: suppliedPass,
			CrossRoot: cross, KeyHash: hash, Now: clock}); err != nil {
			t.Fatalf("signing %s: %v", in, err)
		}
		return out
	}
	// A request for an intermediate is not a cross-root request and the other way round: the hash
	// check names the request the operator means.
	if _, err := controller.SignIntermediate(controller.SignOptions{RootFile: rootFile, CSR: csr, Out: filepath.Join(dir, "bad.crt"), Passphrase: suppliedPass,
		CrossRoot: true, KeyHash: res.Requests.InterKeyHash, Now: clock}); err == nil {
		t.Fatal("signed a request with another key than the one named")
	}
	xFile := sign(csr, true, res.Requests.CrossKeyHash)
	yFile := sign(csr+controller.IntermediateSuffix, false, res.Requests.InterKeyHash)
	for _, f := range []string{xFile, yFile} {
		if _, err := controller.ImportIntermediate(ctx, h.cfg, f, clock); err != nil {
			t.Fatalf("import %s: %v", f, err)
		}
	}
	rs, err = controller.CARotationStatus(ctx, h.cfg, clock)
	if err != nil || !rs.Waiting || rs.NeedsCross || rs.NeedsInter {
		t.Fatalf("status with both imported: %+v, %v", rs, err)
	}
	if got := auditOf(t, h, "ca.import_intermediate"); len(got) != 2 {
		t.Fatalf("audit of the imports: %v", got)
	}
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, r := range db.Client().CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).AllX(storetest.SystemCtx(t)) {
		if r.KeyEnc != nil && len(*r.KeyEnc) != 0 {
			t.Fatal("the old root's key is in the database")
		}
	}
}
