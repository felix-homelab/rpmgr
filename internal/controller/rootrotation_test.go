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

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
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

	if rs, err := controller.RotationStatusOf(e.sys, db, at); err != nil || rs.IssuingRootOnline || !rs.Waiting {
		t.Fatalf("status before the switch: %+v, %v", rs, err)
	}
	before := revisions()
	run()
	if e.ca.Root().Equal(r1) {
		t.Fatal("the job did not move issuing to the new root")
	}
	// The old root was offline and the new one is online, which the status says until it is taken offline.
	if rs, err := controller.RotationStatusOf(e.sys, db, at); err != nil || !rs.IssuingRootOnline {
		t.Fatalf("status after the switch: %+v, %v; want the issuing root online", rs, err)
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
	disabledOne := e.fleetAgent(t, false, at.Add(-rotationDay), pki.RootsDigest([]*x509.Certificate{r1}), false)
	logs.Reset()
	run()
	if got := e.ca.TrustBundle(); len(got) != 1 || !got[0].Equal(e.ca.Root()) {
		t.Fatalf("the bundle after the drop holds %d certificates", len(got))
	}
	if revisions() != before+1 {
		t.Fatal("the drop was no configuration change")
	}
	drops := e.db.Client().AuditEntry.Query().Where(auditentry.Action("ca.drop_root"), auditentry.ActorID("ca-rotation")).AllX(e.sys)
	if len(drops) != 1 {
		t.Fatalf("%d audit records of the drop", len(drops))
	}
	// A disabled agent that lacks the new root does not hold the drop back, but the audit entry and the log name it.
	if !strings.Contains(drops[0].Reason, "disabled agents lack the new root") || !strings.Contains(drops[0].Reason, disabledOne) ||
		!strings.Contains(logs.String(), disabledOne) {
		t.Fatalf("the automatic drop does not name the disabled agent %s: %q, log %s", disabledOne, drops[0].Reason, logs.String())
	}
	// The old root was offline, and the new one still is online after the drop wiped the old root's row.
	if rs, err := controller.RotationStatusOf(e.sys, db, at); err != nil || !rs.IssuingRootOnline {
		t.Fatalf("status after the drop: %+v, %v; want the issuing root online", rs, err)
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
	// The old root of the overlap is reported as such, and not as a second active root.
	if st, err := controller.CAStatus(ctx, h.cfg); err != nil {
		t.Fatal(err)
	} else {
		active, overlap := 0, 0
		for _, k := range st.GetKeys() {
			if k.GetKind() == rpmgrv1.CAKeyKind_CA_KEY_KIND_ROOT {
				switch k.GetState() {
				case rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE:
					active++
				case rpmgrv1.CAKeyState_CA_KEY_STATE_OVERLAP:
					overlap++
				}
			}
		}
		if active != 1 || overlap != 1 {
			t.Fatalf("the roots in the overlap: %d active, %d overlap; want one each", active, overlap)
		}
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

// TestRotationStatusOfAnIntermediateRequest: an ordinary offline request for a next intermediate is not a
// root rotation, and the status does not say it is.
func TestRotationStatusOfAnIntermediateRequest(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	dir := t.TempDir()
	if _, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: h.cfg, Out: filepath.Join(dir, "root.age"), Passphrase: suppliedPass, Getenv: noEnv}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.RequestIntermediate(ctx, h.cfg, filepath.Join(dir, "next.csr"), noEnv, time.Now); err != nil {
		t.Fatal(err)
	}
	rs, err := controller.CARotationStatus(ctx, h.cfg, time.Now)
	if err != nil || rs.Waiting || rs.NeedsCross || rs.NeedsInter || len(rs.KeyHashes) != 0 {
		t.Fatalf("status with a next intermediate only: %+v, %v", rs, err)
	}
}

// TestDropRootKeepsTheRecordedOverlap: the earliest drop date is fixed when issuing moves; lowering the leaf
// lifetime afterwards does not make the old root droppable sooner, and the status shows the recorded date.
func TestDropRootKeepsTheRecordedOverlap(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	now := time.Now()
	if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	// With an online old root the new one being online is nothing to warn about.
	if rs, err := controller.CARotationStatus(ctx, h.cfg, func() time.Time { return now }); err != nil || rs.IssuingRootOnline {
		t.Fatalf("status of a rotation of an online root: %+v, %v", rs, err)
	}
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sys := storetest.SystemCtx(t)
	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{LeafCertificateLifetime: durationpb.New(rotationDay)},
		&fieldmaskpb.FieldMask{Paths: []string{"leaf_certificate_lifetime"}}, 0); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	// With the lowered lifetime the overlap would be 1 + 30 days: 32 days in, the recorded 37 still hold.
	var early *castore.DropEarlyError
	if _, err := controller.DropRoot(ctx, h.cfg, false, false, func() time.Time { return now.Add(32 * rotationDay) }); !errors.As(err, &early) {
		t.Fatalf("a drop within the recorded overlap = %v, want DropEarlyError", err)
	}
	if want := now.Add(37 * rotationDay); early.Earliest.Sub(want).Abs() > time.Minute {
		t.Fatalf("the earliest date is %v, want about %v", early.Earliest, want)
	}
	rs, err := controller.CARotationStatus(ctx, h.cfg, func() time.Time { return now })
	if err != nil || rs.DropAfter.Sub(now.Add(37*rotationDay)).Abs() > time.Minute {
		t.Fatalf("status shows %v, %v", rs.DropAfter, err)
	}
	if _, err := controller.DropRoot(ctx, h.cfg, false, false, func() time.Time { return now.Add(38 * rotationDay) }); err != nil {
		t.Fatalf("the drop after the recorded overlap: %v", err)
	}
}

// hostAgent records a connector with a session in the database of a host, as fleetAgent does in an env's.
func hostAgent(t *testing.T, h host, org string, enabled bool, seen time.Time) string {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	id := ids.New("con")
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		if err := tx.Connector.Create().SetID(id).SetOrgID(org).SetName("con-" + strings.ToLower(id[len(id)-6:])).SetSpiffeID("spiffe://x/" + id).
			SetPubkeySha256("00").SetEnabled(enabled).Exec(sys); err != nil {
			return err
		}
		return tx.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_test").SetLastSeenAt(seen).
			SetConnectedAt(seen).SetRootsDigest("aa").Exec(sys)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func hostOrg(t *testing.T, h host) string {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	return storetest.Org(t, db, "org-a")
}

// TestDropRootForceCountsAnAgentOfflineAcrossTheSwitch: an enabled agent last seen before the switch, within
// the time its leaf and the Reauth grace reach, holds a --force drop back, though no session was seen since;
// a disabled one does not, but the status and the drop name it; and the drop that strands agents, or goes
// early, says so in its audit entry.
func TestDropRootForceCountsAnAgentOfflineAcrossTheSwitch(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	now := time.Now()
	org := hostOrg(t, h)
	if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	_ = hostAgent(t, h, org, true, now.Add(-3*rotationDay)) // offline across the switch
	disabled := hostAgent(t, h, org, false, now.Add(-3*rotationDay))
	at := func(d time.Duration) func() time.Time { return func() time.Time { return now.Add(d) } }

	rs, err := controller.CARotationStatus(ctx, h.cfg, at(rotationDay))
	if err != nil || !slices.Equal(rs.Disabled, []string{disabled}) || len(rs.Stragglers) != 0 {
		t.Fatalf("status: disabled %v, stragglers %v, %v", rs.Disabled, rs.Stragglers, err)
	}
	var strag *castore.StragglersError
	if _, err := controller.DropRoot(ctx, h.cfg, true, false, at(rotationDay)); !errors.As(err, &strag) || !strag.Force || strag.N != 1 {
		t.Fatalf("--force with an agent that was offline across the switch = %v, want a StragglersError for 1 agent", err)
	}
	// Well after the window an agent last seen then is out of reach of its leaf and the grace.
	if _, err := controller.DropRoot(ctx, h.cfg, true, false, at(60*rotationDay)); err != nil {
		t.Fatalf("--force after the overlap, with the agent long unseen: %v", err)
	}
	if got := auditOf(t, h, "ca.drop_root"); len(got) != 1 || strings.Contains(got[0], "--force") {
		t.Fatalf("audit of a drop after the earliest date: %v", got)
	}
}

// TestDropRootAuditsWhatItOverrode: the audit entry of a drop names a drop before the earliest date, and the
// agents that --strand-stragglers left without the new root.
func TestDropRootAuditsWhatItOverrode(t *testing.T) {
	ctx := context.Background()
	t.Run("force", func(t *testing.T) {
		h, _ := initHost(t)
		now := time.Now()
		if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.DropRoot(ctx, h.cfg, true, false, func() time.Time { return now.Add(rotationDay) }); err != nil {
			t.Fatal(err)
		}
		if got := auditOf(t, h, "ca.drop_root"); len(got) != 1 || !strings.Contains(got[0], "before the earliest date") || !strings.Contains(got[0], "--force") {
			t.Fatalf("audit of a forced drop: %v", got)
		}
		// Nothing signs under the old root any more: the keys of the retired intermediate and signing keys
		// are gone from the database (the old root's too), and the active ones are not.
		db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		retired, active := 0, 0
		for _, r := range db.Client().CAKey.Query().AllX(storetest.SystemCtx(t)) {
			switch {
			case r.Status == cakey.StatusRetired && r.KeyEnc != nil && len(*r.KeyEnc) != 0:
				t.Errorf("the key of the retired %s %s is still in the database", r.Kind, r.ID)
			case r.Status == cakey.StatusRetired:
				retired++
			case r.Status == cakey.StatusActive && (r.KeyEnc == nil || len(*r.KeyEnc) == 0):
				t.Errorf("the key of the active %s %s was wiped", r.Kind, r.ID)
			case r.Status == cakey.StatusActive:
				active++
			}
		}
		// The old root was online, so the new one being online afterwards is nothing to warn of.
		if rs, err := controller.CARotationStatus(ctx, h.cfg, time.Now); err != nil || rs.IssuingRootOnline {
			t.Errorf("status after the rotation of an online root: %+v, %v", rs, err)
		}
		if retired < 4 || active < 4 {
			t.Errorf("%d retired and %d active keys; want the old root, intermediate and two signing keys retired, and four active", retired, active)
		}
	})
	t.Run("strand", func(t *testing.T) {
		h, _ := initHost(t)
		now := time.Now()
		org := hostOrg(t, h)
		if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); err != nil {
			t.Fatal(err)
		}
		late := now.Add(38 * rotationDay)
		stranded := hostAgent(t, h, org, true, now.Add(5*rotationDay))
		if _, err := controller.DropRoot(ctx, h.cfg, false, false, func() time.Time { return late }); err == nil {
			t.Fatal("dropped the old root although an enabled agent lacks the new one")
		}
		res, err := controller.DropRoot(ctx, h.cfg, false, true, func() time.Time { return late })
		if err != nil || !slices.Equal(res.Stranded, []string{stranded}) {
			t.Fatalf("--strand-stragglers: %+v, %v", res, err)
		}
		if got := auditOf(t, h, "ca.drop_root"); len(got) != 1 || !strings.Contains(got[0], stranded) || !strings.Contains(got[0], "--strand-stragglers") ||
			!strings.Contains(got[0], "1 enabled agents stranded") {
			t.Fatalf("audit of a stranding drop: %v", got)
		}
	})
}

// TestRotationStatusWarnsOfAnExpiringIntermediate: a root rotation that stalls blocks the rotation of the
// intermediate, so the status says when the active intermediate runs out while one waits, and not otherwise.
func TestRotationStatusWarnsOfAnExpiringIntermediate(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	dir := t.TempDir()
	if _, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: h.cfg, Out: filepath.Join(dir, "root.age"), Passphrase: suppliedPass, Getenv: noEnv}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := controller.NewRoot(ctx, h.cfg, filepath.Join(dir, "r2.csr"), noEnv, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	rs, err := controller.CARotationStatus(ctx, h.cfg, func() time.Time { return now })
	if err != nil || !rs.Waiting || rs.IntermediateExpiring {
		t.Fatalf("status of a fresh rotation: %+v, %v", rs, err)
	}
	// The intermediate lasts a year: 340 days on it expires within 30 days.
	rs, err = controller.CARotationStatus(ctx, h.cfg, func() time.Time { return now.Add(340 * rotationDay) })
	if err != nil || !rs.Waiting || !rs.IntermediateExpiring || rs.IntermediateExpires.IsZero() {
		t.Fatalf("status of a rotation that stalled: %+v, %v", rs, err)
	}
}

// hostLeaf records a current leaf of an agent, as the CA issued it at notBefore, in a host's database; the
// agent's own row stays as it is.
func hostLeaf(t *testing.T, h host, org, subjectType, id string, notBefore time.Time) {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Client().IssuedCertificate.Create().SetID(strings.ToLower(ids.New("crt")[4:])).SetOrgID(org).SetSubjectType(issuedcertificate.SubjectType(subjectType)).
		SetSubjectID(id).SetSpiffeID("spiffe://x/" + id).SetPubkeySha256("00").SetNotBefore(notBefore).SetNotAfter(notBefore.Add(7 * rotationDay)).
		Exec(storetest.SystemCtx(t)); err != nil {
		t.Fatal(err)
	}
}

// hostRows makes an enabled connector and a gateway of a host with no session, created long ago (the connector)
// or ahead by an admin (the gateway), and returns their IDs.
func hostRows(t *testing.T, h host, org string, created time.Time) (con, gw string) {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	con = ids.New("con")
	if err := db.Client().Connector.Create().SetID(con).SetOrgID(org).SetName("con-old").SetSpiffeID("spiffe://x/" + con).SetPubkeySha256("00").
		SetEnabled(true).SetCreatedAt(created).Exec(sys); err != nil {
		t.Fatal(err)
	}
	group := db.Client().GatewayGroup.Create().SetOrgID(org).SetName("gg").SaveX(sys).ID
	gw = db.Client().Gateway.Create().SetOrgID(org).SetGatewayGroupID(group).SetName("gw1").SetSlot(1).SetEnabled(true).
		SetTunnelEndpoints([]string{"gw1.example:443"}).SetSpiffeID("spiffe://x/gw1").SetCreatedAt(created).SaveX(sys).ID
	return con, gw
}

// TestDropRootForceCountsAgentsThatEnrolledBeforeTheSwitch: an agent whose current leaf was issued in the window
// before the switch and that has not connected since holds a --force drop back, whatever its row says: a
// connector made long ago that enrolled again, and a gateway an admin made ahead. A leaf issued after the switch,
// a revoked one and one from before the window do not.
func TestDropRootForceCountsAgentsThatEnrolledBeforeTheSwitch(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	now := time.Now()
	org := hostOrg(t, h)
	if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	con, gw := hostRows(t, h, org, now.Add(-200*rotationDay))
	force := func(d time.Duration) error {
		_, err := controller.DropRoot(ctx, h.cfg, true, false, func() time.Time { return now.Add(d) })
		return err
	}
	// Leaves that must not count, beside the ones that do: one outside the window, and one after the switch.
	hostLeaf(t, h, org, "connector", con, now.Add(-100*rotationDay))
	hostLeaf(t, h, org, "gateway", gw, now.Add(rotationDay))
	var strag *castore.StragglersError
	// The connector re-enrolled three days before the switch; the gateway, created ahead, enrolled two days before.
	hostLeaf(t, h, org, "connector", con, now.Add(-3*rotationDay))
	hostLeaf(t, h, org, "gateway", gw, now.Add(-2*rotationDay))
	if err := force(rotationDay); !errors.As(err, &strag) || strag.N != 2 {
		t.Fatalf("--force with a re-enrolled connector and a gateway enrolled before the switch = %v, want 2 stragglers", err)
	}
	// Past the earliest date --force is a plain drop, which does not count an agent not seen since the switch.
	if err := force(38 * rotationDay); err != nil {
		t.Fatalf("--force after the earliest date: %v", err)
	}
}

// TestDropRootForceIgnoresLeavesThatDoNotCount: a leaf issued after the switch, a revoked or superseded one, and
// one of an agent that was seen since the window began do not hold a --force drop back.
func TestDropRootForceIgnoresLeavesThatDoNotCount(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	now := time.Now()
	org := hostOrg(t, h)
	if _, err := controller.NewRoot(ctx, h.cfg, "", noEnv, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	con, gw := hostRows(t, h, org, now.Add(-200*rotationDay))
	hostLeaf(t, h, org, "connector", con, now.Add(rotationDay)) // after the switch
	hostLeaf(t, h, org, "gateway", gw, now.Add(-2*rotationDay))
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sys := storetest.SystemCtx(t)
	db.Client().IssuedCertificate.Update().Where(issuedcertificate.SubjectID(gw)).SetRevokedAt(now).ExecX(sys) // revoked
	_ = db.Close()
	if _, err := controller.DropRoot(ctx, h.cfg, true, false, func() time.Time { return now.Add(rotationDay) }); err != nil {
		t.Fatalf("--force with no leaf that counts: %v", err)
	}
}

// TestDropWipesOlderRetiredSigners: a signing key the schedule retired before the rotation chained to the old
// root through the old intermediate and is wiped by the drop with the others, not only the keys the drop swapped.
func TestDropWipesOlderRetiredSigners(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	leases := lease.New(db, "ctn_test", nil)
	at := time.Now()
	co := controller.CAOptions{DB: db, CA: e.ca, Sealer: e.sealer, Leases: leases, Now: func() time.Time { return at }}
	run := func() {
		t.Helper()
		if err := runOnce(t, leases, controller.CARotation(co)); err != nil {
			t.Fatal(err)
		}
	}
	signers := func(status cakey.Status) []*ent.CAKey {
		return e.db.Client().CAKey.Query().Where(cakey.KindIn(cakey.KindConfigSigning, cakey.KindAuditCheckpoint), cakey.StatusEQ(status)).AllX(e.sys)
	}
	// The schedule makes the next signing keys and then promotes them, which retires the first ones.
	at = at.Add(pki.SignerLifetime - castore.SignerNextBefore + rotationDay)
	run()
	at = at.Add(castore.SignerNextBefore - castore.SignerPromoteBefore)
	run()
	if older := signers(cakey.StatusRetired); len(older) != 2 {
		t.Fatalf("%d signing keys retired by the schedule, want 2", len(older))
	}
	e.newRootOnline(t, at)
	at = at.Add(38 * rotationDay)
	run()
	if len(e.ca.Roots()) != 1 {
		t.Fatal("the job did not drop the old root")
	}
	for _, r := range e.db.Client().CAKey.Query().Where(cakey.StatusEQ(cakey.StatusRetired)).AllX(e.sys) {
		if r.KeyEnc != nil && len(*r.KeyEnc) != 0 {
			t.Errorf("the key of the retired %s %s is still in the database", r.Kind, r.ID)
		}
	}
}
