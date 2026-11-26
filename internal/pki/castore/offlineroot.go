// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
)

// The offline root (docs/04-security.md, "Offline root CA"): its key leaves the database in an age
// file, and the next intermediate waits in ca_keys for a signature made elsewhere.

// Errors of the offline root.
var (
	// ErrRootOffline is returned when something needs the root's key and the key is offline.
	ErrRootOffline = errors.New("pki: the root is offline; its key signs only on the host that holds its file")
	// ErrRootExport is returned when the root file did not read back as the root in the database.
	ErrRootExport = errors.New("pki: the root file does not read back as the root")
	// ErrNoRequest is returned by ImportIntermediate when no next intermediate waits for a signature.
	ErrNoRequest = errors.New("pki: no intermediate waits for a signature")
)

// IntermediateSigningCritical is how long before the active intermediate expires the need for a
// signature becomes critical.
const IntermediateSigningCritical = 30 * 24 * time.Hour

// RootExport is what RootExportPlan.Apply reports, for the caller's audit record and its marker.
type RootExport struct {
	Pin           string // the root's pin
	PublicKeyHash string // SHA-256 of the root's public key, hexadecimal
	FileSHA256    string // SHA-256 of the file, hexadecimal
	// KEK is the version of the KEK that sealed the key in the database, which the marker names.
	KEK string
}

// A RootExportPlan is the root's key opened before the transaction that takes it out: opening the
// key may wait for a key service, which a write transaction must not.
type RootExportPlan struct {
	id     string
	keyEnc []byte // the sealed key the plan opened, to tell that the row is the same one
	root   pki.KeyPair
	kek    string
}

// PlanRootExport opens the key of the active root, which c reads, for RootExportPlan.Apply. It
// refuses a root that is offline already (ErrRootOffline).
func PlanRootExport(ctx context.Context, c *ent.CAKeyClient, s *secret.Sealer) (*RootExportPlan, error) {
	row, err := c.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return nil, err
	}
	if keyOffline(row) {
		return nil, ErrRootOffline
	}
	root, err := openKey(ctx, s, row)
	if err != nil {
		return nil, err
	}
	kek, err := secret.KEKVersion(*row.KeyEnc)
	if err != nil {
		return nil, err
	}
	return &RootExportPlan{id: row.ID, keyEnc: bytes.Clone(*row.KeyEnc), root: root, kek: kek}, nil
}

// Apply takes the root's key out of the database, in tx. It seals the key and the certificate in an
// age file under passphrase and hands the file to persist, which must write it where the operator
// chose and return what it reads back from the medium (it must read the file again, not return its
// argument); the file read back must open with passphrase to the key of the root in ca_keys. Only
// then is key_enc set to null. It refuses a root that is offline already (ErrRootOffline) and fails
// with ErrRotated when the root's key is not the one the plan opened. It needs the system scope. The
// caller records the audit entry and the marker in the same transaction, and, as the sealed key may
// remain in free pages and in backups, rotates the KEK afterwards.
func (p *RootExportPlan) Apply(ctx context.Context, tx *ent.Tx, passphrase string,
	persist func(file []byte) (readBack []byte, err error)) (RootExport, error) {
	if err := pki.CheckPassphrase(passphrase); err != nil {
		return RootExport{}, err
	}
	// Two exports at once take turns, as two requests do.
	if err := lockRoot(ctx, tx, p.id); err != nil {
		return RootExport{}, err
	}
	row, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return RootExport{}, err
	}
	if keyOffline(row) {
		return RootExport{}, ErrRootOffline
	}
	if row.ID != p.id || !bytes.Equal(*row.KeyEnc, p.keyEnc) {
		return RootExport{}, ErrRotated
	}
	root := p.root
	file, err := pki.SealRootFile(root, passphrase)
	if err != nil {
		return RootExport{}, err
	}
	back, err := persist(file)
	if err != nil {
		return RootExport{}, err
	}
	opened, err := pki.OpenRootFile(back, passphrase)
	if err != nil || !opened.Cert.Equal(root.Cert) || !opened.Key.Equal(root.Key) ||
		!bytes.Equal(opened.Cert.RawSubjectPublicKeyInfo, row.PublicKey) {
		return RootExport{}, ErrRootExport
	}
	if err := tx.CAKey.UpdateOne(row).ClearKeyEnc().Exec(ctx); err != nil {
		return RootExport{}, err
	}
	sum := sha256.Sum256(back)
	return RootExport{Pin: pki.RootPin(root.Cert), PublicKeyHash: pki.PublicKeyHash(row.PublicKey), FileSHA256: hex.EncodeToString(sum[:]), KEK: p.kek}, nil
}

// ApplyRootOffline is what a restore does with the marker `root_offline`: it sets key_enc to null
// for the root whose public key has the SHA-256 hash. held reports that the restored database
// still held the key, found is false for a root it does not hold.
func ApplyRootOffline(ctx context.Context, tx *ent.Tx, hash string) (held, found bool, err error) {
	rows, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot)).All(ctx)
	if err != nil {
		return false, false, err
	}
	for _, r := range rows {
		if pki.PublicKeyHash(r.PublicKey) != hash {
			continue
		}
		if keyOffline(r) {
			return false, true, nil
		}
		return true, true, tx.CAKey.UpdateOne(r).ClearKeyEnc().Exec(ctx)
	}
	return false, false, nil
}

// RootActionOffline is the audit action of the ceremony; its Diff holds RootOfflineDiff(kek).
const RootActionOffline = "ca.root_offline"

// RootOfflineDiff is the Diff of the audit entry of the ceremony: the KEK that sealed the key.
func RootOfflineDiff(kek string) string { return "kek:" + kek }

// RootKeyResidue returns the KEK that sealed the root's key when it went offline while that KEK
// still wraps a stored secret, and so, for the ceremony's KEK rotation, has not been replaced:
// the sealed key may remain in free pages and backups, and this KEK opens it. It returns "" for an
// online root and for a root whose KEK was replaced. unknown is true for an offline root with no
// `ca.root_offline` audit entry (pruned by retention): it cannot tell whether the KEK was rotated
// since. A restore writes the entry again from the revocation log's marker.
func RootKeyResidue(ctx context.Context, db *store.DB) (kek string, unknown bool, err error) {
	c := db.ReadClient()
	if online, err := c.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive),
		cakey.KeyEncNotNil()).Exist(ctx); err != nil || online {
		return "", false, err
	}
	e, err := c.AuditEntry.Query().Where(auditentry.Action(RootActionOffline), auditentry.ResultEQ(auditentry.ResultSuccess)).
		Order(auditentry.BySeq(sql.OrderDesc())).First(ctx)
	if ent.IsNotFound(err) {
		return "", true, nil
	}
	if err != nil {
		return "", false, err
	}
	kek, ok := strings.CutPrefix(e.Diff, "kek:")
	if !ok {
		return "", true, nil
	}
	held, err := c.SecretMeta.Query().Where(secretmeta.KekVersion(kek)).Exist(ctx)
	if err != nil || !held {
		return "", false, err
	}
	return kek, false, nil
}

// PlanSigningRequest works out the request for the offline root to sign the next intermediate: a
// new key, sealed with status next, no certificate and its request in csr. The key is made and
// sealed here, outside the transaction, because sealing may wait for a key service; Apply writes it
// and CSR returns the request (PEM). One request waits at a time: when one waits already, the plan
// writes nothing and CSR returns that one. With an online root it returns ErrRootOnline; the
// intermediate is then signed at once. Apply fails with ErrRotated if the keys changed meanwhile,
// as another request first. It needs the system scope.
func PlanSigningRequest(ctx context.Context, c *ent.CAKeyClient, s *secret.Sealer, now time.Time) (*Plan, error) {
	rows, err := readActive(ctx, c)
	if err != nil {
		return nil, err
	}
	p := &Plan{seen: keysSeen(rows)}
	var root *ent.CAKey
	for _, r := range rows {
		switch {
		case r.Kind == cakey.KindRoot && r.Status == cakey.StatusActive:
			root = r
		case r.Kind == cakey.KindIntermediate && r.Status == cakey.StatusNext && len(r.Certificate) == 0:
			p.csr = r.Csr
		}
	}
	if root == nil {
		return nil, fmt.Errorf("pki: the database holds no active root")
	}
	if !keyOffline(root) {
		return nil, ErrRootOnline
	}
	if p.csr != nil {
		return p, nil
	}
	nk, err := newSigningRequest(ctx, s, now)
	if err != nil {
		return nil, err
	}
	p.lock, p.csr = root.ID, nk.request.csr
	p.steps = []planStep{{done: "intermediate needs signing", create: nk}}
	return p, nil
}

// CSR is the request (PEM) of a plan of PlanSigningRequest, which is the one that waits when the
// plan writes nothing.
func (p *Plan) CSR() []byte { return p.csr }

// newSigningRequest makes the key of the next intermediate and its request, and seals the key.
func newSigningRequest(ctx context.Context, s *secret.Sealer, now time.Time) (*newKey, error) {
	key, csr, err := pki.NewIntermediateRequest()
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	k := &newKey{id: ids.New("cak"), kind: cakey.KindIntermediate, status: cakey.StatusNext,
		request: &signingRequest{pub: pub, csr: csr, notBefore: now, notAfter: now.Add(pki.IntermediateLifetime)}}
	k.sealed, err = sealKey(ctx, s, k.id, key)
	return k, err
}

// ErrRootOnline is returned by PlanSigningRequest when the root's key is in the database.
var ErrRootOnline = errors.New("pki: the root is online and signs the intermediate itself")

// lockRoot makes concurrent requests take turns. PostgreSQL runs at READ COMMITTED, so two
// transactions could both find no pending request: an update of the root row, to the value it has,
// takes its row lock, so the second waits and then sees the first's request. SQLite has one writer.
func lockRoot(ctx context.Context, tx *ent.Tx, id string) error {
	return tx.CAKey.UpdateOneID(id).SetStatus(cakey.StatusActive).Exec(ctx)
}

// pendingIntermediate is the next intermediate that waits for a signature, or nil.
func pendingIntermediate(ctx context.Context, tx *ent.Tx) (*ent.CAKey, error) {
	rows, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusNext)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if len(r.Certificate) == 0 {
			return r, nil
		}
	}
	return nil, nil
}

// ImportIntermediate imports the signed certificate (DER) of the intermediate that waits for it, in
// tx. It needs no KEK. The certificate must pass pki.VerifyIntermediate against the root of the
// database, and otherwise nothing changes. The key stays next until the schedule activates it.
func ImportIntermediate(ctx context.Context, tx *ent.Tx, der []byte, now time.Time) error {
	p, err := pendingIntermediate(ctx, tx)
	if err != nil {
		return err
	}
	if p == nil {
		return ErrNoRequest
	}
	root, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return err
	}
	rootCert, err := x509.ParseCertificate(root.Certificate)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("%w: %w", pki.ErrIntermediateRefused, err)
	}
	pub, err := x509.ParsePKIXPublicKey(p.PublicKey)
	if err != nil {
		return err
	}
	want, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("pki: key %s is not ECDSA", p.ID)
	}
	if err := pki.VerifyIntermediate(cert, rootCert, want, now); err != nil {
		return err
	}
	active, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return err
	}
	if !cert.NotAfter.After(active.NotAfter) {
		return fmt.Errorf("%w: it does not outlast the active intermediate", pki.ErrIntermediateRefused)
	}
	// A signed next intermediate that is not valid now is never activated; this one replaces it.
	stale, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusNext), cakey.IDNEQ(p.ID)).All(ctx)
	if err != nil {
		return err
	}
	for _, r := range stale {
		if len(r.Certificate) == 0 || !notValidAt(r, now) {
			continue
		}
		// Only while it is still next.
		n, err := tx.CAKey.Update().Where(cakey.ID(r.ID), cakey.StatusEQ(cakey.StatusNext)).SetStatus(cakey.StatusRetired).Save(ctx)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrRotated
		}
	}
	return tx.CAKey.UpdateOne(p).SetCertificate(cert.Raw).SetNotBefore(cert.NotBefore).SetNotAfter(cert.NotAfter).Exec(ctx)
}

// SigningAlert is the state of the need for an offline signature.
type SigningAlert string

// The states of SigningAlert.
const (
	AlertNone         SigningAlert = ""              // nothing waits for a signature
	AlertNeedsSigning SigningAlert = "needs_signing" // a request waits
	AlertCritical     SigningAlert = "critical"      // it waits and the active intermediate expires within 30 days
	// AlertNextNotValid is for a signed next intermediate that is not valid now, which the schedule
	// does not activate: the operator signs a new request.
	AlertNextNotValid SigningAlert = "next_not_valid"
)

// IntermediateSigningAlert reports whether the next intermediate waits for a signature, and
// whether the active intermediate expires in IntermediateSigningCritical or less; or whether the
// signed next intermediate is not valid now.
func IntermediateSigningAlert(ctx context.Context, db *store.DB, now time.Time) (SigningAlert, error) {
	rows, err := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate),
		cakey.StatusIn(cakey.StatusActive, cakey.StatusNext)).All(ctx)
	if err != nil {
		return AlertNone, err
	}
	var waits, invalid bool
	var expires time.Time
	for _, r := range rows {
		switch {
		case r.Status == cakey.StatusActive:
			expires = r.NotAfter
		case len(r.Certificate) == 0:
			waits = true
		case notValidAt(r, now):
			invalid = true
		}
	}
	// A request that waits comes first, also beside a stale signed one: it is what the operator
	// signs next, and the urgency is its.
	switch {
	case waits && !expires.IsZero() && !now.Before(expires.Add(-IntermediateSigningCritical)):
		return AlertCritical, nil
	case waits:
		return AlertNeedsSigning, nil
	case invalid:
		return AlertNextNotValid, nil
	}
	return AlertNone, nil
}

// notValidAt reports whether the validity of the key's certificate does not include now.
func notValidAt(r *ent.CAKey, now time.Time) bool {
	return now.Before(r.NotBefore) || !now.Before(r.NotAfter)
}

// NextIntermediateKeyHash is the SHA-256 of the public key of the request that waits for a
// signature, or else of the signed next intermediate that is not valid now; empty when there is
// none.
func NextIntermediateKeyHash(ctx context.Context, db *store.DB) (string, error) {
	rows, err := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusNext)).All(ctx)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	pick := rows[0]
	for _, r := range rows {
		if len(r.Certificate) == 0 {
			pick = r
		}
	}
	return pki.PublicKeyHash(pick.PublicKey), nil
}

// keyOffline reports whether the row holds no private key. Ent reads a null key_enc as a pointer to
// an empty slice, so a nil check alone would miss it.
func keyOffline(r *ent.CAKey) bool { return r.KeyEnc == nil || len(*r.KeyEnc) == 0 }
