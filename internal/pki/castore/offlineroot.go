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
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
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

// RootExport is what ExportRootOffline reports, for the caller's audit record and its marker.
type RootExport struct {
	Pin           string // the root's pin
	PublicKeyHash string // SHA-256 of the root's public key, hexadecimal
	FileSHA256    string // SHA-256 of the file, hexadecimal
}

// ExportRootOffline takes the root's key out of the database, in tx. It seals the key and the
// certificate in an age file under passphrase and hands the file to persist, which must write it
// where the operator chose and return what it reads back from the medium (it must read the file
// again, not return its argument); the file read back must open with
// passphrase to the key of the root in ca_keys. Only then is key_enc set to null. It refuses a root
// that is offline already (ErrRootOffline). It needs the system scope. The caller records the
// audit entry and the marker in the same transaction, and, as the sealed key may remain in free
// pages and in backups, rotates the KEK afterwards.
func ExportRootOffline(ctx context.Context, tx *ent.Tx, s *secret.Sealer, passphrase string,
	persist func(file []byte) (readBack []byte, err error)) (RootExport, error) {
	if err := pki.CheckPassphrase(passphrase); err != nil {
		return RootExport{}, err
	}
	row, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return RootExport{}, err
	}
	if keyOffline(row) {
		return RootExport{}, ErrRootOffline
	}
	root, err := openKey(s, row)
	if err != nil {
		return RootExport{}, err
	}
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
	pub := sha256.Sum256(row.PublicKey)
	sum := sha256.Sum256(back)
	return RootExport{Pin: pki.RootPin(root.Cert), PublicKeyHash: hex.EncodeToString(pub[:]), FileSHA256: hex.EncodeToString(sum[:])}, nil
}

// RequestIntermediateSigning makes the next intermediate when the root is offline: a new key,
// sealed with status next, no certificate and its request in csr. It returns the request (PEM).
// One request waits at a time: a second call returns the one that waits. With an online root it
// returns ErrRootOnline; the intermediate is then signed at once. It needs the system scope.
func RequestIntermediateSigning(ctx context.Context, tx *ent.Tx, s *secret.Sealer, now time.Time) ([]byte, error) {
	root, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return nil, err
	}
	if !keyOffline(root) {
		return nil, ErrRootOnline
	}
	if err := lockRoot(ctx, tx, root.ID); err != nil {
		return nil, err
	}
	if p, err := pendingIntermediate(ctx, tx); err != nil || p != nil {
		if p != nil {
			return p.Csr, nil
		}
		return nil, err
	}
	key, csr, err := pki.NewIntermediateRequest()
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	id, err := sealNew(ctx, tx, s, der)
	if err != nil {
		return nil, err
	}
	// Not before and not after hold the validity the root will most likely give; the certificate's
	// replace them at the import.
	return csr, tx.CAKey.Create().SetID(id.id).SetKind(cakey.KindIntermediate).SetAlgorithm(keyAlgorithm).
		SetPublicKey(pub).SetCsr(csr).SetKeyEnc(id.sealed).SetNotBefore(now).SetNotAfter(now.Add(pki.IntermediateLifetime)).
		SetStatus(cakey.StatusNext).Exec(ctx)
}

// ErrRootOnline is returned by RequestIntermediateSigning when the root's key is in the database.
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
	return tx.CAKey.UpdateOne(p).SetCertificate(cert.Raw).SetNotBefore(cert.NotBefore).SetNotAfter(cert.NotAfter).Exec(ctx)
}

// SigningAlert is the state of the need for an offline signature.
type SigningAlert string

// The states of SigningAlert.
const (
	AlertNone         SigningAlert = ""              // nothing waits for a signature
	AlertNeedsSigning SigningAlert = "needs_signing" // a request waits
	AlertCritical     SigningAlert = "critical"      // it waits and the active intermediate expires within 30 days
)

// IntermediateSigningAlert reports whether the next intermediate waits for a signature, and
// whether the active intermediate expires in IntermediateSigningCritical or less.
func IntermediateSigningAlert(ctx context.Context, db *store.DB, now time.Time) (SigningAlert, error) {
	rows, err := db.ReadClient().CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate),
		cakey.StatusIn(cakey.StatusActive, cakey.StatusNext)).All(ctx)
	if err != nil {
		return AlertNone, err
	}
	var waits bool
	var expires time.Time
	for _, r := range rows {
		switch {
		case r.Status == cakey.StatusActive:
			expires = r.NotAfter
		case len(r.Certificate) == 0:
			waits = true
		}
	}
	switch {
	case !waits:
		return AlertNone, nil
	case !expires.IsZero() && !now.Before(expires.Add(-IntermediateSigningCritical)):
		return AlertCritical, nil
	}
	return AlertNeedsSigning, nil
}

type sealedKey struct {
	id     string
	sealed []byte
}

// sealNew seals a private key (PKCS #8, cleared afterwards) under a new row ID.
func sealNew(ctx context.Context, tx *ent.Tx, s *secret.Sealer, der []byte) (sealedKey, error) {
	id := ids.New("cak")
	sealed, err := store.Seal(ctx, tx, s, keyContext(id), secret.FromBytes(der))
	clear(der)
	return sealedKey{id: id, sealed: sealed}, err
}

// keyOffline reports whether the row holds no private key. Ent reads a null key_enc as a pointer to
// an empty slice, so a nil check alone would miss it.
func keyOffline(r *ent.CAKey) bool { return r.KeyEnc == nil || len(*r.KeyEnc) == 0 }
