// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The ceremony of the offline root (docs/04-security.md, "Offline root CA"; docs/10-operations.md,
// "Take the root offline" and "Rotate the issuing intermediate").

// ErrDeclined is returned by SignIntermediate when the operator did not confirm the signature.
var ErrDeclined = errors.New("controller: not signed: the request was not confirmed")

// maxCeremonyFile bounds what the ceremony reads from a file: the root file, a request, a
// certificate.
const maxCeremonyFile = 1 << 20

// OfflineRootOptions are the inputs of `rpmgr ca offline-root`.
type OfflineRootOptions struct {
	ConfigPath string
	Out        string // the file to write; it must not exist
	// Passphrase is the one the operator supplied, which must pass pki.CheckPassphrase; empty has
	// the command generate one.
	Passphrase string
	Getenv     func(string) string
	Now        func() time.Time
}

// OfflineRootResult is what `rpmgr ca offline-root` reports.
type OfflineRootResult struct {
	castore.RootExport
	// Passphrase is the generated one, shown once and stored nowhere; empty for a supplied one.
	Passphrase string
}

// OfflineRoot is `rpmgr ca offline-root`: it writes the root's key and certificate to o.Out as an
// age passphrase file, reads the file back from the medium and compares it with the database, and
// only then sets key_enc to null, records `ca.root_offline` and appends the `root_offline` marker
// to the revocation log, in one transaction. The KEK must be rotated afterwards.
func OfflineRoot(ctx context.Context, o OfflineRootOptions) (OfflineRootResult, error) {
	var res OfflineRootResult
	if o.Now == nil {
		o.Now = time.Now
	}
	cfg, err := loadController(o.ConfigPath)
	if err != nil {
		return res, err
	}
	kek, err := localKEK(cfg, o.Getenv)
	if err != nil {
		return res, err
	}
	sealer, err := secret.NewSealer(kek)
	if err != nil {
		return res, err
	}
	if err := mustNotExist(o.Out); err != nil {
		return res, err
	}
	passphrase := o.Passphrase
	if passphrase == "" {
		if passphrase, err = pki.GeneratePassphrase(); err != nil {
			return res, err
		}
		res.Passphrase = passphrase
	}
	_, db, sys, err := openLocal(ctx, o.ConfigPath, "rpmgr ca offline-root")
	if err != nil {
		return res, err
	}
	defer func() { _ = db.Close() }()
	rl, err := revlog.Open(filepath.Join(filepath.Dir(cfg.Database.DSN), "revocations.log"), o.Now)
	if err != nil {
		return res, err
	}
	var created, marked bool
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		created, marked = false, false
		var err error
		res.RootExport, err = castore.ExportRootOffline(sys, tx, sealer, passphrase, func(file []byte) ([]byte, error) {
			if err := writeNew(o.Out, file, 0o600); err != nil {
				return nil, err
			}
			created = true
			return readCeremonyFile(o.Out)
		})
		if err != nil {
			return err
		}
		if _, err := audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: castore.RootActionOffline,
			TargetType: "ca", TargetID: res.PublicKeyHash, Result: audit.Success, Diff: castore.RootOfflineDiff(res.KEK),
			Reason: "the root's key moved to an offline file with the SHA-256 " + res.FileSHA256}); err != nil {
			return err
		}
		// Last, so that nothing after it can fail the transaction but its commit.
		if _, err := rl.Append(revlog.Entry{Kind: revlog.RootOffline, Subject: res.PublicKeyHash, Detail: res.KEK, Actor: "local-cli"}); err != nil {
			return err
		}
		marked = true
		return nil
	})
	switch {
	case err != nil && marked:
		return OfflineRootResult{}, fmt.Errorf("controller: the commit failed after the marker was logged; %s holds the root's key, "+
			"keep it and check `rpmgr ca status`: %w", o.Out, err)
	case err != nil && created:
		_ = os.Remove(o.Out) // the root stays online, so a file that holds its key is of no use
	}
	if err != nil {
		return OfflineRootResult{}, err
	}
	return res, nil
}

// mustNotExist refuses a path that exists, a link included, so that no file is ever overwritten.
func mustNotExist(path string) error {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("controller: %s exists; a file is never overwritten", path)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	return nil
}

// readCeremonyFile reads a file of the ceremony from its medium.
func readCeremonyFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCeremonyFile+1))
	if err == nil && len(b) > maxCeremonyFile {
		err = fmt.Errorf("controller: %s is larger than %d bytes", path, maxCeremonyFile)
	}
	return b, err
}

// IntermediateSummary is what the operator sees before the offline root signs, and what was signed.
type IntermediateSummary struct {
	Subject     string
	KeyHash     string // SHA-256 of the key's SubjectPublicKeyInfo, hexadecimal
	NotBefore   time.Time
	NotAfter    time.Time
	Constraints string // path length and name constraints, as text
	Certificate []byte // PEM
}

// SignOptions are the inputs of `rpmgr ca sign-intermediate`.
type SignOptions struct {
	RootFile, CSR, Out string
	Passphrase         string
	Now                func() time.Time
	// Confirm shows the summary and reports whether to sign; nil signs without asking.
	Confirm func(IntermediateSummary) (bool, error)
}

// SignIntermediate is `rpmgr ca sign-intermediate`. It needs no database, KEK or controller: it
// opens the root file, checks the request, shows what it would sign, and writes the certificate to
// o.Out, which must not exist. A file that does not open is ErrRootFile and says nothing more.
func SignIntermediate(o SignOptions) (IntermediateSummary, error) {
	var sum IntermediateSummary
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := mustNotExist(o.Out); err != nil {
		return sum, err
	}
	file, err := readCeremonyFile(o.RootFile)
	if err != nil {
		return sum, fmt.Errorf("controller: the root file: %w", err)
	}
	root, err := pki.OpenRootFile(file, o.Passphrase)
	if err != nil {
		return sum, err
	}
	csr, err := readCeremonyFile(o.CSR)
	if err != nil {
		return sum, fmt.Errorf("controller: the request: %w", err)
	}
	cert, err := pki.SignIntermediate(root, csr, o.Now())
	if err != nil {
		return sum, err
	}
	sum = summarize(cert)
	if o.Confirm != nil {
		if ok, err := o.Confirm(sum); err != nil || !ok {
			if err == nil {
				err = ErrDeclined
			}
			return sum, err
		}
	}
	return sum, writeNew(o.Out, sum.Certificate, 0o644)
}

// summarize describes a certificate the offline root signed.
func summarize(cert *x509.Certificate) IntermediateSummary {
	return IntermediateSummary{Subject: cert.Subject.String(), KeyHash: pki.PublicKeyHash(cert.RawSubjectPublicKeyInfo),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		Constraints: fmt.Sprintf("a CA that may sign no further CA (path length %d); only URI names under %s and DNS names under %s",
			cert.MaxPathLen, strings.Join(cert.PermittedURIDomains, ", "), strings.Join(cert.PermittedDNSDomains, ", ")),
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}
}

// RequestIntermediate is `rpmgr ca rotate-intermediate --csr-out`: with an offline root it makes the
// next intermediate's key, or finds the one that waits, and writes its request to out, which must
// not exist. It returns the SHA-256 of the key, which sign-intermediate shows.
func RequestIntermediate(ctx context.Context, path, out string, getenv func(string) string, now func() time.Time) (string, error) {
	cfg, err := loadController(path)
	if err != nil {
		return "", err
	}
	kek, err := localKEK(cfg, getenv)
	if err != nil {
		return "", err
	}
	sealer, err := secret.NewSealer(kek)
	if err != nil {
		return "", err
	}
	if err := mustNotExist(out); err != nil {
		return "", err
	}
	_, db, sys, err := openLocal(ctx, path, "rpmgr ca rotate-intermediate")
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	var csr []byte
	var hash string
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		var err error
		if csr, err = castore.RequestIntermediateSigning(sys, tx, sealer, now()); err != nil {
			return err
		}
		if hash, err = requestKeyHash(csr); err != nil {
			return err
		}
		_, err = audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "ca.request_intermediate",
			TargetType: "ca", TargetID: hash, Result: audit.Success, Reason: "a request for the offline root to sign the next intermediate"})
		return err
	})
	if err != nil {
		return "", err
	}
	return hash, writeNew(out, csr, 0o644)
}

// requestKeyHash is the SHA-256 of the key a request (PEM) asks to have signed.
func requestKeyHash(csrPEM []byte) (string, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil {
		return "", errors.New("controller: the request is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return "", err
	}
	return pki.PublicKeyHash(csr.RawSubjectPublicKeyInfo), nil
}

// ImportIntermediate is `rpmgr ca import-intermediate`: the certificate (PEM or DER) of the
// intermediate that waits for a signature, checked against the root in the database by
// castore.ImportIntermediate; when a check fails nothing changes. It needs no KEK.
func ImportIntermediate(ctx context.Context, path, in string, now func() time.Time) (IntermediateSummary, error) {
	var sum IntermediateSummary
	raw, err := readCeremonyFile(in)
	if err != nil {
		return sum, fmt.Errorf("controller: the certificate: %w", err)
	}
	der := raw
	if b, _ := pem.Decode(raw); b != nil {
		if b.Type != "CERTIFICATE" {
			return sum, fmt.Errorf("controller: %s is a PEM %s, not a certificate", in, b.Type)
		}
		der = b.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return sum, fmt.Errorf("%w: %w", pki.ErrIntermediateRefused, err)
	}
	_, db, sys, err := openLocal(ctx, path, "rpmgr ca import-intermediate")
	if err != nil {
		return sum, err
	}
	defer func() { _ = db.Close() }()
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		if err := castore.ImportIntermediate(sys, tx, cert.Raw, now()); err != nil {
			return err
		}
		sum = IntermediateSummary{Subject: cert.Subject.String(), KeyHash: pki.PublicKeyHash(cert.RawSubjectPublicKeyInfo),
			NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}
		_, err := audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "ca.import_intermediate",
			TargetType: "ca", TargetID: sum.KeyHash, Result: audit.Success,
			Reason: "an intermediate signed by the offline root, valid until " + cert.NotAfter.UTC().Format(time.RFC3339)})
		return err
	})
	return sum, err
}
