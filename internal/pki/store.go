// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
)

// The CA's keys live in ca_keys, envelope-encrypted under the KEK, and every certificate the CA
// issues is recorded in issued_certificates (docs/04-security.md, "CA hierarchy", "Revocation").

const keyAlgorithm = "ecdsa-p256"

// CA is the controller's internal CA, loaded from the database: it issues and records leaves, and
// holds the signing keys. The root's private key stays sealed.
type CA struct {
	issuer                    *Issuer
	configSigner, auditSigner KeyPair
}

// ErrCAExists is returned by InitCA when the database already holds CA keys.
var ErrCAExists = errors.New("pki: the database already holds a CA")

// InitCA creates the root, the issuing intermediate, and the config-signing and audit-checkpoint
// keys of trust domain td in tx, with every private key sealed under s. It needs the system scope,
// and it runs once.
func InitCA(ctx context.Context, tx *ent.Tx, s *secret.Sealer, td string, now time.Time) error {
	if n, err := tx.CAKey.Query().Count(ctx); err != nil || n > 0 {
		return errors.Join(ErrCAExists, err)
	}
	root, err := NewRoot(td, now)
	if err != nil {
		return err
	}
	inter, err := NewIntermediate(root, now)
	if err != nil {
		return err
	}
	is, err := NewIssuer(root.Cert, inter, func() time.Time { return now })
	if err != nil {
		return err
	}
	keys := map[cakey.Kind]KeyPair{cakey.KindRoot: root, cakey.KindIntermediate: inter}
	for kind, purpose := range map[cakey.Kind]Purpose{
		cakey.KindConfigSigning: PurposeConfigSigning, cakey.KindAuditCheckpoint: PurposeAuditCheckpoint,
	} {
		k, err := NewKey()
		if err != nil {
			return err
		}
		cert, err := is.IssueSigner(&k.PublicKey, purpose)
		if err != nil {
			return err
		}
		keys[kind] = KeyPair{Cert: cert, Key: k}
	}
	for kind, kp := range keys {
		if err := saveKey(ctx, tx, s, kind, kp); err != nil {
			return fmt.Errorf("pki: save the %s key: %w", kind, err)
		}
	}
	return nil
}

func saveKey(ctx context.Context, tx *ent.Tx, s *secret.Sealer, kind cakey.Kind, kp KeyPair) error {
	id := ids.New("cak")
	der, err := x509.MarshalPKCS8PrivateKey(kp.Key)
	if err != nil {
		return err
	}
	sealed, err := store.Seal(ctx, tx, s, keyContext(id), secret.FromBytes(der))
	clear(der)
	if err != nil {
		return err
	}
	return tx.CAKey.Create().SetID(id).SetKind(kind).SetAlgorithm(keyAlgorithm).
		SetPublicKey(kp.Cert.RawSubjectPublicKeyInfo).SetCertificate(kp.Cert.Raw).SetKeyEnc(sealed).
		SetNotBefore(kp.Cert.NotBefore).SetNotAfter(kp.Cert.NotAfter).SetStatus(cakey.StatusActive).Exec(ctx)
}

// keyContext binds a sealed CA key to its row.
func keyContext(id string) secret.Context {
	return secret.Context{Table: "ca_keys", Column: "key_enc", RowID: id}
}

// LoadCA reads the active keys and the retired intermediates that have not expired (rotation
// overlap), and opens the intermediate's and the signing keys with s. It needs the system scope.
func LoadCA(ctx context.Context, db *store.DB, s *secret.Sealer, now func() time.Time) (*CA, error) {
	rows, err := db.ReadClient().CAKey.Query().Where(cakey.Or(
		cakey.StatusEQ(cakey.StatusActive),
		cakey.And(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusRetired), cakey.NotAfterGT(now())),
	)).All(ctx)
	if err != nil {
		return nil, err
	}
	active := map[cakey.Kind]*ent.CAKey{}
	var older []*x509.Certificate
	for _, r := range rows {
		if r.Status == cakey.StatusActive {
			if active[r.Kind] != nil {
				return nil, fmt.Errorf("pki: the database holds two active %s keys", r.Kind)
			}
			active[r.Kind] = r
			continue
		}
		c, err := x509.ParseCertificate(r.Certificate)
		if err != nil {
			return nil, fmt.Errorf("pki: certificate of key %s: %w", r.ID, err)
		}
		older = append(older, c)
	}
	for _, kind := range []cakey.Kind{cakey.KindRoot, cakey.KindIntermediate, cakey.KindConfigSigning, cakey.KindAuditCheckpoint} {
		if active[kind] == nil {
			return nil, fmt.Errorf("pki: the database holds no active %s key", kind)
		}
	}
	root, err := x509.ParseCertificate(active[cakey.KindRoot].Certificate)
	if err != nil {
		return nil, fmt.Errorf("pki: root certificate: %w", err)
	}
	ca := &CA{}
	var inter KeyPair
	for kind, dst := range map[cakey.Kind]*KeyPair{
		cakey.KindIntermediate: &inter, cakey.KindConfigSigning: &ca.configSigner, cakey.KindAuditCheckpoint: &ca.auditSigner,
	} {
		if *dst, err = openKey(s, active[kind]); err != nil {
			return nil, err
		}
	}
	if ca.issuer, err = NewIssuer(root, inter, now, older...); err != nil {
		return nil, err
	}
	chain := append([]*x509.Certificate{inter.Cert}, older...)
	for p, kp := range map[Purpose]KeyPair{PurposeConfigSigning: ca.configSigner, PurposeAuditCheckpoint: ca.auditSigner} {
		if err := VerifySigner(kp.Cert, chain, root, p, now()); err != nil {
			return nil, err
		}
	}
	return ca, nil
}

// openKey opens a sealed key and checks it against its certificate.
func openKey(s *secret.Sealer, r *ent.CAKey) (KeyPair, error) {
	cert, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return KeyPair{}, fmt.Errorf("pki: certificate of the %s key: %w", r.Kind, err)
	}
	if r.KeyEnc == nil {
		return KeyPair{}, fmt.Errorf("pki: the %s key is offline", r.Kind)
	}
	v, err := s.Open(keyContext(r.ID), *r.KeyEnc)
	if err != nil {
		return KeyPair{}, fmt.Errorf("pki: open the %s key: %w", r.Kind, err)
	}
	key, err := x509.ParsePKCS8PrivateKey([]byte(v.Reveal()))
	if err != nil {
		return KeyPair{}, fmt.Errorf("pki: the %s key: %w", r.Kind, err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || !ec.PublicKey.Equal(cert.PublicKey) {
		return KeyPair{}, fmt.Errorf("pki: the %s key does not match its certificate", r.Kind)
	}
	return KeyPair{Cert: cert, Key: ec}, nil
}

// TrustDomain returns the CA's trust domain.
func (ca *CA) TrustDomain() string { return ca.issuer.TrustDomain() }

// Root returns the root certificate.
func (ca *CA) Root() *x509.Certificate { return ca.issuer.Root() }

// Intermediate returns the current intermediate's certificate.
func (ca *CA) Intermediate() *x509.Certificate { return ca.issuer.Intermediate() }

// IdentityOf verifies that cert is a TLS leaf of this CA at time at and returns its identity.
func (ca *CA) IdentityOf(cert *x509.Certificate, at time.Time) (Identity, error) {
	return ca.issuer.IdentityOf(cert, at)
}

// ConfigSigner returns the config-signing key and its certificate.
func (ca *CA) ConfigSigner() KeyPair { return ca.configSigner }

// AuditSigner returns the audit-checkpoint key and its certificate.
func (ca *CA) AuditSigner() KeyPair { return ca.auditSigner }

// Issue issues a leaf for id from csr (see Issuer.IssueLeaf) and records it in tx, the
// transaction that hands it out.
func (ca *CA) Issue(ctx context.Context, tx *ent.Tx, csr *x509.CertificateRequest, id Identity, lifetime time.Duration) (*x509.Certificate, error) {
	cert, err := ca.issuer.IssueLeaf(csr, id, lifetime)
	if err != nil {
		return nil, err
	}
	return cert, record(ctx, tx, cert, id)
}

// Renew renews presented for a CSR with a new key (see Issuer.RenewLeaf) and records the new leaf
// in tx.
func (ca *CA) Renew(ctx context.Context, tx *ent.Tx, presented *x509.Certificate, csr *x509.CertificateRequest, lifetime time.Duration) (*x509.Certificate, error) {
	cert, err := ca.issuer.RenewLeaf(presented, csr, lifetime)
	if err != nil {
		return nil, err
	}
	id, err := ca.issuer.IdentityOf(cert, cert.NotBefore.Add(Backdate))
	if err != nil {
		return nil, err
	}
	return cert, record(ctx, tx, cert, id)
}

// NodeCertificate issues the TLS certificate of controller node nodeID. Its key exists only in
// memory: every start and every renewal gets a new key and a new certificate, recorded without an
// org. It needs the system scope.
func (ca *CA) NodeCertificate(ctx context.Context, db *store.DB, nodeID string) (tls.Certificate, error) {
	key, err := NewKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	id := Identity{TrustDomain: ca.TrustDomain(), Kind: KindController, ID: nodeID}
	var cert *x509.Certificate
	err = store.WriteTx(ctx, db, func(tx *ent.Tx) error {
		cert, err = ca.Issue(ctx, tx, csr, id, ControllerLifetime)
		return err
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw, ca.Intermediate().Raw}, PrivateKey: key, Leaf: cert}, nil
}

// SerialHex is a serial number's key in issued_certificates and on the deny-list.
func SerialHex(n *big.Int) string { return n.Text(16) }

func record(ctx context.Context, tx *ent.Tx, cert *x509.Certificate, id Identity) error {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	c := tx.IssuedCertificate.Create().SetID(SerialHex(cert.SerialNumber)).
		SetSubjectType(issuedcertificate.SubjectType(id.Kind)).SetSubjectID(id.ID).SetSpiffeID(id.String()).
		SetPubkeySha256(hex.EncodeToString(sum[:])).SetNotBefore(cert.NotBefore).SetNotAfter(cert.NotAfter)
	if id.Org != "" { // controller nodes have none
		c.SetOrgID(id.Org)
	}
	return c.Exec(ctx)
}
