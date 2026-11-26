// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// The rotation of the root by cross-signing (docs/04-security.md, "Root rotation"): `ca new-root`
// makes the new root R2 and its first intermediate I2; the old root R1 signs a cross-certificate X
// for R2 and Y for I2's key, itself when its key is in the database, otherwise on the offline host;
// the rotation job then moves issuing to R2 and R1 stays in the bundle, in the overlap, until `ca
// drop-root` or the job drops it.

// Errors of a root rotation.
var (
	// ErrRotationInProgress is returned when a root rotation runs, so that another cannot start, and
	// neither can a rotation of the intermediate.
	ErrRotationInProgress = errors.New("pki: a root rotation is in progress; finish it first (rpmgr ca status shows where it stands)")
	// ErrNoRotation is returned by the drop of a root when no root is in the overlap of a rotation.
	ErrNoRotation = errors.New("pki: no root is in the overlap of a rotation")
)

// DropEarlyError is returned by the drop of the old root before the overlap has passed.
type DropEarlyError struct{ Earliest time.Time }

func (e *DropEarlyError) Error() string {
	return "pki: the old root cannot be dropped before " + e.Earliest.UTC().Format(time.RFC3339) +
		": until then an agent that was offline can still reauthenticate only through it"
}

// StragglersError is returned by the drop of the old root while enabled agents do not hold the new
// one.
type StragglersError struct {
	N     int
	Force bool // the drop was --force, which is accepted only while no agent is a straggler
}

func (e *StragglersError) Error() string {
	if e.Force {
		return fmt.Sprintf("pki: --force is accepted only while no agent lacks the new root, and %d enabled agent(s) still do", e.N)
	}
	return fmt.Sprintf("pki: %d enabled agent(s) that were seen during the overlap still lack the new root and would be stranded "+
		"when the old one is dropped: update, re-enroll or decommission them, or drop with --strand-stragglers", e.N)
}

// RootRequests are the requests the offline old root signs to finish a rotation: the
// cross-certificate of the new root (`sign-intermediate --kind cross-root`) and the certificate of
// the new intermediate's key (`sign-intermediate`), each with the hash of the key it carries.
type RootRequests struct {
	Cross, Intermediate        []byte // PEM
	CrossKeyHash, InterKeyHash string
}

// Requests returns the requests of a PlanNewRoot with an offline old root, or nil.
func (p *Plan) Requests() *RootRequests { return p.requests }

// rotationRows sorts the rows of a plan by kind and status.
type rotationRows struct {
	active, next map[cakey.Kind]*ent.CAKey
	overlap      bool
}

func sortRows(rows []*ent.CAKey) rotationRows {
	r := rotationRows{active: map[cakey.Kind]*ent.CAKey{}, next: map[cakey.Kind]*ent.CAKey{}}
	for _, k := range rows {
		switch k.Status {
		case cakey.StatusActive:
			r.active[k.Kind] = k
		case cakey.StatusOverlap:
			r.overlap = true
		default:
			r.next[k.Kind] = k
		}
	}
	return r
}

// PlanNewRoot is `rpmgr ca new-root`: it makes the new root R2 and its first intermediate I2, and
// seals their keys here, outside the transaction. With the old root's key in the database it also
// signs X and Y and moves issuing to R2 at once: R2 and I2 are active, R1 is in the overlap, the
// signing keys are replaced by keys under I2, and Config reports that the bundle changed. With the
// old root offline it writes R2 and I2 with status next, with their requests (Requests), and the
// rotation job moves issuing when both certificates are imported. When a rotation already waits
// for the old root's signatures, the plan writes nothing and returns the requests that wait; one
// that issues already, or any other state, is ErrRotationInProgress. Apply fails with ErrRotated if
// the keys changed meanwhile. It needs the system scope.
func PlanNewRoot(ctx context.Context, c *ent.CAKeyClient, s *secret.Sealer, now time.Time) (*Plan, error) {
	rows, err := readActive(ctx, c)
	if err != nil {
		return nil, err
	}
	p := &Plan{seen: keysSeen(rows), now: now}
	r := sortRows(rows)
	r1, i1 := r.active[cakey.KindRoot], r.active[cakey.KindIntermediate]
	if r1 == nil || i1 == nil {
		return nil, errors.New("pki: the database holds no active root or intermediate")
	}
	if nr, ni := r.next[cakey.KindRoot], r.next[cakey.KindIntermediate]; nr != nil && !r.overlap {
		// Requests made and not yet signed: they are the ones that wait.
		if ni == nil || len(nr.CrossCertificate) > 0 && len(ni.CrossCertificate) > 0 || len(nr.Csr) == 0 || len(ni.Csr) == 0 {
			return nil, ErrRotationInProgress
		}
		p.requests = &RootRequests{Cross: nr.Csr, Intermediate: ni.Csr,
			CrossKeyHash: pki.PublicKeyHash(nr.PublicKey), InterKeyHash: pki.PublicKeyHash(ni.PublicKey)}
		return p, nil
	}
	if r.overlap || r.next[cakey.KindRoot] != nil {
		return nil, ErrRotationInProgress
	}
	if n := r.next[cakey.KindIntermediate]; n != nil && len(n.Certificate) == 0 {
		return nil, fmt.Errorf("%w: the next intermediate waits for the root's signature; import it first", ErrRotationInProgress)
	}
	r1cert, err := x509.ParseCertificate(r1.Certificate)
	if err != nil {
		return nil, err
	}
	td, err := pki.TrustDomainOf(r1cert)
	if err != nil {
		return nil, err
	}
	r2, err := pki.NewRoot(td, now)
	if err != nil {
		return nil, err
	}
	i2, err := pki.NewIntermediate(r2, now)
	if err != nil {
		return nil, err
	}
	p.lock, p.newRoot = r1.ID, r2.Cert
	if keyOffline(r1) {
		return p, planNewRootOffline(ctx, s, p, r2, i2)
	}
	r1kp, err := openKey(ctx, s, r1)
	if err != nil {
		return nil, err
	}
	x, y, err := pki.CrossSign(r1kp, r2.Key, i2.Key, now)
	if err != nil {
		return nil, err
	}
	if err := pki.VerifyCrossRoot(x, r1cert, r2.Cert, now); err != nil {
		return nil, err
	}
	if err := pki.VerifyIntermediate(y, r1cert, &i2.Key.PublicKey, now); err != nil {
		return nil, err
	}
	nr2, err := sealNew(ctx, s, cakey.KindRoot, r2, cakey.StatusActive)
	if err != nil {
		return nil, err
	}
	ni2, err := sealNew(ctx, s, cakey.KindIntermediate, i2, cakey.StatusActive)
	if err != nil {
		return nil, err
	}
	nr2.cross, ni2.cross = x.Raw, y.Raw
	p.config = true
	p.steps = []planStep{
		{done: "root rotated: the new root issues and the old one stays in the bundle", overlap: r1.ID, create: nr2},
		{done: "intermediate replaced by the new root's", retire: i1.ID, create: ni2},
	}
	is, err := pki.NewIssuer(r2.Cert, i2, func() time.Time { return now })
	if err != nil {
		return nil, err
	}
	return p, signerSteps(ctx, s, p, r, is)
}

// planNewRootOffline writes R2 and I2 as next keys, with the requests the offline old root signs.
func planNewRootOffline(ctx context.Context, s *secret.Sealer, p *Plan, r2, i2 pki.KeyPair) error {
	crossCSR, err := pki.RequestFor(r2.Key)
	if err != nil {
		return err
	}
	interCSR, err := pki.RequestFor(i2.Key)
	if err != nil {
		return err
	}
	nr2, err := sealNew(ctx, s, cakey.KindRoot, r2, cakey.StatusNext)
	if err != nil {
		return err
	}
	ni2, err := sealNew(ctx, s, cakey.KindIntermediate, i2, cakey.StatusNext)
	if err != nil {
		return err
	}
	nr2.csr, ni2.csr = crossCSR, interCSR
	p.requests = &RootRequests{Cross: crossCSR, Intermediate: interCSR,
		CrossKeyHash: pki.PublicKeyHash(r2.Cert.RawSubjectPublicKeyInfo), InterKeyHash: pki.PublicKeyHash(i2.Cert.RawSubjectPublicKeyInfo)}
	p.steps = []planStep{{done: "new root made; it waits for the old root's signatures", create: nr2},
		{done: "new intermediate made; it waits for the old root's signature", create: ni2}}
	return nil
}

// planSwitch moves issuing to the new root once the old root signed X and Y: the rotation job runs
// it, as importing needs no KEK and the keys of the signing certificates are sealed here.
func planSwitch(ctx context.Context, s *secret.Sealer, p *Plan, active, next map[cakey.Kind]*ent.CAKey, now time.Time) error {
	nr, ni := next[cakey.KindRoot], next[cakey.KindIntermediate]
	r2, err := openKey(ctx, s, nr)
	if err != nil {
		return err
	}
	i2, err := openKey(ctx, s, ni)
	if err != nil {
		return err
	}
	is, err := pki.NewIssuer(r2.Cert, i2, func() time.Time { return now })
	if err != nil {
		return err
	}
	p.lock, p.config = active[cakey.KindRoot].ID, true
	p.steps = []planStep{
		{done: "root rotated: the new root issues and the old one stays in the bundle", overlap: active[cakey.KindRoot].ID, promote: nr.ID},
		{done: "intermediate replaced by the new root's", retire: active[cakey.KindIntermediate].ID, promote: ni.ID},
	}
	return signerSteps(ctx, s, p, rotationRows{active: active, next: next}, is)
}

// signerSteps makes the next config-signing and audit-checkpoint key, issued by the new intermediate,
// so that what agents verify snapshots and deny-lists with chains to the new root, and still verifies
// once the old root is dropped. The active signing keys stay active through the overlap: connected
// agents learn the next key's certificate with their next Welcome, which every renewal brings, and
// cannot verify a snapshot signed by a key they do not know. The drop of the old root makes the
// next keys active (DropPlan). A next key made before, which the old intermediate issued, is retired.
func signerSteps(ctx context.Context, s *secret.Sealer, p *Plan, r rotationRows, is *pki.Issuer) error {
	for _, kind := range []cakey.Kind{cakey.KindConfigSigning, cakey.KindAuditCheckpoint} {
		if r.active[kind] == nil {
			return fmt.Errorf("pki: the database holds no active %s key", kind)
		}
		purpose := pki.PurposeConfigSigning
		if kind == cakey.KindAuditCheckpoint {
			purpose = pki.PurposeAuditCheckpoint
		}
		key, err := pki.NewKey()
		if err != nil {
			return err
		}
		cert, err := is.IssueSigner(&key.PublicKey, purpose)
		if err != nil {
			return err
		}
		nk, err := sealNew(ctx, s, kind, pki.KeyPair{Cert: cert, Key: key}, cakey.StatusNext)
		if err != nil {
			return err
		}
		if n := r.next[kind]; n != nil {
			p.steps = append(p.steps, planStep{retireNext: n.ID})
		}
		p.steps = append(p.steps, planStep{done: "next " + string(kind) + " key made under the new root", create: nk})
	}
	return nil
}

// importCrossCertificate imports the certificate cert (DER, parsed) that the old root signed for the
// key of the new root or of the new intermediate, when one of them waits for it; handled is false
// when none does. It needs no KEK. The certificate must pass pki.VerifyCrossRoot or
// pki.VerifyIntermediate against the old root, and otherwise nothing changes. It replaces a
// certificate imported before, as long as issuing did not move.
func importCrossCertificate(ctx context.Context, tx *ent.Tx, cert *x509.Certificate, now time.Time) (handled bool, err error) {
	rows, err := tx.CAKey.Query().Where(cakey.StatusEQ(cakey.StatusNext), cakey.KindIn(cakey.KindRoot, cakey.KindIntermediate)).All(ctx)
	if err != nil {
		return false, err
	}
	// Only while a new root waits: a next intermediate with a certificate is otherwise the schedule's.
	if !slices.ContainsFunc(rows, func(r *ent.CAKey) bool { return r.Kind == cakey.KindRoot }) {
		return false, nil
	}
	for _, r := range rows {
		if len(r.Certificate) == 0 || !bytes.Equal(r.PublicKey, cert.RawSubjectPublicKeyInfo) {
			continue
		}
		r1, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
		if err != nil {
			return true, err
		}
		r1cert, err := x509.ParseCertificate(r1.Certificate)
		if err != nil {
			return true, err
		}
		own, err := x509.ParseCertificate(r.Certificate)
		if err != nil {
			return true, err
		}
		if r.Kind == cakey.KindRoot {
			err = pki.VerifyCrossRoot(cert, r1cert, own, now)
		} else {
			pub, ok := own.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return true, fmt.Errorf("pki: key %s is not ECDSA", r.ID)
			}
			err = pki.VerifyIntermediate(cert, r1cert, pub, now)
		}
		if err != nil {
			return true, err
		}
		return true, tx.CAKey.UpdateOne(r).SetCrossCertificate(cert.Raw).Exec(ctx)
	}
	return false, nil
}
