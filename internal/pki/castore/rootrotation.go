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
	// ErrNothingToAbort is returned by the abort of a root rotation that has no new root waiting.
	ErrNothingToAbort = errors.New("pki: no new root waits for the old root's signatures")
	// ErrSwitched is returned by the abort of a root rotation that moved issuing already: it is finished
	// by dropping the old root.
	ErrSwitched = errors.New("pki: issuing already moved to the new root; drop the old root to finish the rotation")
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
	if n := r.next[cakey.KindIntermediate]; n != nil {
		// Whether it waits for the root's signature or for the schedule to activate it, a second next
		// intermediate under the new root would collide with it.
		if len(n.Certificate) == 0 {
			return nil, fmt.Errorf("%w: the next intermediate waits for the root's signature; import it first", ErrRotationInProgress)
		}
		return nil, fmt.Errorf("%w: an intermediate is signed and waits for the schedule to activate it; rotate the root after that", ErrRotationInProgress)
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
	// Only the new root's certificate is needed: it does not sign here, so its key stays sealed (or
	// offline) and is not opened.
	r2, err := x509.ParseCertificate(nr.Certificate)
	if err != nil {
		return fmt.Errorf("pki: certificate of the new root: %w", err)
	}
	i2, err := openKey(ctx, s, ni)
	if err != nil {
		return err
	}
	is, err := pki.NewIssuer(r2, i2, func() time.Time { return now })
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
		// Only while the row is still next: a switch between the read and this write must not have a
		// certificate land on a row that is no longer waiting for it.
		n, err := tx.CAKey.Update().Where(cakey.ID(r.ID), cakey.StatusEQ(cakey.StatusNext)).SetCrossCertificate(cert.Raw).Save(ctx)
		if err != nil {
			return true, err
		}
		if n != 1 {
			return true, ErrRotated
		}
		return true, nil
	}
	return false, nil
}

// StragglerCount counts the enabled agents that were seen since the overlap began and do not hold
// the new root; the caller reads it from the agents' Hello digests.
type StragglerCount func(ctx context.Context, tx *ent.Tx, since time.Time) (int, error)

// DropOptions are the inputs of PlanDropRoot.
type DropOptions struct {
	// Overlap is how long after issuing moved the old root stays: the longest agent leaf lifetime
	// plus the Reauth grace period.
	Overlap time.Duration
	// Force drops before the overlap has passed, which is accepted only while no agent is a straggler;
	// Strand drops after it although enabled agents still lack the new root.
	Force, Strand bool
	// Stragglers counts the agents that lack the new root.
	Stragglers StragglerCount
	// StragglerIDs, when set, lists them too, so that a drop that strands them can record who they were.
	StragglerIDs StragglerList
}

// StragglerList is StragglerCount that names the agents.
type StragglerList func(ctx context.Context, tx *ent.Tx, since time.Time) ([]string, error)

// A DropPlan is the drop of the old root of a rotation. It opens no key, so there is nothing to
// seal before its transaction; it is a plan so that Apply checks, in its transaction, every premise
// it was made from.
type DropPlan struct {
	seen string
	o    DropOptions
	now  time.Time
	r2   string
	// swaps are the signing keys that chain to the old root and the next ones, issued under the new
	// intermediate, that replace them with the drop.
	swaps []signerSwap
	// early is set when the drop is allowed before the earliest date (Force); earliest is that date.
	early    bool
	earliest time.Time
	// stranded are the agents a drop with Strand leaves without the new root, as Apply found them.
	stranded []string
}

// Early reports whether the drop was made before the earliest date, which Force allows, and the date.
func (p *DropPlan) Early() (bool, time.Time) { return p.early, p.earliest }

// Stranded names the enabled agents the drop left without the new root; it is filled by Apply, when
// the drop was made with Strand and StragglerIDs was set.
func (p *DropPlan) Stranded() []string { return p.stranded }

type signerSwap struct{ old, next string }

// PlanDropRoot checks that a root is in the overlap and that dropping it is allowed at now: not
// before Overlap has passed since issuing moved (a DropEarlyError, unless Force and no agent is a straggler), and not while enabled agents that were seen since lack the new
// root (a StragglersError), unless Strand. c reads outside a transaction; Apply repeats every check.
func PlanDropRoot(ctx context.Context, c *ent.CAKeyClient, now time.Time, o DropOptions) (*DropPlan, error) {
	rows, err := readActive(ctx, c)
	if err != nil {
		return nil, err
	}
	p := &DropPlan{seen: keysSeen(rows), o: o, now: now}
	if _, err := p.check(ctx, rows, nil); err != nil {
		return nil, err
	}
	return p, nil
}

// check decides whether the drop is allowed on rows, and returns the root in the overlap. tx is nil
// for the plan, which counts no stragglers then and only decides the checks that do not need them.
func (p *DropPlan) check(ctx context.Context, rows []*ent.CAKey, tx *ent.Tx) (*ent.CAKey, error) {
	var r1, r2 *ent.CAKey
	for _, r := range rows {
		switch {
		case r.Kind == cakey.KindRoot && r.Status == cakey.StatusOverlap:
			r1 = r
		case r.Kind == cakey.KindRoot && r.Status == cakey.StatusActive:
			r2 = r
		}
	}
	if r1 == nil || r2 == nil || r1.RotatedAt == nil {
		return nil, ErrNoRotation
	}
	p.r2 = r2.ID
	swaps, err := signerSwaps(rows)
	if err != nil {
		return nil, err
	}
	p.swaps = swaps
	// The later of the date recorded when issuing moved and the one the settings give now: lowering the
	// leaf lifetime meanwhile does not shorten the overlap that agents were promised.
	earliest := DropAfter(r1, p.o.Overlap)
	early := p.now.Before(earliest)
	p.early, p.earliest = early, earliest
	if early && !p.o.Force {
		return nil, &DropEarlyError{Earliest: earliest}
	}
	if p.o.Strand && early {
		return nil, &DropEarlyError{Earliest: earliest}
	}
	if tx == nil || p.o.Stragglers == nil {
		return r1, nil
	}
	since := StragglersSince(r1, p.now, p.o)
	n, err := p.o.Stragglers(ctx, tx, since)
	if err != nil {
		return nil, err
	}
	p.stranded = nil
	if n > 0 && p.o.Strand && p.o.StragglerIDs != nil {
		if p.stranded, err = p.o.StragglerIDs(ctx, tx, since); err != nil {
			return nil, err
		}
	}
	switch {
	case n > 0 && p.o.Force:
		return nil, &StragglersError{N: n, Force: true}
	case n > 0 && !p.o.Strand:
		return nil, &StragglersError{N: n}
	}
	return r1, nil
}

// Apply drops the old root in tx: it leaves the bundle, which becomes the new root alone, and its
// row is retired. It repeats every check on what tx reads and fails with ErrRotated when the keys
// are not the ones the plan was made from. The caller writes it in a configuration transaction, so
// that agents get the bundle in a snapshot of a new revision, and records the audit entry. It needs
// the system scope.
func (p *DropPlan) Apply(ctx context.Context, tx *ent.Tx) ([]string, error) {
	// Two drops, or a drop and the rotation job, take turns on the issuing root's row.
	if err := lockRoot(ctx, tx, p.r2); err != nil {
		return nil, err
	}
	rows, err := readActive(ctx, tx.CAKey)
	if err != nil {
		return nil, err
	}
	if keysSeen(rows) != p.seen {
		return nil, ErrRotated
	}
	r1, err := p.check(ctx, rows, tx)
	if err != nil {
		return nil, err
	}
	n, err := tx.CAKey.Update().Where(cakey.ID(r1.ID), cakey.StatusEQ(cakey.StatusOverlap)).SetStatus(cakey.StatusRetired).Save(ctx)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrRotated
	}
	// The signing keys that chain to the old root give way to the next ones, which agents hold.
	for _, sw := range p.swaps {
		if n, err := tx.CAKey.Update().Where(cakey.ID(sw.old), cakey.StatusEQ(cakey.StatusActive)).SetStatus(cakey.StatusRetired).Save(ctx); err != nil {
			return nil, err
		} else if n != 1 {
			return nil, ErrRotated
		}
		if n, err := tx.CAKey.Update().Where(cakey.ID(sw.next), cakey.StatusEQ(cakey.StatusNext)).SetStatus(cakey.StatusActive).Save(ctx); err != nil {
			return nil, err
		} else if n != 1 {
			return nil, ErrRotated
		}
	}
	// Nothing signs under the old root any more: its key, those of the intermediates it signed and those
	// of every signing key that chained to one of them are wiped, so that a copy of the database no longer
	// holds them. That the root was offline is recorded in was_offline, which the key's absence no longer says.
	r1cert, err := x509.ParseCertificate(r1.Certificate)
	if err != nil {
		return nil, err
	}
	wipe := []string{r1.ID}
	var inters []*x509.Certificate
	olds, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusRetired)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, o := range olds {
		if c, err := x509.ParseCertificate(o.Certificate); err == nil && c.CheckSignatureFrom(r1cert) == nil {
			wipe = append(wipe, o.ID)
			inters = append(inters, c)
		}
	}
	for _, sw := range p.swaps {
		wipe = append(wipe, sw.old)
	}
	signers, err := tx.CAKey.Query().Where(cakey.KindIn(cakey.KindConfigSigning, cakey.KindAuditCheckpoint), cakey.StatusEQ(cakey.StatusRetired)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		c, err := x509.ParseCertificate(s.Certificate)
		if err != nil {
			continue
		}
		for _, in := range inters {
			if c.CheckSignatureFrom(in) == nil {
				wipe = append(wipe, s.ID)
				break
			}
		}
	}
	if err := tx.CAKey.Update().Where(cakey.IDIn(wipe...), cakey.KeyEncNotNil()).ClearKeyEnc().Exec(ctx); err != nil {
		return nil, err
	}
	return []string{"old root dropped from the trust bundle"}, nil
}

// ErrNoSigner is returned by the drop of the old root when an active signing key chains to it and no
// next key issued under the new intermediate can replace it: the agents would be left with
// snapshots they cannot verify.
var ErrNoSigner = errors.New("pki: a signing key still chains to the old root and no next key under the new root can replace it")

// signerSwaps pairs each active signing key that the active intermediate did not sign with the next
// key of its kind that it did.
func signerSwaps(rows []*ent.CAKey) ([]signerSwap, error) {
	var inter *x509.Certificate
	for _, r := range rows {
		if r.Kind == cakey.KindIntermediate && r.Status == cakey.StatusActive {
			c, err := x509.ParseCertificate(r.Certificate)
			if err != nil {
				return nil, err
			}
			inter = c
		}
	}
	if inter == nil {
		return nil, errors.New("pki: the database holds no active intermediate")
	}
	signedByNew := func(r *ent.CAKey) bool {
		c, err := x509.ParseCertificate(r.Certificate)
		return err == nil && c.CheckSignatureFrom(inter) == nil
	}
	var swaps []signerSwap
	for _, kind := range []cakey.Kind{cakey.KindConfigSigning, cakey.KindAuditCheckpoint} {
		var a, n *ent.CAKey
		for _, r := range rows {
			switch {
			case r.Kind == kind && r.Status == cakey.StatusActive:
				a = r
			case r.Kind == kind && r.Status == cakey.StatusNext && len(r.Certificate) > 0 && signedByNew(r):
				n = r
			}
		}
		switch {
		case a == nil || signedByNew(a):
		case n == nil:
			return nil, fmt.Errorf("%w (%s)", ErrNoSigner, kind)
		default:
			swaps = append(swaps, signerSwap{old: a.ID, next: n.ID})
		}
	}
	return swaps, nil
}

// DropAfter is the earliest date the old root in the overlap, row r, may be dropped: the later of the
// date recorded when issuing moved and its start plus overlap, the one the settings give now. It is
// zero for a row that does not record when issuing moved.
func DropAfter(r *ent.CAKey, overlap time.Duration) time.Time {
	if r.RotatedAt == nil {
		return time.Time{}
	}
	d := r.RotatedAt.Add(overlap)
	if r.DropAfter != nil && r.DropAfter.After(d) {
		d = *r.DropAfter
	}
	return d
}

// StragglersSince is the time from which an agent that was seen counts as one that may still need the
// old root: since issuing moved, and, for a drop with Force, since the longest a leaf and the Reauth
// grace can reach back, so that an agent that was offline across the switch and may still renew
// through the old root holds the drop back too. It is the start of the overlap the old root has.
func StragglersSince(r1 *ent.CAKey, now time.Time, o DropOptions) time.Time {
	since := *r1.RotatedAt
	if o.Force {
		window := o.Overlap
		if r1.DropAfter != nil && r1.DropAfter.Sub(*r1.RotatedAt) > window {
			window = r1.DropAfter.Sub(*r1.RotatedAt)
		}
		if w := now.Add(-window); w.Before(since) {
			since = w
		}
	}
	return since
}

// PlanAbortNewRoot is `rpmgr ca new-root --abort`: it removes the new root and the new intermediate that
// wait for the old root's signatures, so that a rotation that stalled can be given up and started
// again. It refuses once issuing moved (ErrSwitched): that rotation ends with the drop of the old root.
// It opens no key. Apply repeats the checks in its transaction and fails with ErrRotated if the keys
// changed meanwhile. It needs the system scope.
func PlanAbortNewRoot(ctx context.Context, c *ent.CAKeyClient, now time.Time) (*Plan, error) {
	rows, err := readActive(ctx, c)
	if err != nil {
		return nil, err
	}
	r := sortRows(rows)
	switch {
	case r.overlap:
		return nil, ErrSwitched
	case r.next[cakey.KindRoot] == nil:
		return nil, ErrNothingToAbort
	case r.active[cakey.KindRoot] == nil:
		return nil, errors.New("pki: the database holds no active root")
	}
	p := &Plan{seen: keysSeen(rows), now: now, lock: r.active[cakey.KindRoot].ID}
	p.steps = []planStep{{done: "the new root that waited for the old root's signatures removed", remove: r.next[cakey.KindRoot].ID}}
	if ni := r.next[cakey.KindIntermediate]; ni != nil {
		p.steps = append(p.steps, planStep{done: "the new intermediate that waited for the old root's signatures removed", remove: ni.ID})
	}
	return p, nil
}
