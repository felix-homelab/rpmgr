// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// The rotation schedule of the CA's keys (docs/04-security.md, "CA hierarchy", "CA rotation").
const (
	// SignerNextBefore is how long before the active signing key's certificate expires the next
	// key is created; agents receive its certificate in every Welcome from then on.
	SignerNextBefore = 90 * 24 * time.Hour
	// SignerPromoteBefore is how long before it expires the next key replaces it. The replaced key
	// stays verifiable until its certificate expires.
	SignerPromoteBefore = 60 * 24 * time.Hour
)

// ErrRotated is returned when the CA's active keys changed while a plan was made and written:
// another rotation, request or ceremony came first.
var ErrRotated = errors.New("pki: the CA's keys changed meanwhile: another rotation, request or ceremony came first")

// A Plan is a rotation worked out before its transaction: the keys it needs are opened, the new
// ones made and sealed, all of which may wait for a key service, which a write transaction must not.
// Apply writes it, and fails with ErrRotated if the active keys are not the ones it was made from.
type Plan struct {
	seen  string
	steps []planStep
	// lock is the root that Apply locks first, when a step makes a request for a signature.
	lock string
	// csr is the request (PEM) of a PlanSigningRequest: the new one, or the one that waits.
	csr []byte
	// now is when the plan was made, which a step that starts an overlap records.
	now time.Time
	// config is set when the plan changes the trust bundle or the root that issues: its caller
	// writes it in a configuration transaction, so that the snapshots agents get carry a new
	// revision and the roots in them are ordered by it.
	config bool
	// requests are the requests an offline old root has to sign, of PlanNewRoot.
	requests *RootRequests
	// newRoot is the new root of a PlanNewRoot that makes one.
	newRoot *x509.Certificate
	// overlap, when set, is how long the old root stays after a step that starts an overlap: the date is
	// recorded on the old root, so that a later change of the settings cannot shorten it.
	overlap time.Duration
	// from and to are the hashes of the public keys of the root that stopped issuing and of the one that
	// issues now, once Apply moved issuing.
	from, to string
}

// WithOverlap sets the overlap a plan that moves issuing to a new root records: the earliest drop
// date of the old root is the moment issuing moved plus d.
func (p *Plan) WithOverlap(d time.Duration) *Plan {
	p.overlap = d
	return p
}

// NewRoot returns the new root that a plan of PlanNewRoot makes; nil for a plan that makes none.
func (p *Plan) NewRoot() *x509.Certificate { return p.newRoot }

// RootSwitch returns, after Apply, the SHA-256 hashes of the public keys of the root that stopped
// issuing and of the one that issues now; both are empty for a plan that moved no issuing. The caller
// logs them as the `root_switched` marker of the revocation log.
func (p *Plan) RootSwitch() (from, to string) { return p.from, p.to }

// Config reports whether the plan changes the trust bundle or the root that issues, so that its
// caller must write it in a configuration transaction (store.ConfigTx) and not a plain write.
func (p *Plan) Config() bool { return p.config }

type planStep struct {
	done            string
	retire, promote string // IDs of keys: retire an active one, activate a next one
	retireNext      string // ID of a next key to retire
	remove          string // ID of a next key to delete (the abort of a root rotation)
	overlap         string // ID of the active root that enters the overlap of a root rotation
	create          *newKey
}

type newKey struct {
	id     string
	kind   cakey.Kind
	status cakey.Status
	kp     pki.KeyPair
	sealed []byte
	// cross is the certificate an old root signed for this key (a root rotation's X or Y); csr is the
	// request an offline old root signs it from.
	cross, csr []byte
	// request is set for a next intermediate that waits for the offline root's signature: it has no
	// certificate, and the key and the validity it is expected to get are in pub, csr and the times.
	request *signingRequest
}

type signingRequest struct {
	pub, csr            []byte
	notBefore, notAfter time.Time
}

// keysSeen names the active and next keys of rows and whether a key is offline, to tell a changed
// set: a plan made before the root went offline must not be applied after it.
func keysSeen(rows []*ent.CAKey) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.ID + ":" + string(r.Status))
		if keyOffline(r) {
			b.WriteString(":offline")
		}
		if len(r.CrossCertificate) > 0 {
			b.WriteString(":cross")
		}
		b.WriteString(";")
	}
	return b.String()
}

func readActive(ctx context.Context, c *ent.CAKeyClient) ([]*ent.CAKey, error) {
	return c.Query().Where(cakey.StatusIn(cakey.StatusActive, cakey.StatusNext, cakey.StatusOverlap)).Order(ent.Asc(cakey.FieldID)).All(ctx)
}

// sealNew makes a key record for kp, sealing its private key with s. It runs before the
// transaction that writes the record.
func sealNew(ctx context.Context, s *secret.Sealer, kind cakey.Kind, kp pki.KeyPair, status cakey.Status) (*newKey, error) {
	k := &newKey{id: ids.New("cak"), kind: kind, status: status, kp: kp}
	var err error
	k.sealed, err = sealKey(ctx, s, k.id, kp.Key)
	return k, err
}

// sealKey seals the private key of the row id (PKCS #8, cleared afterwards).
func sealKey(ctx context.Context, s *secret.Sealer, id string, key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return s.Seal(ctx, keyContext(id), secret.FromBytes(der))
}

// PlanRotation brings the CA's keys up to the schedule at now, from the keys c reads, which may be
// outside a transaction; Apply writes it and returns what it changed:
//   - the intermediate is replaced at half its lifetime; the old one is retired and keeps
//     verifying the leaves it issued until it expires;
//   - the config-signing and the audit-checkpoint key each get a next key SignerNextBefore their
//     certificate expires, which replaces them SignerPromoteBefore it does.
//
// Every new key is sealed under s, here and so before the transaction. The caller runs it as a
// singleton job and reloads the CA afterwards. It needs the system scope.
func PlanRotation(ctx context.Context, c *ent.CAKeyClient, s *secret.Sealer, now time.Time) (*Plan, error) {
	return plan(ctx, c, s, now, false)
}

// PlanIntermediateRotation replaces the active intermediate now, before its half-life: the old one
// is retired and keeps verifying the leaves it issued until it expires (docs/04-security.md, "CA
// rotation"). It refuses an offline root (ErrRootOffline). The caller reloads the CA afterwards.
func PlanIntermediateRotation(ctx context.Context, c *ent.CAKeyClient, s *secret.Sealer, now time.Time) (*Plan, error) {
	return plan(ctx, c, s, now, true)
}

func plan(ctx context.Context, c *ent.CAKeyClient, s *secret.Sealer, now time.Time, forceIntermediate bool) (*Plan, error) {
	rows, err := readActive(ctx, c)
	if err != nil {
		return nil, err
	}
	p := &Plan{seen: keysSeen(rows), now: now}
	active, next := map[cakey.Kind]*ent.CAKey{}, map[cakey.Kind]*ent.CAKey{}
	overlap := false // a root in the overlap of a root rotation
	for _, r := range rows {
		switch r.Status {
		case cakey.StatusActive:
			active[r.Kind] = r
		case cakey.StatusOverlap:
			overlap = true
		default:
			next[r.Kind] = r
		}
	}
	// While a root rotation runs, from the new root's request until the old root is dropped, the
	// intermediate is not rotated: the next intermediate is the rotation's, and an intermediate made
	// in the overlap would need the old root's signature as well.
	rotating := next[cakey.KindRoot] != nil || overlap
	if rotating && forceIntermediate {
		return nil, ErrRotationInProgress
	}
	if active[cakey.KindRoot] == nil || active[cakey.KindIntermediate] == nil {
		return nil, fmt.Errorf("pki: the database holds no active root or intermediate")
	}
	root, err := x509.ParseCertificate(active[cakey.KindRoot].Certificate)
	if err != nil {
		return nil, err
	}
	old := active[cakey.KindIntermediate]
	rootOffline := keyOffline(active[cakey.KindRoot])
	halfLife := !now.Before(old.NotBefore.Add(old.NotAfter.Sub(old.NotBefore) / 2))
	var inter pki.KeyPair
	if nr := next[cakey.KindRoot]; nr != nil && next[cakey.KindIntermediate] != nil && len(nr.CrossCertificate) > 0 &&
		len(next[cakey.KindIntermediate].CrossCertificate) > 0 {
		// The old root signed both: issuing moves to the new root.
		if err := planSwitch(ctx, s, p, active, next, now); err != nil {
			return nil, err
		}
		return p, nil
	}
	switch {
	case rotating:
		inter, err = openKey(ctx, s, old)
	case forceIntermediate && rootOffline:
		return nil, ErrRootOffline
	case !forceIntermediate && !halfLife:
		inter, err = openKey(ctx, s, old)
	case rootOffline:
		// An offline root cannot sign: ask for a signature, and go on with the old intermediate until
		// the signed one is imported and valid.
		n := next[cakey.KindIntermediate]
		switch {
		case n == nil:
			var nk *newKey
			if nk, err = newSigningRequest(ctx, s, now); err != nil {
				return nil, err
			}
			p.lock = active[cakey.KindRoot].ID
			p.csr = nk.request.csr
			p.steps = append(p.steps, planStep{done: "intermediate needs signing", create: nk})
			inter, err = openKey(ctx, s, old)
		case len(n.Certificate) == 0, now.Before(n.NotBefore) || !now.Before(n.NotAfter):
			// It still waits for its signature, or the signed one is not valid now: never make an
			// intermediate active that issues leaves nobody accepts. IntermediateSigningAlert says so, on
			// Settings -> PKI and in the log of every run; this is no change, so no audit entry each hour.
			inter, err = openKey(ctx, s, old)
		default:
			if inter, err = openKey(ctx, s, n); err == nil {
				p.steps = append(p.steps, planStep{done: "intermediate replaced by the signed next one", retire: old.ID, promote: n.ID})
			}
		}
	default:
		var rootKP pki.KeyPair
		if rootKP, err = openKey(ctx, s, active[cakey.KindRoot]); err != nil {
			return nil, err
		}
		if inter, err = pki.NewIntermediate(rootKP, now); err != nil {
			return nil, err
		}
		var nk *newKey
		if nk, err = sealNew(ctx, s, cakey.KindIntermediate, inter, cakey.StatusActive); err != nil {
			return nil, err
		}
		p.steps = append(p.steps, planStep{done: "intermediate rotated", retire: old.ID, create: nk})
	}
	if err != nil {
		return nil, err
	}
	if forceIntermediate {
		return p, nil
	}
	is, err := pki.NewIssuer(root, inter, func() time.Time { return now })
	if err != nil {
		return nil, err
	}
	for kind, purpose := range map[cakey.Kind]pki.Purpose{
		cakey.KindConfigSigning: pki.PurposeConfigSigning, cakey.KindAuditCheckpoint: pki.PurposeAuditCheckpoint,
	} {
		a, n := active[kind], next[kind]
		if a == nil {
			return nil, fmt.Errorf("pki: the database holds no active %s key", kind)
		}
		switch {
		case n != nil && !now.Before(a.NotAfter.Add(-SignerPromoteBefore)):
			p.steps = append(p.steps, planStep{done: string(kind) + " key replaced by the next one", retire: a.ID, promote: n.ID})
		case n == nil && !now.Before(a.NotAfter.Add(-SignerNextBefore)):
			key, err := pki.NewKey()
			if err != nil {
				return nil, err
			}
			cert, err := is.IssueSigner(&key.PublicKey, purpose)
			if err != nil {
				return nil, err
			}
			nk, err := sealNew(ctx, s, kind, pki.KeyPair{Cert: cert, Key: key}, cakey.StatusNext)
			if err != nil {
				return nil, err
			}
			p.steps = append(p.steps, planStep{done: "next " + string(kind) + " key created", create: nk})
		}
	}
	return p, nil
}

// Apply writes the plan in tx and returns what it changed. The old intermediate is retired only
// while it is still active, so of two rotations at once one fails with ErrRotated instead of
// leaving two active intermediates.
func (p *Plan) Apply(ctx context.Context, tx *ent.Tx) ([]string, error) {
	// PostgreSQL runs at READ COMMITTED: two plans could both find the keys they saw. Taking the root's
	// row lock first, whatever the plan, makes them take turns, and the second then sees the first's keys.
	lock := p.lock
	if lock == "" {
		id, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).OnlyID(ctx)
		if err != nil {
			return nil, err
		}
		lock = id
	}
	if err := lockRoot(ctx, tx, lock); err != nil {
		return nil, err
	}
	rows, err := readActive(ctx, tx.CAKey)
	if err != nil {
		return nil, err
	}
	if keysSeen(rows) != p.seen {
		return nil, ErrRotated
	}
	var done []string
	for _, st := range p.steps {
		if st.overlap != "" {
			u := tx.CAKey.Update().Where(cakey.ID(st.overlap), cakey.StatusEQ(cakey.StatusActive)).
				SetStatus(cakey.StatusOverlap).SetRotatedAt(p.now)
			if p.overlap > 0 {
				u.SetDropAfter(p.now.Add(p.overlap))
			}
			for _, r := range rows {
				if r.ID == st.overlap {
					u.SetWasOffline(keyOffline(r))
				}
			}
			n, err := u.Save(ctx)
			if err != nil {
				return nil, err
			}
			if n != 1 {
				return nil, ErrRotated
			}
			p.from = hashOfRow(rows, st.overlap)
		}
		if st.retireNext != "" {
			n, err := tx.CAKey.Update().Where(cakey.ID(st.retireNext), cakey.StatusEQ(cakey.StatusNext)).SetStatus(cakey.StatusRetired).Save(ctx)
			if err != nil {
				return nil, err
			}
			if n != 1 {
				return nil, ErrRotated
			}
		}
		if st.remove != "" {
			n, err := tx.CAKey.Delete().Where(cakey.ID(st.remove), cakey.StatusEQ(cakey.StatusNext)).Exec(ctx)
			if err != nil {
				return nil, err
			}
			if n != 1 {
				return nil, ErrRotated
			}
		}
		if st.retire != "" {
			n, err := tx.CAKey.Update().Where(cakey.ID(st.retire), cakey.StatusEQ(cakey.StatusActive)).SetStatus(cakey.StatusRetired).Save(ctx)
			if err != nil {
				return nil, err
			}
			if n != 1 {
				return nil, ErrRotated
			}
		}
		if st.promote != "" {
			if err := tx.CAKey.UpdateOneID(st.promote).SetStatus(cakey.StatusActive).Exec(ctx); err != nil {
				return nil, err
			}
			if p.from != "" && p.to == "" {
				p.to = hashOfRow(rows, st.promote)
			}
		}
		if k := st.create; k != nil {
			if k.kind == cakey.KindRoot && k.status == cakey.StatusActive {
				p.to = pki.PublicKeyHash(k.kp.Cert.RawSubjectPublicKeyInfo)
			}
			if err := store.RecordSealed(ctx, tx, keyContext(k.id), k.sealed); err != nil {
				return nil, err
			}
			c := tx.CAKey.Create().SetID(k.id).SetKind(k.kind).SetAlgorithm(keyAlgorithm).SetKeyEnc(k.sealed).SetStatus(k.status)
			if r := k.request; r != nil {
				// Not before and not after hold the validity the root will most likely give; the
				// certificate's replace them at the import.
				c.SetPublicKey(r.pub).SetCsr(r.csr).SetNotBefore(r.notBefore).SetNotAfter(r.notAfter)
			} else {
				c.SetPublicKey(k.kp.Cert.RawSubjectPublicKeyInfo).SetCertificate(k.kp.Cert.Raw).
					SetNotBefore(k.kp.Cert.NotBefore).SetNotAfter(k.kp.Cert.NotAfter)
			}
			if len(k.cross) > 0 {
				c.SetCrossCertificate(k.cross)
			}
			if k.request == nil && len(k.csr) > 0 {
				c.SetCsr(k.csr)
			}
			if err := c.Exec(ctx); err != nil {
				return nil, err
			}
		}
		if st.done != "" {
			done = append(done, st.done)
		}
	}
	return done, nil
}

// hashOfRow is the SHA-256 hash of the public key of the row id among rows, "" if it is not there.
func hashOfRow(rows []*ent.CAKey, id string) string {
	for _, r := range rows {
		if r.ID == id {
			return pki.PublicKeyHash(r.PublicKey)
		}
	}
	return ""
}
