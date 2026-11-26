// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
)

// The rotation of the root by cross-signing (docs/04-security.md, "Root rotation"; docs/10-operations.md,
// "Rotate the root").

// RotationOverlap is how long the old root stays in the bundle after issuing moved to the new one:
// the longest agent leaf lifetime plus the Reauth grace period (7 + 30 days with the defaults), so
// that an agent that was offline can still reauthenticate through it.
func RotationOverlap(ctx context.Context, c *ent.Client) (time.Duration, error) {
	inst, _, err := settings.Instance(ctx, c)
	if err != nil {
		return 0, err
	}
	return inst.GetLeafCertificateLifetime().AsDuration() + inst.GetExpiredCertificateGrace().AsDuration(), nil
}

// holdsNewRoot reports, for a roots digest an agent sent in Hello (lower-case hexadecimal), whether
// the agent holds the new root: the digest is that of the bundle's roots, or of the new root with any
// of the old ones. An agent without the capability "trust.roots" sends none and never does.
func holdsNewRoot(digest string, roots []*x509.Certificate) bool {
	if digest == "" || len(roots) == 0 {
		return false
	}
	old := roots[1:]
	// The new root is roots[0]; the old ones may or may not be held.
	for mask := 0; mask < 1<<len(old); mask++ {
		subset := []*x509.Certificate{roots[0]}
		for i, r := range old {
			if mask&(1<<i) != 0 {
				subset = append(subset, r)
			}
		}
		if digest == hex.EncodeToString(pki.RootsDigest(subset)) {
			return true
		}
	}
	return false
}

// Stragglers lists the enabled agents that were seen since `since` and do not hold the new root,
// from the roots digest of their Hello (docs/04-security.md, "Root rotation"): an agent that never
// connected, or was not seen since the overlap began, is not one, as it has no session to learn the
// root in. It reads through tx and needs the system scope.
func Stragglers(ctx context.Context, tx *ent.Tx, since time.Time) ([]string, error) {
	bundle, err := castore.BundleOf(ctx, tx.CAKey)
	if err != nil {
		return nil, err
	}
	var roots []*x509.Certificate // the issuing root first: BundleOf lists it first
	for _, c := range bundle {
		if c.CheckSignatureFrom(c) == nil {
			roots = append(roots, c)
		}
	}
	sessions, err := tx.AgentSession.Query().Where(agentsession.LastSeenAtGTE(since)).All(ctx)
	if err != nil {
		return nil, err
	}
	var lacking []string
	for _, s := range sessions {
		if !holdsNewRoot(s.RootsDigest, roots) {
			lacking = append(lacking, s.ID)
		}
	}
	if len(lacking) == 0 {
		return nil, nil
	}
	gws, err := tx.Gateway.Query().Where(gateway.IDIn(lacking...), gateway.Enabled(true), gateway.DecommissionedAtIsNil()).IDs(ctx)
	if err != nil {
		return nil, err
	}
	cons, err := tx.Connector.Query().Where(connector.IDIn(lacking...), connector.Enabled(true), connector.DecommissionedAtIsNil()).IDs(ctx)
	if err != nil {
		return nil, err
	}
	out := append(gws, cons...)
	slices.Sort(out)
	return out, nil
}

// stragglerCount is castore.StragglerCount over Stragglers.
func stragglerCount(ctx context.Context, tx *ent.Tx, since time.Time) (int, error) {
	l, err := Stragglers(ctx, tx, since)
	return len(l), err
}

// NewRootResult is what `rpmgr ca new-root` reports.
type NewRootResult struct {
	// Pin is the pin of the new root, with an online old root: issuing moved to it at once.
	Pin string
	// Requests are what the offline old root signs, with an offline one: the files written are
	// Out and Out + IntermediateSuffix.
	Requests *castore.RootRequests
	Done     []string
}

// IntermediateSuffix is appended to the --csr-out file for the request of the new intermediate.
const IntermediateSuffix = ".intermediate"

// NewRoot is `rpmgr ca new-root`: it makes the new root and its first intermediate, and with an
// online old root signs the cross-certificates and moves issuing to the new root at once, in one
// transaction. With an offline old root it needs csrOut and stops after it wrote the request of the
// new root there and that of the new intermediate to csrOut + IntermediateSuffix (neither may exist);
// the old root signs both on its host, and the rotation job moves issuing when they are imported. It
// needs the KEK. Beside a running controller, which loads the new keys within a minute.
func NewRoot(ctx context.Context, path, csrOut string, getenv func(string) string, now func() time.Time) (NewRootResult, error) {
	var res NewRootResult
	cfg, err := loadController(path)
	if err != nil {
		return res, err
	}
	kek, err := localWrapper(ctx, cfg, getenv)
	if err != nil {
		return res, err
	}
	sealer, err := secret.NewSealerWith(kek.Wrapper)
	if err != nil {
		return res, err
	}
	if csrOut != "" {
		if err := errors.Join(mustNotExist(csrOut), mustNotExist(csrOut+IntermediateSuffix)); err != nil {
			return res, err
		}
	}
	_, db, sys, err := openLocal(ctx, path, "rpmgr ca new-root")
	if err != nil {
		return res, err
	}
	defer func() { _ = db.Close() }()
	// The keys are made and sealed before the transaction: sealing may wait for a key service. If the
	// keys changed meanwhile, plan again.
	for attempt := 0; ; attempt++ {
		var plan *castore.Plan
		if plan, err = castore.PlanNewRoot(sys, db.ReadClient().CAKey, sealer, now()); err != nil {
			return res, err
		}
		if res.Requests = plan.Requests(); res.Requests != nil && csrOut == "" {
			return res, fmt.Errorf("%w: the old root is offline, so the new root's request goes to a file for it to sign: "+
				"run with --csr-out <file>", castore.ErrRootOffline)
		}
		overlap, oerr := RotationOverlap(sys, db.ReadClient())
		if oerr != nil {
			return res, oerr
		}
		plan.WithOverlap(overlap)
		if err = fault("planned", csrOut); err != nil {
			return res, err
		}
		res.Done, err = applyNewRoot(sys, db, plan, now)
		if !errors.Is(err, castore.ErrRotated) || attempt == 2 {
			if err == nil && plan.NewRoot() != nil && plan.Requests() == nil {
				res.Pin = pki.RootPin(plan.NewRoot())
			}
			break
		}
	}
	if errors.Is(err, castore.ErrRotated) {
		return res, fmt.Errorf("controller: the CA's keys changed on each of three attempts to make the new root (another rotation or "+
			"ceremony ran at the same time); look at `rpmgr ca status` and try again: %w", err)
	}
	if err != nil {
		return res, err
	}
	if res.Requests != nil {
		if err := writeNew(csrOut, res.Requests.Cross, 0o644); err != nil {
			return res, err
		}
		return res, writeNew(csrOut+IntermediateSuffix, res.Requests.Intermediate, 0o644)
	}
	return res, nil
}

// applyNewRoot writes the plan and the audit entry of the call: in a configuration transaction when
// it changes the trust bundle, so that agents get snapshots of a new revision that carry it.
func applyNewRoot(sys context.Context, db *store.DB, plan *castore.Plan, _ func() time.Time) ([]string, error) {
	var done []string
	write := func(tx *ent.Tx) error {
		var err error
		if done, err = plan.Apply(sys, tx); err != nil {
			return err
		}
		action, reason := "ca.new_root", "a new root, cross-signed by the old one, issues from now on"
		if plan.Requests() != nil {
			action, reason = "ca.request_new_root", "a new root and intermediate that wait for the offline root's signatures"
		}
		if len(done) == 0 {
			return nil // the requests that waited are shown again; nothing changed
		}
		_, err = audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: action,
			TargetType: "ca", Result: audit.Success, Reason: reason})
		return err
	}
	if plan.Config() {
		_, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) { return []string{"pki"}, write(tx) })
		return done, err
	}
	return done, store.WriteTx(sys, db, write)
}

// DropRootResult is what `rpmgr ca drop-root` reports.
type DropRootResult struct{ Done []string }

// DropRoot is `rpmgr ca drop-root`: the old root of a rotation leaves the bundle, which becomes the
// new root alone. It is refused before the overlap has passed since issuing moved (castore.DropEarlyError,
// naming the date), unless force is set and no agent is a straggler, and while enabled agents that were
// seen since lack the new root (castore.StragglersError), unless strand is set, which is accepted only after
// the overlap. It needs no KEK; running controllers load the new bundle within a minute and send agents a
// snapshot of a new revision that carries it.
func DropRoot(ctx context.Context, path string, force, strand bool, now func() time.Time) (DropRootResult, error) {
	var res DropRootResult
	_, db, sys, err := openLocal(ctx, path, "rpmgr ca drop-root")
	if err != nil {
		return res, err
	}
	defer func() { _ = db.Close() }()
	overlap, err := RotationOverlap(sys, db.ReadClient())
	if err != nil {
		return res, err
	}
	plan, err := castore.PlanDropRoot(sys, db.ReadClient().CAKey, now(), castore.DropOptions{Overlap: overlap, Force: force,
		Strand: strand, Stragglers: stragglerCount})
	if err != nil {
		return res, err
	}
	res.Done, err = applyDrop(sys, db, plan, "local-cli", dropReason(strand))
	return res, err
}

func dropReason(strand bool) string {
	if strand {
		return "the old root dropped although agents still lacked the new one (--strand-stragglers)"
	}
	return "the old root dropped from the trust bundle"
}

// applyDrop writes the drop of the old root and its audit entry in a configuration transaction. The
// caller adds to tx through fenced, if it must.
func applyDrop(sys context.Context, db *store.DB, plan *castore.DropPlan, actor, reason string, fenced ...func(*ent.Tx) error) ([]string, error) {
	var done []string
	_, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
		for _, f := range fenced {
			if err := f(tx); err != nil {
				return nil, err
			}
		}
		var err error
		if done, err = plan.Apply(sys, tx); err != nil {
			return nil, err
		}
		_, err = audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: actor, Action: "ca.drop_root",
			TargetType: "ca", Result: audit.Success, Reason: reason})
		return []string{"pki"}, err
	})
	return done, err
}

// RotationStatus is the state of a root rotation, for `rpmgr ca status`.
type RotationStatus struct {
	// Waiting is true after `ca new-root --csr-out`, until the old root's signatures are imported and the
	// rotation job moved issuing: the keys of the requests are KeyHashes.
	Waiting      bool
	KeyHashes    []string
	NeedsCross   bool // X was not imported yet
	NeedsInter   bool // Y was not imported yet
	Overlap      bool // issuing moved; the old root is in the bundle
	IssuingSince time.Time
	DropAfter    time.Time // when the old root can be dropped
	Roots        []RotationRoot
	Stragglers   []string // enabled agents seen since the overlap began that lack the new root
}

// RotationRoot is a root of the bundle.
type RotationRoot struct {
	Pin       string
	Issuing   bool
	NotAfter  time.Time
	Offline   bool
	CrossSign bool // the bundle carries a cross-certificate for it
}

// CARotationStatus is what `rpmgr ca status` adds during a root rotation. It needs no KEK; the
// zero value says no rotation runs.
func CARotationStatus(ctx context.Context, path string, now func() time.Time) (RotationStatus, error) {
	var st RotationStatus
	_, db, sys, err := openLocal(ctx, path, "rpmgr ca status")
	if err != nil {
		return st, err
	}
	defer func() { _ = db.Close() }()
	return rotationStatus(sys, db, now())
}

func rotationStatus(sys context.Context, db *store.DB, now time.Time) (RotationStatus, error) {
	var st RotationStatus
	c := db.ReadClient()
	rows, err := c.CAKey.Query().Where(cakey.KindIn(cakey.KindRoot, cakey.KindIntermediate),
		cakey.StatusIn(cakey.StatusActive, cakey.StatusNext, cakey.StatusOverlap)).Order(ent.Asc(cakey.FieldID)).All(sys)
	if err != nil {
		return st, err
	}
	var old *ent.CAKey
	// A next intermediate alone is an ordinary rotation of the intermediate that waits for the offline
	// root, not a root rotation: only a next root row makes one.
	nextRoot := slices.ContainsFunc(rows, func(r *ent.CAKey) bool { return r.Kind == cakey.KindRoot && r.Status == cakey.StatusNext })
	for _, r := range rows {
		switch r.Status {
		case cakey.StatusNext:
			if !nextRoot {
				continue
			}
			st.Waiting = true
			st.KeyHashes = append(st.KeyHashes, pki.PublicKeyHash(r.PublicKey))
			if len(r.CrossCertificate) == 0 {
				st.NeedsCross = st.NeedsCross || r.Kind == cakey.KindRoot
				st.NeedsInter = st.NeedsInter || r.Kind == cakey.KindIntermediate
			}
		case cakey.StatusOverlap:
			st.Overlap, old = true, r
		}
		if r.Kind != cakey.KindRoot || r.Status == cakey.StatusNext {
			continue
		}
		cert, err := x509.ParseCertificate(r.Certificate)
		if err != nil {
			return st, err
		}
		st.Roots = append(st.Roots, RotationRoot{Pin: pki.RootPin(cert), Issuing: r.Status == cakey.StatusActive, NotAfter: r.NotAfter,
			Offline: r.KeyEnc == nil || len(*r.KeyEnc) == 0, CrossSign: r.Status == cakey.StatusActive && len(r.CrossCertificate) > 0})
	}
	// The root that issues first.
	slices.SortStableFunc(st.Roots, func(a, b RotationRoot) int {
		switch {
		case a.Issuing == b.Issuing:
			return 0
		case a.Issuing:
			return -1
		}
		return 1
	})
	if old == nil || old.RotatedAt == nil {
		return st, nil
	}
	st.IssuingSince = *old.RotatedAt
	overlap, err := RotationOverlap(sys, c)
	if err != nil {
		return st, err
	}
	st.DropAfter = castore.DropAfter(old, overlap)
	// A read transaction for the stragglers, which read through one.
	err = store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		st.Stragglers, err = Stragglers(sys, tx, *old.RotatedAt)
		return err
	})
	return st, err
}
