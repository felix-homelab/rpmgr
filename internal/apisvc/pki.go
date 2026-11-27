// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// Pki is PkiService. The CA's keys are instance rows, which its methods read and change in the
// controller's system scope.
type Pki struct {
	rpmgrv1connect.UnimplementedPkiServiceHandler
	DB     *store.DB
	Sys    context.Context
	Sealer *secret.Sealer
	// CA is reloaded after a rotation, so this replica issues from the new intermediate at once;
	// the others reload within a minute.
	CA  *castore.CA
	Now func() time.Time
}

var (
	caKeyKinds = map[cakey.Kind]rpmgrv1.CAKeyKind{cakey.KindRoot: rpmgrv1.CAKeyKind_CA_KEY_KIND_ROOT,
		cakey.KindIntermediate: rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE, cakey.KindConfigSigning: rpmgrv1.CAKeyKind_CA_KEY_KIND_CONFIG_SIGNING,
		cakey.KindAuditCheckpoint: rpmgrv1.CAKeyKind_CA_KEY_KIND_AUDIT_CHECKPOINT}
	caKeyStates = map[cakey.Status]rpmgrv1.CAKeyState{cakey.StatusNext: rpmgrv1.CAKeyState_CA_KEY_STATE_NEXT,
		cakey.StatusActive: rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE, cakey.StatusRetired: rpmgrv1.CAKeyState_CA_KEY_STATE_RETIRED,
		// The old root in the overlap of a rotation no longer issues but is still trusted: no enum value says
		// that, and RETIRED would say agents may drop it, so it is reported as ACTIVE until it is dropped.
		cakey.StatusOverlap: rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE,
		// A key replaced as compromised is shown as retired, which says only that it no longer issues; `rpmgr ca
		// status` adds that the root was replaced as compromised and who has not enrolled again.
		cakey.StatusCompromised: rpmgrv1.CAKeyState_CA_KEY_STATE_RETIRED}
)

// GetPkiStatus implements PkiService.
func (p *Pki) GetPkiStatus(ctx context.Context, _ *connect.Request[rpmgrv1.GetPkiStatusRequest]) (
	*connect.Response[rpmgrv1.GetPkiStatusResponse], error) {
	sys := store.CarryTxHook(p.Sys, ctx)
	c := p.DB.ReadClient()
	inst, err := c.Instance.Get(sys, 1)
	if err != nil {
		return nil, storeError(err)
	}
	rows, err := c.CAKey.Query().Where(cakey.NotAfterGT(p.now().UTC())).All(sys)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.GetPkiStatusResponse{TrustDomain: inst.TrustDomain}
	for _, r := range rows {
		if len(r.Certificate) == 0 {
			continue // a next intermediate that waits for the signature of an offline root
		}
		k, err := caKeyOf(r)
		if err != nil {
			return nil, err
		}
		if r.Kind == cakey.KindRoot && r.Status == cakey.StatusActive {
			out.RootOffline = r.KeyEnc == nil || len(*r.KeyEnc) == 0
		}
		// The pin new agents enroll with: the active root, or in the overlap of a root rotation the old
		// one, so that they hold both roots (docs/04-security.md, "Root rotation").
		if r.Kind == cakey.KindRoot && (r.Status == cakey.StatusOverlap || r.Status == cakey.StatusActive && out.RootPin == "") {
			root, err := x509.ParseCertificate(r.Certificate)
			if err != nil {
				return nil, err
			}
			out.RootPin = pki.RootPin(root)
		}
		out.Keys = append(out.Keys, k)
	}
	if out.RootOffline {
		if out.RootKeyResidueKek, out.RootKekUnknown, err = castore.RootKeyResidue(sys, p.DB); err != nil {
			return nil, storeError(err)
		}
		if err := p.signingAlert(sys, out); err != nil {
			return nil, storeError(err)
		}
	}
	// Active, then next, then retired; by kind; the newest first.
	rank := map[rpmgrv1.CAKeyState]int{rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE: 0, rpmgrv1.CAKeyState_CA_KEY_STATE_NEXT: 1,
		rpmgrv1.CAKeyState_CA_KEY_STATE_RETIRED: 2}
	slices.SortFunc(out.Keys, func(a, b *rpmgrv1.CAKey) int {
		return cmp.Or(cmp.Compare(rank[a.GetState()], rank[b.GetState()]), cmp.Compare(a.GetKind(), b.GetKind()),
			b.GetNotBefore().AsTime().Compare(a.GetNotBefore().AsTime()))
	})
	return connect.NewResponse(out), nil
}

var signingAlerts = map[castore.SigningAlert]rpmgrv1.SigningAlert{castore.AlertNeedsSigning: rpmgrv1.SigningAlert_SIGNING_ALERT_NEEDS_SIGNING,
	castore.AlertCritical: rpmgrv1.SigningAlert_SIGNING_ALERT_CRITICAL, castore.AlertNextNotValid: rpmgrv1.SigningAlert_SIGNING_ALERT_NEXT_NOT_VALID}

// signingAlert sets the alert of an offline root: the next intermediate waits for a signature, or
// holds one that is not valid now (docs/04-security.md, "Offline root CA").
func (p *Pki) signingAlert(ctx context.Context, out *rpmgrv1.GetPkiStatusResponse) error {
	a, err := castore.IntermediateSigningAlert(ctx, p.DB, p.now())
	if err != nil || a == castore.AlertNone {
		return err
	}
	out.SigningAlert = signingAlerts[a]
	out.NextIntermediateKeyHash, err = castore.NextIntermediateKeyHash(ctx, p.DB)
	return err
}

// RotateIntermediate implements PkiService. Of two rotations at once, on this replica or with the
// rotation job, the second is ABORTED.
func (p *Pki) RotateIntermediate(ctx context.Context, _ *connect.Request[rpmgrv1.RotateIntermediateRequest]) (
	*connect.Response[rpmgrv1.RotateIntermediateResponse], error) {
	sys := store.CarryTxHook(p.Sys, ctx)
	var row *ent.CAKey
	// Planned before the transaction: opening and sealing keys may wait for a key service.
	plan, err := castore.PlanIntermediateRotation(sys, p.DB.ReadClient().CAKey, p.Sealer, p.now())
	if errors.Is(err, castore.ErrRootOffline) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err != nil {
		return nil, storeError(err)
	}
	err = store.WriteTx(sys, p.DB, func(tx *ent.Tx) error {
		if _, err := plan.Apply(sys, tx); err != nil {
			return err
		}
		var err error
		row, err = tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusActive)).Only(sys)
		return err
	})
	// The plan refused an offline root before the transaction; a root that went offline since changes
	// the keys the plan saw, which is ErrRotated.
	if errors.Is(err, castore.ErrRotated) {
		return nil, connect.NewError(connect.CodeAborted, err)
	}
	if err != nil {
		return nil, storeError(err)
	}
	if p.CA != nil {
		if _, err := p.CA.Reload(sys, p.DB, p.Sealer, p.now); err != nil {
			return nil, err
		}
	}
	k, err := caKeyOf(row)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.RotateIntermediateResponse{Intermediate: k}), nil
}

func (p *Pki) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// caKeyOf is a key of the CA as the API shows it, with the time the schedule replaces it if it is
// active (castore.PlanRotation).
func caKeyOf(r *ent.CAKey) (*rpmgrv1.CAKey, error) {
	cert, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.CAKey{Kind: caKeyKinds[r.Kind], State: caKeyStates[r.Status], Subject: cert.Subject.String(),
		NotBefore: timestamppb.New(r.NotBefore), NotAfter: timestamppb.New(r.NotAfter)}
	if r.Status == cakey.StatusActive {
		switch r.Kind {
		case cakey.KindIntermediate:
			out.RotateTime = timestamppb.New(r.NotBefore.Add(r.NotAfter.Sub(r.NotBefore) / 2))
		case cakey.KindConfigSigning, cakey.KindAuditCheckpoint:
			out.RotateTime = timestamppb.New(r.NotAfter.Add(-castore.SignerPromoteBefore))
		}
	}
	return out, nil
}
