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
	CA  *pki.CA
	Now func() time.Time
}

var (
	caKeyKinds = map[cakey.Kind]rpmgrv1.CAKeyKind{cakey.KindRoot: rpmgrv1.CAKeyKind_CA_KEY_KIND_ROOT,
		cakey.KindIntermediate: rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE, cakey.KindConfigSigning: rpmgrv1.CAKeyKind_CA_KEY_KIND_CONFIG_SIGNING,
		cakey.KindAuditCheckpoint: rpmgrv1.CAKeyKind_CA_KEY_KIND_AUDIT_CHECKPOINT}
	caKeyStates = map[cakey.Status]rpmgrv1.CAKeyState{cakey.StatusNext: rpmgrv1.CAKeyState_CA_KEY_STATE_NEXT,
		cakey.StatusActive: rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE, cakey.StatusRetired: rpmgrv1.CAKeyState_CA_KEY_STATE_RETIRED}
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
		k, err := caKeyOf(r)
		if err != nil {
			return nil, err
		}
		if r.Kind == cakey.KindRoot && r.Status == cakey.StatusActive {
			root, err := x509.ParseCertificate(r.Certificate)
			if err != nil {
				return nil, err
			}
			out.RootPin = pki.RootPin(root)
		}
		out.Keys = append(out.Keys, k)
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

// RotateIntermediate implements PkiService. Of two rotations at once, on this replica or with the
// rotation job, the second is ABORTED.
func (p *Pki) RotateIntermediate(ctx context.Context, _ *connect.Request[rpmgrv1.RotateIntermediateRequest]) (
	*connect.Response[rpmgrv1.RotateIntermediateResponse], error) {
	sys := store.CarryTxHook(p.Sys, ctx)
	var row *ent.CAKey
	err := store.WriteTx(sys, p.DB, func(tx *ent.Tx) error {
		if err := pki.RotateIntermediate(sys, tx, p.Sealer, p.now()); err != nil {
			return err
		}
		var err error
		row, err = tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindIntermediate), cakey.StatusEQ(cakey.StatusActive)).Only(sys)
		return err
	})
	if errors.Is(err, pki.ErrRotated) {
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
// active (pki.Rotate).
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
			out.RotateTime = timestamppb.New(r.NotAfter.Add(-pki.SignerPromoteBefore))
		}
	}
	return out, nil
}
