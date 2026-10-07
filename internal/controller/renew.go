// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Renew issues the caller a new certificate for a CSR with a new key, bound to this connection
// (docs/04-security.md, "Leaf certificates", "Flow").
func (s *Sessions) Renew(ctx context.Context, req *agentv1.RenewRequest) (*agentv1.RenewResponse, error) {
	chain, err := renew(ctx, s.db, s.ca, s.sys, s.now, req.GetCsr())
	if err != nil {
		return nil, err
	}
	return &agentv1.RenewResponse{Chain: chain}, nil
}

// ReauthService answers Reauth at reauth.controller.<td>, where the TLS layer accepted a client
// certificate that expired at most the grace period ago (ReauthChecks).
type ReauthService struct {
	agentv1.UnimplementedReauthServer
	db  *store.DB
	ca  *pki.CA
	sys context.Context
	now func() time.Time
}

// NewReauthService returns the Reauth service; sys is the audited system scope it works in.
func NewReauthService(db *store.DB, ca *pki.CA, sys context.Context, now func() time.Time) *ReauthService {
	if now == nil {
		now = time.Now
	}
	return &ReauthService{db: db, ca: ca, sys: sys, now: now}
}

// Reauth issues a new certificate for an agent whose certificate expired within the grace period.
func (r *ReauthService) Reauth(ctx context.Context, req *agentv1.ReauthRequest) (*agentv1.ReauthResponse, error) {
	chain, err := renew(ctx, r.db, r.ca, r.sys, r.now, req.GetCsr())
	if err != nil {
		return nil, err
	}
	return &agentv1.ReauthResponse{Chain: chain}, nil
}

// ReauthChecks are the database checks of the Reauth verifier: the grace period from the instance
// settings, and that the presented certificate may be renewed. A settings read that fails gives
// no grace, so the verifier refuses every expired certificate.
func ReauthChecks(db *store.DB, sys context.Context) pki.Reauth {
	return pki.Reauth{
		Grace: func() time.Duration {
			inst, _, err := settings.Instance(sys, db.Client())
			if err != nil {
				return 0
			}
			return inst.GetExpiredCertificateGrace().AsDuration()
		},
		Check: func(leaf *x509.Certificate) error { return pki.CheckRenewable(sys, db.Client(), leaf) },
	}
}

// renew checks that the CSR is bound to the caller's connection and that the presented
// certificate may be renewed, records that it was seen, and issues the new leaf, all in one
// transaction.
func renew(ctx context.Context, db *store.DB, ca *pki.CA, sys context.Context, now func() time.Time, der []byte) ([][]byte, error) {
	agent, ok := AgentFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	p, _ := peer.FromContext(ctx)
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "not TLS")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the CSR does not parse")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Error(codes.InvalidArgument, "the CSR's signature does not verify")
	}
	if err := pki.VerifyBinding(csr, tls.ConnectionState(info.State)); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	var cert *x509.Certificate
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		if err := pki.CheckRenewable(sys, tx.Client(), agent.Certificate); err != nil {
			return err
		}
		if err := pki.MarkSeen(sys, tx, agent.Certificate, now()); err != nil {
			return err
		}
		inst, _, err := settings.Instance(sys, tx.Client())
		if err != nil {
			return err
		}
		cert, err = ca.Renew(sys, tx, agent.Certificate, csr, inst.GetLeafCertificateLifetime().AsDuration())
		return err
	})
	switch {
	case errors.Is(err, pki.ErrNotIssued), errors.Is(err, pki.ErrCertRevoked), errors.Is(err, pki.ErrSuperseded):
		return nil, status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, pki.ErrSameKey), errors.Is(err, pki.ErrBadCSR):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		return nil, status.Error(codes.Unavailable, "the controller cannot issue certificates now")
	}
	return [][]byte{cert.Raw, ca.Intermediate().Raw}, nil
}
