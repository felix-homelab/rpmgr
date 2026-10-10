// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"strconv"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
)

// Audit implements AuditService (docs/07-api.md, "Services"; docs/04-security.md, "Audit log"):
// an org's chain for its Owners and Admins, the instance chain for the Instance Admin.
type Audit struct {
	rpmgrv1connect.UnimplementedAuditServiceHandler
	DB  *store.DB
	Sys context.Context // the system scope: the instance chain and the CA's certificates
	API *api.Server
}

// ListAuditEntries implements AuditService.
func (a *Audit) ListAuditEntries(ctx context.Context, req *connect.Request[rpmgrv1.ListAuditEntriesRequest]) (
	*connect.Response[rpmgrv1.ListAuditEntriesResponse], error) {
	m := req.Msg
	entries, next, err := a.list(ctx, m.GetOrgId(), m, m.GetPageSize(), m.GetPageToken(), m.GetAction(), m.GetActorId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ListAuditEntriesResponse{Entries: entries, NextPageToken: next}), nil
}

// ListInstanceAuditEntries implements AuditService.
func (a *Audit) ListInstanceAuditEntries(_ context.Context, req *connect.Request[rpmgrv1.ListInstanceAuditEntriesRequest]) (
	*connect.Response[rpmgrv1.ListInstanceAuditEntriesResponse], error) {
	m := req.Msg
	entries, next, err := a.list(a.Sys, "", m, m.GetPageSize(), m.GetPageToken(), m.GetAction(), m.GetActorId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ListInstanceAuditEntriesResponse{Entries: entries, NextPageToken: next}), nil
}

// list returns a page of the chain of orgID, newest first; the page token holds the seq of the
// last entry of the page before.
func (a *Audit) list(ctx context.Context, orgID string, req proto.Message, pageSize int32, token, action, actor string) (
	[]*rpmgrv1.AuditEntry, string, error) {
	size, err := api.PageSize(pageSize)
	if err != nil {
		return nil, "", err
	}
	after, err := a.API.AfterPage(token, req)
	if err != nil {
		return nil, "", err
	}
	q := a.DB.ReadClient().AuditEntry.Query().Order(ent.Desc(auditentry.FieldSeq)).Limit(size + 1)
	if orgID == "" {
		q.Where(auditentry.OrgIDIsNil())
	} else {
		q.Where(auditentry.OrgID(orgID))
	}
	if after != "" {
		seq, err := strconv.ParseInt(after, 10, 64)
		if err != nil {
			return nil, "", connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: the page token"))
		}
		q.Where(auditentry.SeqLT(seq))
	}
	if action != "" {
		q.Where(auditentry.Action(action))
	}
	if actor != "" {
		q.Where(auditentry.ActorID(actor))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, "", storeError(err)
	}
	next := ""
	if len(rows) > size {
		rows = rows[:size]
		next = a.API.PageToken(strconv.FormatInt(rows[size-1].Seq, 10), req)
	}
	out := make([]*rpmgrv1.AuditEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, &rpmgrv1.AuditEntry{Id: r.ID, Seq: r.Seq, Time: timestamppb.New(r.Ts), ActorType: string(r.ActorType),
			ActorId: r.ActorID, CredentialId: r.CredentialID, AuthMethod: r.AuthMethod, Ip: r.IP, UserAgent: r.UserAgent,
			RequestId: r.RequestID, Action: r.Action, TargetType: r.TargetType, TargetId: r.TargetID, Result: string(r.Result),
			Diff: r.Diff, Reason: r.Reason})
	}
	return out, next, nil
}

// VerifyAuditChain implements AuditService.
func (a *Audit) VerifyAuditChain(ctx context.Context, req *connect.Request[rpmgrv1.VerifyAuditChainRequest]) (
	*connect.Response[rpmgrv1.VerifyAuditChainResponse], error) {
	v, err := a.verify(ctx, req.Msg.GetOrgId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.VerifyAuditChainResponse{Verification: v}), nil
}

// VerifyInstanceAuditChain implements AuditService.
func (a *Audit) VerifyInstanceAuditChain(context.Context, *connect.Request[rpmgrv1.VerifyInstanceAuditChainRequest]) (
	*connect.Response[rpmgrv1.VerifyInstanceAuditChainResponse], error) {
	v, err := a.verify(a.Sys, "")
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.VerifyInstanceAuditChainResponse{Verification: v}), nil
}

// verify verifies the chain of orgID with every certificate the CA has had for audit checkpoints;
// a broken chain is an answer, not an error.
func (a *Audit) verify(ctx context.Context, orgID string) (*rpmgrv1.AuditVerification, error) {
	signers, inters, root, err := pki.SignerCertificates(a.Sys, a.DB, pki.PurposeAuditCheckpoint)
	if err != nil {
		return nil, err
	}
	head, last, err := audit.VerifyChain(ctx, a.DB, orgID, audit.Trust{Root: root, Intermediates: inters, Signers: signers})
	out := &rpmgrv1.AuditVerification{}
	var broken *audit.ChainError
	switch {
	case errors.As(err, &broken):
		out.BrokenAt, out.Problem = broken.Seq, broken.Problem
	case err != nil:
		return nil, err
	default:
		out.Intact, out.HeadSeq = true, head.Seq
	}
	if last != nil {
		out.LastCheckpoint = &rpmgrv1.AuditCheckpoint{Seq: last.Seq, Time: timestamppb.New(last.Time), KeyId: last.KeyID}
	}
	return out, nil
}
