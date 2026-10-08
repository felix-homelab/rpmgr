// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
)

// Domains is DomainService. Its methods run in the org scope the interceptor gives them, but
// MarkDomainTrusted, which an Instance Admin calls for a claim of any org.
type Domains struct {
	rpmgrv1connect.UnimplementedDomainServiceHandler
	DB  *store.DB
	API *api.Server
	// Sys is the controller's system scope, for MarkDomainTrusted.
	Sys context.Context
	Now func() time.Time
}

// CreateDomain implements DomainService.
func (d *Domains) CreateDomain(ctx context.Context, req *connect.Request[rpmgrv1.CreateDomainRequest]) (
	*connect.Response[rpmgrv1.CreateDomainResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, d.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateDomainResponse, error) {
		in := m.GetDomain()
		method := domain.MethodDNSTxt
		if in.GetMethod() == rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP {
			method = domain.MethodHTTP
		}
		var row *ent.Domain
		err := store.WriteTx(ctx, d.DB, func(tx *ent.Tx) error {
			var err error
			if row, err = domains.Claim(ctx, tx, m.GetOrgId(), in.GetFqdn(), in.GetWildcard()); err != nil {
				return err
			}
			row, err = tx.Domain.UpdateOne(row).SetMethod(method).Save(ctx)
			return err
		})
		switch {
		case errors.Is(err, domains.ErrInvalid):
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		case errors.Is(err, domains.ErrTaken):
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		case err != nil:
			return nil, storeError(err)
		}
		return &rpmgrv1.CreateDomainResponse{Domain: domainOf(row)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetDomain implements DomainService.
func (d *Domains) GetDomain(ctx context.Context, req *connect.Request[rpmgrv1.GetDomainRequest]) (*connect.Response[rpmgrv1.GetDomainResponse], error) {
	row, err := d.DB.ReadClient().Domain.Get(ctx, req.Msg.GetDomainId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetDomainResponse{Domain: domainOf(row)}), nil
}

// ListDomains implements DomainService.
func (d *Domains) ListDomains(ctx context.Context, req *connect.Request[rpmgrv1.ListDomainsRequest]) (*connect.Response[rpmgrv1.ListDomainsResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := d.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := d.DB.ReadClient().Domain.Query().Where(domain.OrgID(m.GetOrgId())).Order(ent.Asc(domain.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(domain.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListDomainsResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = d.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.Domains = append(out.Domains, domainOf(r))
	}
	return connect.NewResponse(out), nil
}

// DeleteDomain implements DomainService.
func (d *Domains) DeleteDomain(ctx context.Context, req *connect.Request[rpmgrv1.DeleteDomainRequest]) (*connect.Response[rpmgrv1.DeleteDomainResponse], error) {
	err := store.WriteTx(ctx, d.DB, func(tx *ent.Tx) error {
		cur, err := tx.Domain.Get(ctx, req.Msg.GetDomainId())
		if err != nil {
			return err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, domainOf(cur)); err != nil {
			return err
		}
		if n, err := tx.RouteHostname.Query().Where(routehostname.DomainID(cur.ID)).Count(ctx); err != nil || n > 0 {
			return errors.Join(err, errIf(n > 0, dependants(fmt.Sprintf("%d route hostnames lie under the domain", n))))
		}
		return tx.Domain.DeleteOneID(cur.ID).Where(domain.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteDomainResponse{}), nil
}

// MarkDomainTrusted implements DomainService: it runs in the system scope, because the Instance
// Admin need not be a member of the claim's org, and carries the request's audit entry.
func (d *Domains) MarkDomainTrusted(ctx context.Context, req *connect.Request[rpmgrv1.MarkDomainTrustedRequest]) (
	*connect.Response[rpmgrv1.MarkDomainTrustedResponse], error) {
	sys := store.CarryTxHook(d.Sys, ctx)
	var row *ent.Domain
	err := store.WriteTx(sys, d.DB, func(tx *ent.Tx) error {
		cur, err := tx.Domain.Get(sys, req.Msg.GetDomainId())
		if err != nil {
			return err
		}
		if row = cur; cur.Status == domain.StatusVerified {
			return nil
		}
		row, err = tx.Domain.UpdateOne(cur).SetStatus(domain.StatusVerified).SetMethod(domain.MethodTrusted).SetVerifiedAt(d.now()).Save(sys)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.MarkDomainTrustedResponse{Domain: domainOf(row)}), nil
}

func (d *Domains) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// ChallengeTXT is the name of a claim's TXT record (docs/04-security.md, "Route and hostname
// ownership").
func ChallengeTXT(fqdn string) string { return "_rpmgr-challenge." + fqdn }

// ChallengeURL is where the org's gateways serve a claim's HTTP token (R17).
func ChallengeURL(fqdn, id string) string {
	return "http://" + fqdn + "/.well-known/rpmgr-challenge/" + id
}

func domainOf(r *ent.Domain) *rpmgrv1.Domain {
	out := &rpmgrv1.Domain{Id: r.ID, Fqdn: r.Fqdn, Wildcard: r.Wildcard, CreateTime: timestamppb.New(r.CreatedAt), Etag: etagOf(r.Version),
		Status: map[domain.Status]rpmgrv1.DomainStatus{domain.StatusPending: rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING,
			domain.StatusPendingApproval: rpmgrv1.DomainStatus_DOMAIN_STATUS_PENDING_APPROVAL, domain.StatusVerified: rpmgrv1.DomainStatus_DOMAIN_STATUS_VERIFIED,
			domain.StatusFailed: rpmgrv1.DomainStatus_DOMAIN_STATUS_FAILED}[r.Status],
		Method: map[domain.Method]rpmgrv1.DomainMethod{domain.MethodDNSTxt: rpmgrv1.DomainMethod_DOMAIN_METHOD_DNS_TXT,
			domain.MethodHTTP: rpmgrv1.DomainMethod_DOMAIN_METHOD_HTTP, domain.MethodTrusted: rpmgrv1.DomainMethod_DOMAIN_METHOD_TRUSTED,
			domain.MethodDelegated: rpmgrv1.DomainMethod_DOMAIN_METHOD_DELEGATED}[r.Method]}
	if r.Status == domain.StatusPending {
		out.Challenge = &rpmgrv1.DomainChallenge{Value: r.ChallengeValue}
		if r.Method == domain.MethodHTTP {
			out.Challenge.HttpUrl = ChallengeURL(r.Fqdn, r.ID)
		} else {
			out.Challenge.TxtName = ChallengeTXT(r.Fqdn)
		}
	}
	if r.VerifiedAt != nil {
		out.VerifyTime = timestamppb.New(*r.VerifiedAt)
	}
	if r.LastCheckedAt != nil {
		out.LastCheckTime = timestamppb.New(*r.LastCheckedAt)
	}
	return out
}
