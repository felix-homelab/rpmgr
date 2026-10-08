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
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
)

// Certificates is CertificateService. Its methods run in the org scope the interceptor gives
// them.
type Certificates struct {
	rpmgrv1connect.UnimplementedCertificateServiceHandler
	DB     *store.DB
	API    *api.Server
	Sealer *secret.Sealer
	Now    func() time.Time
}

// UploadCertificate implements CertificateService: the chain and key are checked as 04 requires,
// and the key is sealed under the KEK.
func (c *Certificates) UploadCertificate(ctx context.Context, req *connect.Request[rpmgrv1.UploadCertificateRequest]) (
	*connect.Response[rpmgrv1.UploadCertificateResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, c.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.UploadCertificateResponse, error) {
		var row *ent.Certificate
		rev, err := store.ConfigTx(ctx, c.DB, func(tx *ent.Tx) ([]string, error) {
			var err error
			row, err = certs.Upload(ctx, tx, c.Sealer, m.GetOrgId(), []byte(m.GetChainPem()), []byte(m.GetPrivateKeyPem()), c.now())
			if err != nil {
				return nil, err
			}
			return []string{row.ID}, nil
		})
		if errors.Is(err, certs.ErrInvalid) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		if err != nil {
			return nil, storeError(err)
		}
		out, err := certificateOf(ctx, c.DB.ReadClient(), row)
		if err != nil {
			return nil, storeError(err)
		}
		return &rpmgrv1.UploadCertificateResponse{Certificate: out, Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetCertificate implements CertificateService.
func (c *Certificates) GetCertificate(ctx context.Context, req *connect.Request[rpmgrv1.GetCertificateRequest]) (
	*connect.Response[rpmgrv1.GetCertificateResponse], error) {
	rc := c.DB.ReadClient()
	row, err := rc.Certificate.Get(ctx, req.Msg.GetCertificateId())
	if err != nil {
		return nil, storeError(err)
	}
	out, err := certificateOf(ctx, rc, row)
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetCertificateResponse{Certificate: out}), nil
}

// ListCertificates implements CertificateService.
func (c *Certificates) ListCertificates(ctx context.Context, req *connect.Request[rpmgrv1.ListCertificatesRequest]) (
	*connect.Response[rpmgrv1.ListCertificatesResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := c.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	rc := c.DB.ReadClient()
	q := rc.Certificate.Query().Where(certificate.OrgID(m.GetOrgId())).Order(ent.Asc(certificate.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(certificate.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListCertificatesResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = c.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		crt, err := certificateOf(ctx, rc, r)
		if err != nil {
			return nil, storeError(err)
		}
		out.Certificates = append(out.Certificates, crt)
	}
	return connect.NewResponse(out), nil
}

// DeleteCertificate implements CertificateService.
func (c *Certificates) DeleteCertificate(ctx context.Context, req *connect.Request[rpmgrv1.DeleteCertificateRequest]) (
	*connect.Response[rpmgrv1.DeleteCertificateResponse], error) {
	rev, err := store.ConfigTx(ctx, c.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.Certificate.Get(ctx, req.Msg.GetCertificateId())
		if err != nil {
			return nil, err
		}
		shown, err := certificateOf(ctx, tx.Client(), cur)
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, shown); err != nil {
			return nil, err
		}
		if cur.Source == certificate.SourceAcme {
			return nil, connect.NewError(connect.CodeFailedPrecondition,
				errors.New("apisvc: the ACME job keeps an ACME certificate while a route needs it"))
		}
		if n := len(shown.GetRouteIds()); n > 0 {
			return nil, dependants(fmt.Sprintf("%d routes serve the certificate", n))
		}
		return []string{cur.ID}, certs.Delete(ctx, tx, cur)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteCertificateResponse{Revision: revisionOf(rev)}), nil
}

func (c *Certificates) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// certificateOf is a certificate as the API shows it: never its key; an uploaded one with the
// http routes that serve it.
func certificateOf(ctx context.Context, c *ent.Client, row *ent.Certificate) (*rpmgrv1.Certificate, error) {
	out := &rpmgrv1.Certificate{Id: row.ID, Source: rpmgrv1.CertificateSource_CERTIFICATE_SOURCE_ACME, Sans: row.Sans, Issuer: row.Issuer,
		Status: map[certificate.Status]rpmgrv1.CertificateStatus{certificate.StatusPending: rpmgrv1.CertificateStatus_CERTIFICATE_STATUS_PENDING,
			certificate.StatusActive: rpmgrv1.CertificateStatus_CERTIFICATE_STATUS_ACTIVE,
			certificate.StatusFailed: rpmgrv1.CertificateStatus_CERTIFICATE_STATUS_FAILED}[row.Status],
		LastError: row.LastError, CreateTime: timestamppb.New(row.CreatedAt), Etag: etagOf(row.Version)}
	if row.NotBefore != nil {
		out.NotBefore = timestamppb.New(*row.NotBefore)
	}
	if row.NotAfter != nil {
		out.NotAfter = timestamppb.New(*row.NotAfter)
	}
	if row.Source == certificate.SourceUploaded {
		out.Source = rpmgrv1.CertificateSource_CERTIFICATE_SOURCE_UPLOADED
		var err error
		if out.RouteIds, err = c.RouteHTTP.Query().Where(routehttp.CertificateID(row.ID)).Order(ent.Asc(routehttp.FieldRouteID)).
			Select(routehttp.FieldRouteID).Strings(ctx); err != nil {
			return nil, err
		}
	}
	return out, nil
}
