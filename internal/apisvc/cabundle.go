// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cabundle"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// caBundleFields are the fields of a CA bundle a client may change.
var caBundleFields = []string{"name", "pem"}

// CreateCABundle implements CertificateService.
func (c *Certificates) CreateCABundle(ctx context.Context, req *connect.Request[rpmgrv1.CreateCABundleRequest]) (
	*connect.Response[rpmgrv1.CreateCABundleResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, c.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateCABundleResponse, error) {
		in := m.GetCaBundle()
		if err := checkBundle(in.GetPem()); err != nil {
			return nil, err
		}
		var row *ent.CABundle
		rev, err := store.ConfigTx(ctx, c.DB, func(tx *ent.Tx) ([]string, error) {
			var err error
			row, err = tx.CABundle.Create().SetOrgID(m.GetOrgId()).SetName(in.GetName()).SetPem([]byte(in.GetPem())).Save(ctx)
			if err != nil {
				return nil, err
			}
			return []string{row.ID}, nil
		})
		if err != nil {
			return nil, storeError(err)
		}
		out, err := caBundleOf(ctx, c.DB.ReadClient(), row)
		if err != nil {
			return nil, storeError(err)
		}
		return &rpmgrv1.CreateCABundleResponse{CaBundle: out, Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetCABundle implements CertificateService.
func (c *Certificates) GetCABundle(ctx context.Context, req *connect.Request[rpmgrv1.GetCABundleRequest]) (
	*connect.Response[rpmgrv1.GetCABundleResponse], error) {
	rc := c.DB.ReadClient()
	row, err := rc.CABundle.Get(ctx, req.Msg.GetCaBundleId())
	if err != nil {
		return nil, storeError(err)
	}
	out, err := caBundleOf(ctx, rc, row)
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetCABundleResponse{CaBundle: out}), nil
}

// ListCABundles implements CertificateService.
func (c *Certificates) ListCABundles(ctx context.Context, req *connect.Request[rpmgrv1.ListCABundlesRequest]) (
	*connect.Response[rpmgrv1.ListCABundlesResponse], error) {
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
	q := rc.CABundle.Query().Where(cabundle.OrgID(m.GetOrgId())).Order(ent.Asc(cabundle.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(cabundle.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListCABundlesResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = c.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		b, err := caBundleOf(ctx, rc, r)
		if err != nil {
			return nil, storeError(err)
		}
		out.CaBundles = append(out.CaBundles, b)
	}
	return connect.NewResponse(out), nil
}

// UpdateCABundle implements CertificateService. The revision names the targets that use the
// bundle, whose gateways get the new one.
func (c *Certificates) UpdateCABundle(ctx context.Context, req *connect.Request[rpmgrv1.UpdateCABundleRequest]) (
	*connect.Response[rpmgrv1.UpdateCABundleResponse], error) {
	m := req.Msg
	var row *ent.CABundle
	rev, err := store.ConfigTx(ctx, c.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.CABundle.Get(ctx, m.GetCaBundle().GetId())
		if err != nil {
			return nil, err
		}
		shown, err := caBundleOf(ctx, tx.Client(), cur)
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, shown); err != nil {
			return nil, err
		}
		next := proto.Clone(shown).(*rpmgrv1.CABundle)
		if err := api.ApplyMask(next, m.GetCaBundle(), m.GetUpdateMask(), caBundleFields...); err != nil {
			return nil, err
		}
		if err := checkBundle(next.GetPem()); err != nil {
			return nil, err
		}
		if row, err = tx.CABundle.UpdateOneID(cur.ID).Where(cabundle.Version(cur.Version)).SetName(next.GetName()).
			SetPem([]byte(next.GetPem())).Save(ctx); err != nil {
			return nil, err
		}
		return append([]string{cur.ID}, shown.GetTargetIds()...), nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	out, err := caBundleOf(ctx, c.DB.ReadClient(), row)
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateCABundleResponse{CaBundle: out, Revision: revisionOf(rev)}), nil
}

// DeleteCABundle implements CertificateService.
func (c *Certificates) DeleteCABundle(ctx context.Context, req *connect.Request[rpmgrv1.DeleteCABundleRequest]) (
	*connect.Response[rpmgrv1.DeleteCABundleResponse], error) {
	rev, err := store.ConfigTx(ctx, c.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.CABundle.Get(ctx, req.Msg.GetCaBundleId())
		if err != nil {
			return nil, err
		}
		shown, err := caBundleOf(ctx, tx.Client(), cur)
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, shown); err != nil {
			return nil, err
		}
		if n := len(shown.GetTargetIds()); n > 0 {
			return nil, dependants(fmt.Sprintf("%d route targets use the bundle", n))
		}
		return []string{cur.ID}, tx.CABundle.DeleteOneID(cur.ID).Where(cabundle.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteCABundleResponse{Revision: revisionOf(rev)}), nil
}

// checkBundle refuses a bundle the gateways could not use (docs/04-security.md, "Controller
// certificates").
func checkBundle(pem string) error {
	if _, err := certs.CheckBundle([]byte(pem)); err != nil {
		if errors.Is(err, certs.ErrInvalid) {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		return err
	}
	return nil
}

// caBundleOf is a CA bundle as the API shows it, with its certificates and the targets that use it.
func caBundleOf(ctx context.Context, c *ent.Client, row *ent.CABundle) (*rpmgrv1.CABundle, error) {
	out := &rpmgrv1.CABundle{Id: row.ID, Name: row.Name, Pem: string(row.Pem), CreateTime: timestamppb.New(row.CreatedAt), Etag: etagOf(row.Version)}
	cs, err := certs.CheckBundle(row.Pem)
	if err != nil {
		return nil, err
	}
	for _, crt := range cs {
		out.Certificates = append(out.Certificates, &rpmgrv1.CACertificate{Subject: crt.Subject.String(), NotAfter: timestamppb.New(crt.NotAfter)})
	}
	if out.TargetIds, err = c.RouteTarget.Query().Where(routetarget.TLSCaBundleID(row.ID)).Order(ent.Asc(routetarget.FieldID)).IDs(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
