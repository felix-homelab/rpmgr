// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsname"
)

// dnsNameFields are the fields UpdateDnsName may change.
var dnsNameFields = []string{"gateway_group_id", "ttl"}

// DnsNames is DnsNameService (docs/07-api.md; docs/15-dns.md, "Concepts"). Its methods run in the
// org scope the interceptor gives them, so a gateway group of another org, or a shared one that
// the org has no grant for, is not found.
type DnsNames struct {
	rpmgrv1connect.UnimplementedDnsNameServiceHandler
	DB  *store.DB
	API *api.Server
}

// dnsNameOf is the API's view of a row.
func dnsNameOf(r *ent.DNSName) *rpmgrv1.DnsName {
	return &rpmgrv1.DnsName{Id: r.ID, Fqdn: r.Fqdn, GatewayGroupId: r.GatewayGroupID, Ttl: int32(r.TTL), Etag: etagOf(r.Version)} //nolint:gosec // G115: bounded on write
}

// checkNameTTL refuses a TTL other than 0, the zone's default, outside the bounds of a zone's
// default_ttl.
func checkNameTTL(ttl int32) error {
	if ttl != 0 && (ttl < minZoneTTL || ttl > maxZoneTTL) {
		return invalid(errors.New("apisvc: ttl is 0, or out of range"))
	}
	return nil
}

// dnsNameError gives the rules of names their API codes.
func dnsNameError(err error) error {
	switch {
	case errors.Is(err, domains.ErrNotOwned):
		return withReason(connect.NewError(connect.CodeFailedPrecondition,
			errors.New("apisvc: the name lies under no verified domain of the org that covers it")), ReasonDomainNotVerified)
	case errors.Is(err, domains.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case store.IsUniqueViolation(err):
		return connect.NewError(connect.CodeAlreadyExists, errors.New("apisvc: the name exists"))
	}
	return storeError(err)
}

// CreateDnsName implements DnsNameService. The name is checked against the org's verified
// domains and gateway groups in the transaction that creates it, as a route's hostname is.
func (d *DnsNames) CreateDnsName(ctx context.Context, req *connect.Request[rpmgrv1.CreateDnsNameRequest]) (
	*connect.Response[rpmgrv1.CreateDnsNameResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, d.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateDnsNameResponse, error) {
		in := m.GetDnsName()
		if err := checkNameTTL(in.GetTtl()); err != nil {
			return nil, err
		}
		if in.GetGatewayGroupId() == "" {
			return nil, invalid(errors.New("apisvc: the gateway group is not set"))
		}
		fqdn, err := domains.Normalize(in.GetFqdn(), true)
		if err != nil {
			return nil, dnsNameError(err)
		}
		var row *ent.DNSName
		_, err = store.ConfigTx(ctx, d.DB, func(tx *ent.Tx) ([]string, error) {
			g, err := tx.GatewayGroup.Get(ctx, in.GetGatewayGroupId())
			if err != nil {
				return nil, err
			}
			cover, err := domains.Covering(ctx, tx, g.OrgID, fqdn)
			if err != nil {
				return nil, err
			}
			row, err = tx.DNSName.Create().SetOrgID(g.OrgID).SetFqdn(fqdn).SetGatewayGroupID(g.ID).SetDomainID(cover.ID).
				SetTTL(int(in.GetTtl())).Save(ctx)
			if err != nil {
				return nil, err
			}
			return []string{row.ID}, nil
		})
		if err != nil {
			return nil, dnsNameError(err)
		}
		return &rpmgrv1.CreateDnsNameResponse{DnsName: dnsNameOf(row)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetDnsName implements DnsNameService.
func (d *DnsNames) GetDnsName(ctx context.Context, req *connect.Request[rpmgrv1.GetDnsNameRequest]) (
	*connect.Response[rpmgrv1.GetDnsNameResponse], error) {
	row, err := d.DB.ReadClient().DNSName.Get(ctx, req.Msg.GetDnsNameId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetDnsNameResponse{DnsName: dnsNameOf(row)}), nil
}

// ListDnsNames implements DnsNameService.
func (d *DnsNames) ListDnsNames(ctx context.Context, req *connect.Request[rpmgrv1.ListDnsNamesRequest]) (
	*connect.Response[rpmgrv1.ListDnsNamesResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := d.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := d.DB.ReadClient().DNSName.Query().Where(dnsname.OrgID(m.GetOrgId())).Order(ent.Asc(dnsname.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(dnsname.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListDnsNamesResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = d.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.DnsNames = append(out.DnsNames, dnsNameOf(r))
	}
	return connect.NewResponse(out), nil
}

// UpdateDnsName implements DnsNameService: the gateway group and the TTL. The group is checked as
// when the name is created.
func (d *DnsNames) UpdateDnsName(ctx context.Context, req *connect.Request[rpmgrv1.UpdateDnsNameRequest]) (
	*connect.Response[rpmgrv1.UpdateDnsNameResponse], error) {
	m := req.Msg
	cur, err := d.DB.ReadClient().DNSName.Get(ctx, m.GetDnsName().GetId())
	if err != nil {
		return nil, storeError(err)
	}
	if err := api.CheckEtag(m.GetEtag(), cur.Version, dnsNameOf(cur)); err != nil {
		return nil, err
	}
	next := proto.Clone(dnsNameOf(cur)).(*rpmgrv1.DnsName)
	if err := api.ApplyMask(next, m.GetDnsName(), m.GetUpdateMask(), dnsNameFields...); err != nil {
		return nil, err
	}
	if err := checkNameTTL(next.GetTtl()); err != nil {
		return nil, err
	}
	var row *ent.DNSName
	_, err = store.ConfigTx(ctx, d.DB, func(tx *ent.Tx) ([]string, error) {
		g, err := tx.GatewayGroup.Get(ctx, next.GetGatewayGroupId())
		if err != nil {
			return nil, err
		}
		row, err = tx.DNSName.UpdateOneID(cur.ID).Where(dnsname.Version(cur.Version)).SetGatewayGroupID(g.ID).SetTTL(int(next.GetTtl())).Save(ctx)
		return []string{cur.ID}, err
	})
	if err != nil {
		return nil, dnsNameError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateDnsNameResponse{DnsName: dnsNameOf(row)}), nil
}

// DeleteDnsName implements DnsNameService.
func (d *DnsNames) DeleteDnsName(ctx context.Context, req *connect.Request[rpmgrv1.DeleteDnsNameRequest]) (
	*connect.Response[rpmgrv1.DeleteDnsNameResponse], error) {
	_, err := store.ConfigTx(ctx, d.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.DNSName.Get(ctx, req.Msg.GetDnsNameId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, dnsNameOf(cur)); err != nil {
			return nil, err
		}
		return []string{cur.ID}, tx.DNSName.DeleteOneID(cur.ID).Where(dnsname.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteDnsNameResponse{}), nil
}
