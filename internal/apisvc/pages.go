// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaypage"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

// SetGatewayPage implements GatewayService: it replaces a page of a gateway group with the
// group's own HTML (D132). The interceptor admits only the group's owner org, so another org's
// member, also one using a shared group, is refused.
func (g *Gateways) SetGatewayPage(ctx context.Context, req *connect.Request[rpmgrv1.SetGatewayPageRequest]) (
	*connect.Response[rpmgrv1.SetGatewayPageResponse], error) {
	in := req.Msg.GetGatewayPage()
	kind, err := pageKindOf(in.GetKind())
	if err != nil {
		return nil, err
	}
	switch html := in.GetHtml(); {
	case html == "" || len(html) > schema.MaxPageBytes:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: a page has 1 to %d bytes, not %d", schema.MaxPageBytes, len(html)))
	case !utf8.ValidString(html):
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: a page is UTF-8"))
	}
	sum := sha256.Sum256([]byte(in.GetHtml()))
	// The audit entry records what identifies the page, not its up to 64 KiB of HTML.
	if b, err := json.Marshal(map[string]any{"gateway_group_id": in.GetGatewayGroupId(), "kind": string(kind),
		"html_sha256": hex.EncodeToString(sum[:]), "html_bytes": len(in.GetHtml())}); err == nil {
		api.AuditDiff(ctx, string(b))
	}
	var row *ent.GatewayPage
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		group, err := tx.GatewayGroup.Get(ctx, in.GetGatewayGroupId())
		if err != nil {
			return nil, err
		}
		cur, err := tx.GatewayPage.Query().Where(gatewaypage.GatewayGroupID(group.ID), gatewaypage.KindEQ(kind)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			row, err = tx.GatewayPage.Create().SetOrgID(group.OrgID).SetGatewayGroupID(group.ID).SetKind(kind).SetHTML(in.GetHtml()).
				SetContentSha256(sum[:]).SetUpdatedBy(api.CallerFrom(ctx).UserID).Save(ctx)
		case err == nil:
			row, err = tx.GatewayPage.UpdateOne(cur).SetHTML(in.GetHtml()).SetContentSha256(sum[:]).
				SetUpdatedBy(api.CallerFrom(ctx).UserID).Save(ctx)
		}
		if err != nil {
			return nil, err
		}
		return []string{group.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.SetGatewayPageResponse{GatewayPage: pageOf(row), Revision: revisionOf(rev)}), nil
}

// ListGatewayPages implements GatewayService.
func (g *Gateways) ListGatewayPages(ctx context.Context, req *connect.Request[rpmgrv1.ListGatewayPagesRequest]) (
	*connect.Response[rpmgrv1.ListGatewayPagesResponse], error) {
	c := g.DB.ReadClient()
	group, err := c.GatewayGroup.Get(ctx, req.Msg.GetGatewayGroupId())
	if err != nil {
		return nil, storeError(err)
	}
	rows, err := c.GatewayPage.Query().Where(gatewaypage.GatewayGroupID(group.ID)).Order(ent.Asc(gatewaypage.FieldKind)).All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListGatewayPagesResponse{}
	for _, r := range rows {
		out.GatewayPages = append(out.GatewayPages, pageOf(r))
	}
	return connect.NewResponse(out), nil
}

// DeleteGatewayPage implements GatewayService: the group's gateways serve the built-in page of the
// kind again.
func (g *Gateways) DeleteGatewayPage(ctx context.Context, req *connect.Request[rpmgrv1.DeleteGatewayPageRequest]) (
	*connect.Response[rpmgrv1.DeleteGatewayPageResponse], error) {
	kind, err := pageKindOf(req.Msg.GetKind())
	if err != nil {
		return nil, err
	}
	rev, err := store.ConfigTx(ctx, g.DB, func(tx *ent.Tx) ([]string, error) {
		group, err := tx.GatewayGroup.Get(ctx, req.Msg.GetGatewayGroupId())
		if err != nil {
			return nil, err
		}
		n, err := tx.GatewayPage.Delete().Where(gatewaypage.GatewayGroupID(group.ID), gatewaypage.KindEQ(kind)).Exec(ctx)
		if err == nil && n == 0 {
			err = connect.NewError(connect.CodeNotFound, fmt.Errorf("apisvc: the group has no %s page of its own", kind))
		}
		return []string{group.ID}, err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteGatewayPageResponse{Revision: revisionOf(rev)}), nil
}

// pageKindOf is a page kind of the API in the store's terms; it must be set.
func pageKindOf(k rpmgrv1.GatewayPageKind) (gatewaypage.Kind, error) {
	for kind, v := range routes.PageKinds {
		if v == k {
			return kind, nil
		}
	}
	return "", connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: the page kind must be not_found, unavailable or maintenance"))
}

func pageOf(r *ent.GatewayPage) *rpmgrv1.GatewayPage {
	return &rpmgrv1.GatewayPage{GatewayGroupId: r.GatewayGroupID, Kind: routes.PageKinds[r.Kind], Html: r.HTML,
		UpdateTime: timestamppb.New(r.UpdatedAt), UpdateUserId: r.UpdatedBy}
}
