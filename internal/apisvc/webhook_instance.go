// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
)

// InstanceWebhooks is InstanceWebhookService: the instance's endpoints, which receive instance
// events (docs/07-api.md, "Webhooks (Phase 2)"). The interceptor admits only the Instance Admin.
// It works on the endpoints of no org, through the logic of Webhooks; an endpoint of an org is
// NOT_FOUND here, as one of the instance is in WebhookService.
type InstanceWebhooks struct {
	rpmgrv1connect.UnimplementedInstanceWebhookServiceHandler
	W *Webhooks
}

// instance returns NOT_FOUND unless id is an endpoint of the instance.
func (i *InstanceWebhooks) instance(ctx context.Context, id string) error {
	row, err := i.W.DB.ReadClient().Webhook.Get(i.W.scope(ctx), id)
	if err == nil && row.OrgID != nil {
		return connect.NewError(connect.CodeNotFound, errors.New("apisvc: not found"))
	}
	return storeError(err)
}

// CreateInstanceWebhook implements InstanceWebhookService.
func (i *InstanceWebhooks) CreateInstanceWebhook(ctx context.Context, req *connect.Request[rpmgrv1.CreateInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.CreateInstanceWebhookResponse], error) {
	ctx = instanceCtx(ctx)
	m := req.Msg
	resp, err := api.Dedupe(ctx, i.W.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateInstanceWebhookResponse, error) {
		row, sec, err := i.W.create(ctx, "", m.GetWebhook())
		if err != nil {
			return nil, err
		}
		return &rpmgrv1.CreateInstanceWebhookResponse{Webhook: i.W.webhookOf(row), Secret: sec}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// GetInstanceWebhook implements InstanceWebhookService.
func (i *InstanceWebhooks) GetInstanceWebhook(ctx context.Context, req *connect.Request[rpmgrv1.GetInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.GetInstanceWebhookResponse], error) {
	ctx = instanceCtx(ctx)
	if err := i.instance(ctx, req.Msg.GetWebhookId()); err != nil {
		return nil, err
	}
	r, err := i.W.GetWebhook(ctx, connect.NewRequest(&rpmgrv1.GetWebhookRequest{WebhookId: req.Msg.GetWebhookId()}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.GetInstanceWebhookResponse{Webhook: r.Msg.GetWebhook()}), nil
}

// ListInstanceWebhooks implements InstanceWebhookService.
func (i *InstanceWebhooks) ListInstanceWebhooks(ctx context.Context, req *connect.Request[rpmgrv1.ListInstanceWebhooksRequest]) (
	*connect.Response[rpmgrv1.ListInstanceWebhooksResponse], error) {
	ctx = instanceCtx(ctx)
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := i.W.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	rows, err := i.W.listHooks(ctx, "", after, size)
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.ListInstanceWebhooksResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = i.W.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.Webhooks = append(out.Webhooks, i.W.webhookOf(r))
	}
	return connect.NewResponse(out), nil
}

// UpdateInstanceWebhook implements InstanceWebhookService.
func (i *InstanceWebhooks) UpdateInstanceWebhook(ctx context.Context, req *connect.Request[rpmgrv1.UpdateInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.UpdateInstanceWebhookResponse], error) {
	ctx = instanceCtx(ctx)
	m := req.Msg
	if err := i.instance(ctx, m.GetWebhook().GetId()); err != nil {
		return nil, err
	}
	r, err := i.W.UpdateWebhook(ctx, connect.NewRequest(&rpmgrv1.UpdateWebhookRequest{Webhook: m.GetWebhook(), UpdateMask: m.GetUpdateMask(), Etag: m.GetEtag()}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.UpdateInstanceWebhookResponse{Webhook: r.Msg.GetWebhook()}), nil
}

// DeleteInstanceWebhook implements InstanceWebhookService.
func (i *InstanceWebhooks) DeleteInstanceWebhook(ctx context.Context, req *connect.Request[rpmgrv1.DeleteInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.DeleteInstanceWebhookResponse], error) {
	ctx = instanceCtx(ctx)
	m := req.Msg
	if err := i.instance(ctx, m.GetWebhookId()); err != nil {
		return nil, err
	}
	if _, err := i.W.DeleteWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteWebhookRequest{WebhookId: m.GetWebhookId(), Etag: m.GetEtag()})); err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.DeleteInstanceWebhookResponse{}), nil
}

// RotateInstanceWebhookSecret implements InstanceWebhookService.
func (i *InstanceWebhooks) RotateInstanceWebhookSecret(ctx context.Context, req *connect.Request[rpmgrv1.RotateInstanceWebhookSecretRequest]) (
	*connect.Response[rpmgrv1.RotateInstanceWebhookSecretResponse], error) {
	ctx = instanceCtx(ctx)
	if err := i.instance(ctx, req.Msg.GetWebhookId()); err != nil {
		return nil, err
	}
	r, err := i.W.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: req.Msg.GetWebhookId()}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.RotateInstanceWebhookSecretResponse{Webhook: r.Msg.GetWebhook(), Secret: r.Msg.GetSecret()}), nil
}

// ListInstanceWebhookDeliveries implements InstanceWebhookService.
func (i *InstanceWebhooks) ListInstanceWebhookDeliveries(ctx context.Context, req *connect.Request[rpmgrv1.ListInstanceWebhookDeliveriesRequest]) (
	*connect.Response[rpmgrv1.ListInstanceWebhookDeliveriesResponse], error) {
	ctx = instanceCtx(ctx)
	m := req.Msg
	if err := i.instance(ctx, m.GetWebhookId()); err != nil {
		return nil, err
	}
	r, err := i.W.ListWebhookDeliveries(ctx, connect.NewRequest(&rpmgrv1.ListWebhookDeliveriesRequest{
		WebhookId: m.GetWebhookId(), PageSize: m.GetPageSize(), PageToken: m.GetPageToken()}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.ListInstanceWebhookDeliveriesResponse{Deliveries: r.Msg.GetDeliveries(), NextPageToken: r.Msg.GetNextPageToken()}), nil
}

// TestInstanceWebhook implements InstanceWebhookService.
func (i *InstanceWebhooks) TestInstanceWebhook(ctx context.Context, req *connect.Request[rpmgrv1.TestInstanceWebhookRequest]) (
	*connect.Response[rpmgrv1.TestInstanceWebhookResponse], error) {
	ctx = instanceCtx(ctx)
	if err := i.instance(ctx, req.Msg.GetWebhookId()); err != nil {
		return nil, err
	}
	r, err := i.W.test(ctx, req.Msg.GetWebhookId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.TestInstanceWebhookResponse{Delivered: r.GetDelivered(), StatusCode: r.GetStatusCode(), Error: r.GetError()}), nil
}
