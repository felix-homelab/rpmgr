// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
)

// Drains shows and ends the old process of an agent's hand-off, normally the controller's
// Sessions (D160). Its errors are ErrNoDrain, ErrDrainNotConnected and ErrDrainUnsupported.
type Drains interface {
	// Draining returns the old process the agent's new process reported, nil for none.
	Draining(agentID string) *rpmgrv1.DrainingProcess
	// EndDrain ends the drain at once and returns the old process as last reported.
	EndDrain(ctx context.Context, agentID string) (*rpmgrv1.DrainingProcess, error)
}

// Firewalls shows the state of a gateway host's firewall management as the gateway reported it,
// normally the controller's Sessions (D152).
type Firewalls interface {
	// Firewall returns the state the gateway reported, nil for none.
	Firewall(agentID string) *rpmgrv1.FirewallStatus
}

// firewallOf is the firewall state of a gateway for its status; nil without Firewalls.
func firewallOf(f Firewalls, agentID string) *rpmgrv1.FirewallStatus {
	if f == nil {
		return nil
	}
	return f.Firewall(agentID)
}

// The errors of Drains.EndDrain.
var (
	ErrNoDrain           = errors.New("no old process drains")
	ErrDrainNotConnected = errors.New("the agent has no control session with this controller")
	ErrDrainUnsupported  = errors.New("the agent's version cannot report or end a drain; upgrade it")
)

// drainOf is the old process of an agent for its status; nil without Drains.
func drainOf(d Drains, agentID string) *rpmgrv1.DrainingProcess {
	if d == nil {
		return nil
	}
	return d.Draining(agentID)
}

// endDrain ends an agent's drain for EndGatewayDrain and EndConnectorDrain. A built-in agent of
// the all-in-one needs the Instance Admin, who may be in no org (D160).
func endDrain(ctx context.Context, d Drains, agentID string, builtIn bool) (*rpmgrv1.DrainingProcess, error) {
	if builtIn && !api.CallerFrom(ctx).InstanceAdmin {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("apisvc: the all-in-one's own agents need the Instance Admin"))
	}
	if d == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("apisvc: no drains are shown here"))
	}
	ended, err := d.EndDrain(ctx, agentID)
	switch {
	case errors.Is(err, ErrNoDrain), errors.Is(err, ErrDrainNotConnected), errors.Is(err, ErrDrainUnsupported):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, err
	}
	return ended, nil
}

// EndGatewayDrain implements GatewayService.
func (g *Gateways) EndGatewayDrain(ctx context.Context, req *connect.Request[rpmgrv1.EndGatewayDrainRequest]) (
	*connect.Response[rpmgrv1.EndGatewayDrainResponse], error) {
	row, err := g.DB.ReadClient().Gateway.Get(ctx, req.Msg.GetGatewayId())
	if err != nil {
		return nil, storeError(err)
	}
	if row.DecommissionedAt != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the gateway is decommissioned"))
	}
	ended, err := endDrain(ctx, g.Drains, row.ID, row.BuiltIn)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.EndGatewayDrainResponse{Ended: ended}), nil
}

// EndConnectorDrain implements ConnectorService.
func (c *Connectors) EndConnectorDrain(ctx context.Context, req *connect.Request[rpmgrv1.EndConnectorDrainRequest]) (
	*connect.Response[rpmgrv1.EndConnectorDrainResponse], error) {
	row, err := c.DB.ReadClient().Connector.Get(ctx, req.Msg.GetConnectorId())
	if err != nil {
		return nil, storeError(err)
	}
	if row.DecommissionedAt != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the connector is decommissioned"))
	}
	ended, err := endDrain(ctx, c.Drains, row.ID, row.BuiltIn)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.EndConnectorDrainResponse{Ended: ended}), nil
}
