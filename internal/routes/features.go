// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
)

// The gated route features of this release (docs/03-connections.md, "Versioning and
// capabilities"), registered when the program starts so that every replica compiles with them.
func init() {
	Register(Gate{Capability: agentproto.CapTCPHTTPConnect, Kind: pki.KindGateway, Uses: usesHTTPConnect})
}

// usesHTTPConnect reports whether a tcp route is in http_connect mode: an older gateway would bind
// its listener's port as a plain tcp route's, once per route.
func usesHTTPConnect(ctx context.Context, c *ent.Client, routeID string) (bool, error) {
	return c.RouteTCP.Query().Where(routetcp.RouteID(routeID), routetcp.ListenerModeEQ(routetcp.ListenerModeHTTPConnect)).Exist(ctx)
}
