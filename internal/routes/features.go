// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
)

// The gated route features of this release (docs/03-connections.md, "Versioning and
// capabilities"), registered when the program starts so that every replica compiles with them.
func init() {
	Register(Gate{Capability: agentproto.CapHTTPHeaderMatch, Kind: pki.KindGateway, Uses: usesHeaderMatches})
}

// usesHeaderMatches reports whether an http route matches on request headers.
func usesHeaderMatches(ctx context.Context, c *ent.Client, routeID string) (bool, error) {
	return c.RouteHTTP.Query().Where(routehttp.RouteID(routeID), routehttp.MatchKeyNEQ("")).Exist(ctx)
}
