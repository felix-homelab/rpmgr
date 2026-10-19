// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// A Gate is a route feature that only agents announcing its capability carry out
// (docs/03-connections.md, "Versioning and capabilities", D113). An agent ignores snapshot fields
// it does not know, so an older one would serve a route with an access rule or a limit without
// enforcing it. The compiler therefore leaves a route that uses the feature out of the snapshot
// of every agent of the gate's kind that lacks the capability, and the route status names the
// agent with CapabilityMissing.
type Gate struct {
	// Capability is the capability string an agent announces in Hello.
	Capability string
	// Kind is the kind of agent that carries the feature out: pki.KindGateway or
	// pki.KindConnector.
	Kind pki.Kind
	// Uses reports whether route routeID uses the feature. It reads only through c and must be
	// deterministic, as a snapshot source is; a route that does not exist does not use it.
	Uses func(ctx context.Context, c *ent.Client, routeID string) (bool, error)
}

// A Requirement is a capability that an agent of Kind needs to get a route.
type Requirement struct {
	Kind       pki.Kind
	Capability string
}

// CapabilityMissing is the route status reason of an agent that lacks a capability the route
// needs; the detail names the capabilities.
const CapabilityMissing = "CAPABILITY_MISSING"

// gates are the registered gates. Features register theirs when the program starts, so every
// replica of a release compiles with the same gates; tests may add and remove one.
var gates struct {
	sync.RWMutex
	list []*Gate
}

// Register adds a gate and returns a function that removes it again. A gate without a capability,
// a gateway or connector kind, or Uses is a programming error.
func Register(g Gate) (remove func()) {
	if g.Capability == "" || g.Uses == nil || (g.Kind != pki.KindGateway && g.Kind != pki.KindConnector) {
		panic(fmt.Sprintf("routes: invalid gate %+v", g))
	}
	p := &g
	gates.Lock()
	gates.list = append(gates.list, p)
	gates.Unlock()
	return func() {
		gates.Lock()
		gates.list = slices.DeleteFunc(gates.list, func(x *Gate) bool { return x == p })
		gates.Unlock()
	}
}

// Required returns what agents need to get route routeID: one requirement per registered gate the
// route uses, sorted and without repeats.
func Required(ctx context.Context, c *ent.Client, routeID string) ([]Requirement, error) {
	gates.RLock()
	list := slices.Clone(gates.list)
	gates.RUnlock()
	var out []Requirement
	for _, g := range list {
		uses, err := g.Uses(ctx, c, routeID)
		if err != nil {
			return nil, err
		}
		if uses {
			out = append(out, Requirement{Kind: g.Kind, Capability: g.Capability})
		}
	}
	slices.SortFunc(out, func(x, y Requirement) int {
		return cmp.Or(cmp.Compare(x.Kind, y.Kind), cmp.Compare(x.Capability, y.Capability))
	})
	return slices.Compact(out), nil
}

// Missing returns the capabilities of reqs that an agent of kind lacks, given has, which reports
// whether the agent announced a capability.
func Missing(reqs []Requirement, kind pki.Kind, has func(string) bool) []string {
	var out []string
	for _, r := range reqs {
		if r.Kind == kind && !has(r.Capability) {
			out = append(out, r.Capability)
		}
	}
	return out
}

// isRoute reports whether a resource is a route's: the resources a gate withholds.
func isRoute(r *agentv1.Resource) bool {
	switch r.GetKind().(type) {
	case *agentv1.Resource_GatewayTcpRoute, *agentv1.Resource_GatewayUdpRoute, *agentv1.Resource_GatewayTcpUdpRoute,
		*agentv1.Resource_GatewayPassthroughRoute, *agentv1.Resource_GatewayHttpRoute, *agentv1.Resource_ConnectorRoute:
		return true
	}
	return false
}

// gated wraps a snapshot source so that it leaves out every route the agent lacks a capability
// for. A route resource's ID is the route's.
func gated(src snapshot.Source) snapshot.Source {
	return func(ctx context.Context, tx *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
		rs, err := src(ctx, tx, a)
		if err != nil {
			return nil, err
		}
		out := rs[:0]
		for _, r := range rs {
			if isRoute(r) {
				reqs, err := Required(ctx, tx.Client(), r.GetId())
				if err != nil {
					return nil, err
				}
				if len(Missing(reqs, a.Identity.Kind, a.Has)) > 0 {
					continue
				}
			}
			out = append(out, r)
		}
		return out, nil
	}
}
