// SPDX-License-Identifier: Apache-2.0

// Package routes holds the rules of routes and their public ports (docs/06-data-model.md,
// "Routes", "Gateway groups and ports"): port pools, quotas and allocation, and the snapshot
// compilers of each route type.
package routes

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portallocation"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portquota"
)

// Why a port cannot be allocated.
var (
	ErrPortTaken     = errors.New("routes: the port is taken")
	ErrNotInPool     = errors.New("routes: the port is in no pool of the gateway group")
	ErrPoolExhausted = errors.New("routes: the gateway group's pools have no free port")
	ErrQuotaReached  = errors.New("routes: the org's port quota for the gateway group is reached")
	ErrPoolOverlap   = errors.New("routes: the port range overlaps another pool of the gateway group")
	ErrNoGroup       = errors.New("routes: no such gateway group")
)

// Protocol is a port's protocol.
type Protocol string

// The protocols of ports.
const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// AddPool adds the ports from to to of protocol to the org's gateway group, refusing a range that
// overlaps another pool of the group and protocol.
func AddPool(ctx context.Context, tx *ent.Tx, org, group string, p Protocol, from, to int) (*ent.PortPool, error) {
	if from < 1 || to > 65535 || from > to {
		return nil, fmt.Errorf("routes: port range %d-%d, want 1 <= from <= to <= 65535", from, to)
	}
	if err := ownGroup(ctx, tx, org, group); err != nil {
		return nil, err
	}
	overlap, err := tx.PortPool.Query().Where(portpool.GatewayGroupID(group), portpool.ProtocolEQ(portpool.Protocol(p)),
		portpool.PortFromLTE(to), portpool.PortToGTE(from)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if overlap {
		return nil, ErrPoolOverlap
	}
	return tx.PortPool.Create().SetOrgID(org).SetGatewayGroupID(group).SetProtocol(portpool.Protocol(p)).
		SetPortFrom(from).SetPortTo(to).Save(ctx)
}

// ownGroup refuses a gateway group of another org; shared groups come in Phase 2.
func ownGroup(ctx context.Context, tx *ent.Tx, org, group string) error {
	ok, err := tx.GatewayGroup.Query().Where(gatewaygroup.ID(group), gatewaygroup.OrgID(org)).Exist(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoGroup
	}
	return nil
}

// Allocate allocates a public port of protocol in the org's gateway group, in tx: port, which
// must lie in one of the org's pools of the group, or with port 0 a random free one. The org's
// quota for the group, if it has one, caps its allocations; without one only the pools do.
func Allocate(ctx context.Context, tx *ent.Tx, org, group string, p Protocol, port int) (*ent.PortAllocation, error) {
	if err := ownGroup(ctx, tx, org, group); err != nil {
		return nil, err
	}
	proto := portallocation.Protocol(p)
	quota, err := tx.PortQuota.Query().Where(portquota.OrgID(org), portquota.GatewayGroupID(group),
		portquota.ProtocolEQ(portquota.Protocol(p))).Only(ctx)
	switch {
	case ent.IsNotFound(err):
	case err != nil:
		return nil, err
	default:
		n, err := tx.PortAllocation.Query().Where(portallocation.OrgID(org), portallocation.GatewayGroupID(group),
			portallocation.ProtocolEQ(proto)).Count(ctx)
		if err != nil {
			return nil, err
		}
		if n >= quota.MaxPorts {
			return nil, ErrQuotaReached
		}
	}
	pools, err := tx.PortPool.Query().Where(portpool.OrgID(org), portpool.GatewayGroupID(group),
		portpool.ProtocolEQ(portpool.Protocol(p))).Order(ent.Asc(portpool.FieldPortFrom)).All(ctx)
	if err != nil {
		return nil, err
	}
	taken := map[int]bool{}
	allocated, err := tx.PortAllocation.Query().Where(portallocation.GatewayGroupID(group), portallocation.ProtocolEQ(proto)).
		Select(portallocation.FieldPort).Ints(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range allocated {
		taken[a] = true
	}
	if port != 0 {
		if !inPools(pools, port) {
			return nil, ErrNotInPool
		}
		if taken[port] {
			return nil, ErrPortTaken
		}
	} else if port, err = randomFree(pools, taken); err != nil {
		return nil, err
	}
	a, err := tx.PortAllocation.Create().SetOrgID(org).SetGatewayGroupID(group).SetProtocol(proto).SetPort(port).Save(ctx)
	if ent.IsConstraintError(err) {
		return nil, ErrPortTaken // allocated concurrently
	}
	return a, err
}

func inPools(pools []*ent.PortPool, port int) bool {
	for _, p := range pools {
		if port >= p.PortFrom && port <= p.PortTo {
			return true
		}
	}
	return false
}

// randomFree picks a free port of the pools: from a random place in their combined range, the
// next free one, so that allocations are not predictable.
func randomFree(pools []*ent.PortPool, taken map[int]bool) (int, error) {
	total := 0
	for _, p := range pools {
		total += p.PortTo - p.PortFrom + 1
	}
	if total == 0 {
		return 0, ErrPoolExhausted
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(total)))
	if err != nil {
		return 0, err
	}
	start := int(n.Int64())
	for i := range total {
		k := (start + i) % total
		for _, p := range pools {
			size := p.PortTo - p.PortFrom + 1
			if k < size {
				if port := p.PortFrom + k; !taken[port] {
					return port, nil
				}
				break
			}
			k -= size
		}
	}
	return 0, ErrPoolExhausted
}

// Release frees a route's port, in tx.
func Release(ctx context.Context, tx *ent.Tx, allocationID string) error {
	return tx.PortAllocation.DeleteOneID(allocationID).Exec(ctx)
}
