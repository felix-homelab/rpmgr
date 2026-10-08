// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portallocation"
)

const (
	tcp = rpmgrv1.PortProtocol_PORT_PROTOCOL_TCP
	udp = rpmgrv1.PortProtocol_PORT_PROTOCOL_UDP
)

// allocate allocates a port as a route would; port 0 is a random free one.
func (e *env) allocate(t *testing.T, org, group string, p routes.Protocol, port int) error {
	t.Helper()
	_, err := store.ConfigTx(e.sys, e.db, func(tx *ent.Tx) ([]string, error) {
		_, err := routes.Allocate(e.sys, tx, org, group, p, port)
		return nil, err
	})
	return err
}

// TestPortPools: an Owner adds, reads, lists, resizes and deletes port pools: pools of a group and
// protocol never overlap, a range is 1 to 65535 with from <= to, a resize keeps every allocated
// port inside, and a pool with allocated ports cannot be deleted; a Viewer only reads.
func TestPortPools(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	create := func(b *browser, p rpmgrv1.PortProtocol, from, to int32, requestID string) (*rpmgrv1.PortPool, error) {
		r, err := b.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, RequestId: requestID,
			PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: p, PortFrom: from, PortTo: to}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetPortPool(), nil
	}
	pool, err := create(ada, tcp, 20000, 20099, "req-1")
	if err != nil || pool.GetEtag() != "1" || pool.GetAllocatedPorts() != 0 || pool.GetProtocol() != tcp {
		t.Fatalf("create: %v %v", pool, err)
	}
	if again, err := create(ada, tcp, 20000, 20099, "req-1"); err != nil || again.GetId() != pool.GetId() {
		t.Fatalf("a retry: %v %v", again, err)
	}
	for name, c := range map[string]struct {
		p        rpmgrv1.PortProtocol
		from, to int32
		want     connect.Code
	}{
		"an overlap":        {tcp, 20099, 20150, connect.CodeInvalidArgument},
		"a range inside":    {tcp, 20010, 20020, connect.CodeInvalidArgument},
		"from above to":     {tcp, 30010, 30000, connect.CodeInvalidArgument},
		"port 0":            {tcp, 0, 100, connect.CodeInvalidArgument},
		"port 65536":        {tcp, 65000, 65536, connect.CodeInvalidArgument},
		"no protocol":       {rpmgrv1.PortProtocol_PORT_PROTOCOL_UNSPECIFIED, 30000, 30010, connect.CodeInvalidArgument},
		"an undefined enum": {rpmgrv1.PortProtocol(7), 30000, 30010, connect.CodeInvalidArgument},
	} {
		if _, err := create(ada, c.p, c.from, c.to, ""); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: "gwg_missing", Protocol: tcp, PortFrom: 1, PortTo: 2}})); code(err) != connect.CodeNotFound {
		t.Fatalf("a group that does not exist: %v", err)
	}
	if _, err := create(ada, udp, 20000, 20099, ""); err != nil {
		t.Fatalf("the same range for UDP: %v", err)
	}
	if _, err := create(ada, tcp, 65535, 65535, ""); err != nil {
		t.Fatalf("a pool of the last port: %v", err)
	}

	for _, port := range []int{20005, 20090} {
		if err := e.allocate(t, org, group, routes.TCP, port); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ada.gw.GetPortPool(ctx, connect.NewRequest(&rpmgrv1.GetPortPoolRequest{PortPoolId: pool.GetId()}))
	if err != nil || got.Msg.GetPortPool().GetAllocatedPorts() != 2 {
		t.Fatalf("a pool with two routes: %v %v", got, err)
	}
	first, err := ada.gw.ListPortPools(ctx, connect.NewRequest(&rpmgrv1.ListPortPoolsRequest{OrgId: org, GatewayGroupId: group, PageSize: 2}))
	if err != nil || len(first.Msg.GetPortPools()) != 2 || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("the first page: %v %v", first, err)
	}
	rest, err := ada.gw.ListPortPools(ctx, connect.NewRequest(&rpmgrv1.ListPortPoolsRequest{OrgId: org, GatewayGroupId: group, PageSize: 2,
		PageToken: first.Msg.GetNextPageToken()}))
	if err != nil || len(rest.Msg.GetPortPools()) != 1 {
		t.Fatalf("the last page: %v %v", rest, err)
	}

	resize := func(mask []string, from, to int32, etag string) (*rpmgrv1.PortPool, error) {
		r, err := ada.gw.UpdatePortPool(ctx, connect.NewRequest(&rpmgrv1.UpdatePortPoolRequest{
			PortPool: &rpmgrv1.PortPool{Id: pool.GetId(), PortFrom: from, PortTo: to, Protocol: udp}, UpdateMask: &fieldmaskpb.FieldMask{Paths: mask},
			Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetPortPool(), nil
	}
	if _, err := resize([]string{"port_to"}, 0, 20050, "1"); reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("a shrink that leaves out an allocated port: %v", err)
	}
	if _, err := resize([]string{"port_from"}, 20006, 0, "1"); reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("a shrink from below: %v", err)
	}
	up, err := resize([]string{"port_to"}, 0, 20199, "1")
	if err != nil || up.GetPortFrom() != 20000 || up.GetPortTo() != 20199 || up.GetEtag() != "2" || up.GetProtocol() != tcp ||
		up.GetAllocatedPorts() != 2 {
		t.Fatalf("a growth: %v %v", up, err)
	}
	if up, err = resize([]string{"port_from", "port_to"}, 20005, 20090, ""); err != nil || up.GetPortFrom() != 20005 || up.GetPortTo() != 20090 {
		t.Fatalf("a shrink to exactly the allocated ports: %v %v", up, err)
	}
	if _, err := resize([]string{"port_to"}, 0, 20199, "2"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if _, err := create(ada, tcp, 20300, 20399, ""); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		mask     []string
		from, to int32
	}{
		"into another pool": {[]string{"port_to"}, 0, 20300}, "below from": {[]string{"port_to"}, 0, 20004},
		"the protocol": {[]string{"protocol"}, 0, 0}, "the group": {[]string{"gateway_group_id"}, 0, 0}, "an empty mask": {nil, 0, 0},
	} {
		if _, err := resize(c.mask, c.from, c.to, ""); code(err) != connect.CodeInvalidArgument {
			t.Errorf("a resize %s: %v", name, err)
		}
	}

	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := create(vwr, tcp, 40000, 40001, ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer creates: %v", err)
	}
	if _, err := vwr.gw.GetPortPool(ctx, connect.NewRequest(&rpmgrv1.GetPortPoolRequest{PortPoolId: pool.GetId()})); err != nil {
		t.Fatalf("a Viewer reads: %v", err)
	}
	del := func(b *browser) error {
		_, err := b.gw.DeletePortPool(ctx, connect.NewRequest(&rpmgrv1.DeletePortPoolRequest{PortPoolId: pool.GetId()}))
		return err
	}
	if err := del(vwr); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer deletes: %v", err)
	}
	if err := del(ada); reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("a pool with allocated ports: %v", err)
	}
	e.db.Client().PortAllocation.Delete().Where(portallocation.GatewayGroupID(group)).ExecX(e.sys)
	if err := del(ada); err != nil {
		t.Fatalf("a pool without allocations: %v", err)
	}
	if _, err := ada.gw.GetPortPool(ctx, connect.NewRequest(&rpmgrv1.GetPortPoolRequest{PortPoolId: pool.GetId()})); code(err) != connect.CodeNotFound {
		t.Fatalf("a deleted pool: %v", err)
	}
}
