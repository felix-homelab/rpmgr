// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestStoreResolver: a resource's ID resolves to its org, whichever org asks; an ID no resource
// has, a malformed one and one of a kind the API does not name by ID resolve to ErrNotFound.
func TestStoreResolver(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		sys := storetest.SystemCtx(t)
		orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		c := db.Client()
		groupA := c.GatewayGroup.Create().SetOrgID(orgA).SetName("eu").SaveX(sys)
		groupB := c.GatewayGroup.Create().SetOrgID(orgB).SetName("eu").SaveX(sys)
		route := c.Route.Create().SetOrgID(orgB).SetName("web").SetType("http").SetGatewayGroupID(groupB.ID).SaveX(sys)
		resolve := api.StoreResolver(db, sys)
		for id, want := range map[string]string{groupA.ID: orgA, groupB.ID: orgB, route.ID: orgB} {
			if got, err := resolve(context.Background(), id); err != nil || got != want {
				t.Errorf("%s: %q %v, want %q", id, got, err, want)
			}
		}
		for _, id := range []string{ids.New("rt"), ids.New("gwg"), "rt_not-an-id", "rt", "", ids.New("usr"), ids.New("aud"), orgA} {
			if got, err := resolve(context.Background(), id); !errors.Is(err, api.ErrNotFound) {
				t.Errorf("%q: %q %v, want ErrNotFound", id, got, err)
			}
		}
	})
}

// TestStoreOperatorsMayEnroll: the org setting is off by default and read per org.
func TestStoreOperatorsMayEnroll(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	orgA, orgB := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
	may := api.StoreOperatorsMayEnroll(db, sys)
	if ok, err := may(context.Background(), orgA); err != nil || ok {
		t.Fatalf("by default: %v %v", ok, err)
	}
	if _, err := settings.UpdateOrg(sys, db, orgA, &rpmgrv1.OrgSettings{OperatorsMayEnroll: proto.Bool(true)},
		&fieldmaskpb.FieldMask{Paths: []string{"operators_may_enroll"}}, 0); err != nil {
		t.Fatal(err)
	}
	if ok, err := may(context.Background(), orgA); err != nil || !ok {
		t.Fatalf("allowed: %v %v", ok, err)
	}
	if ok, err := may(context.Background(), orgB); err != nil || ok {
		t.Fatalf("another org: %v %v", ok, err)
	}
}
