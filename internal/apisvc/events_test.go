// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
)

// TestEvents_APIChanges (#646): an API write that succeeds is an event of its org, typed by its
// method as <resource>.<verb>, naming its actor, its subject and the fields of its update mask; a
// refused write is none.
func TestEvents_APIChanges(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	in := gw
	in.Name = "gw-one"
	if _, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: in, Etag: in.GetEtag(),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}}})); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: in, Etag: "1",
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}}})); err == nil {
		t.Fatal("a stale etag was accepted")
	}
	rows, err := e.db.Client().Event.Query().Where(event.OrgID(org)).Order(ent.Asc(event.FieldID)).All(e.sys)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	var update *ent.Event
	for _, r := range rows {
		types = append(types, r.Type)
		if r.Type == "gateway.update" {
			update = r
		}
	}
	if update == nil || slices.Index(types, "gateway.create") > slices.Index(types, "gateway.update") ||
		slices.ContainsFunc(rows, func(r *ent.Event) bool { return r.Type == "gateway.update" && r != update }) {
		t.Fatalf("events %v, want gateway.create, then one gateway.update", types)
	}
	if update.ActorType != "user" || update.ActorID == "" || update.SubjectType != "gateway" || update.SubjectID != gw.GetId() ||
		!slices.Equal(update.Changed, []string{"name"}) {
		t.Fatalf("the update's event %+v", update)
	}
}
