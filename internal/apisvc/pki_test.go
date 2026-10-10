// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestPki (docs/04-security.md, "CA hierarchy", "CA rotation"): the Instance Admin sees the CA's
// keys with their validity and when the schedule replaces them, and the root's pin; a rotation of
// the intermediate on request needs a step-up, retires the old one, which is still shown, and is
// served by this replica at once; no one else sees or rotates anything.
func TestPki(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		return pki.InitCA(e.sys, tx, e.sealer, "rpmgr-teststor", e.clock.Add(-time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(e.sys, e.db, e.sealer, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	e.pki.CA = ca
	status := func(b *browser) (*rpmgrv1.GetPkiStatusResponse, error) {
		r, err := b.pki.GetPkiStatus(ctx, connect.NewRequest(&rpmgrv1.GetPkiStatusRequest{}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	st, err := status(ada)
	if err != nil || st.GetTrustDomain() != "rpmgr-teststor" || st.GetRootPin() != pki.RootPin(ca.Root()) || len(st.GetKeys()) != 4 {
		t.Fatalf("the status: %v %v", st, err)
	}
	var inter *rpmgrv1.CAKey
	for _, k := range st.GetKeys() {
		if k.GetState() != rpmgrv1.CAKeyState_CA_KEY_STATE_ACTIVE || (k.GetKind() == rpmgrv1.CAKeyKind_CA_KEY_KIND_ROOT) != (k.GetRotateTime() == nil) {
			t.Errorf("a key: %v", k)
		}
		if k.GetKind() == rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE {
			inter = k
		}
	}
	half := inter.GetNotBefore().AsTime().Add(inter.GetNotAfter().AsTime().Sub(inter.GetNotBefore().AsTime()) / 2)
	if !inter.GetRotateTime().AsTime().Equal(half) {
		t.Errorf("the intermediate rotates at %v, want %v", inter.GetRotateTime().AsTime(), half)
	}

	rotate := func(b *browser) (*rpmgrv1.RotateIntermediateResponse, error) {
		r, err := b.pki.RotateIntermediate(ctx, connect.NewRequest(&rpmgrv1.RotateIntermediateRequest{}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	if _, err := rotate(ada); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a rotation without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	r, err := rotate(ada)
	if err != nil || r.GetIntermediate().GetSubject() == "" || !r.GetIntermediate().GetNotBefore().AsTime().After(inter.GetNotBefore().AsTime()) {
		t.Fatalf("a rotation: %v %v", r, err)
	}
	if !ca.Intermediate().NotBefore.Equal(r.GetIntermediate().GetNotBefore().AsTime()) {
		t.Errorf("this replica issues from the intermediate of %v, not the new one", ca.Intermediate().NotBefore)
	}
	st, err = status(ada)
	if err != nil || len(st.GetKeys()) != 5 || st.GetKeys()[len(st.GetKeys())-1].GetState() != rpmgrv1.CAKeyState_CA_KEY_STATE_RETIRED {
		t.Fatalf("the status after a rotation: %v %v", st, err)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.PkiService.RotateIntermediate"),
		auditentry.ResultEQ(auditentry.ResultSuccess)).CountX(e.sys); n != 1 {
		t.Errorf("%d audit entries of the rotation", n)
	}

	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := status(bob); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner reads the PKI status: %v", err)
	}
	if _, err := rotate(bob); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner rotates: %v", err)
	}
}
