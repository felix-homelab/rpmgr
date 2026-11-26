// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// TestPkiStatusWithPendingIntermediate: while the next intermediate waits for the signature of an
// offline root (no certificate yet), the status still loads and shows the keys that have one.
func TestPkiStatusWithPendingIntermediate(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		return castore.InitCA(e.sys, tx, e.sealer, "rpmgr-teststor", e.clock.Add(-time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := castore.PlanRootExport(e.sys, e.db.ReadClient().CAKey, e.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := plan.Apply(e.sys, tx, "correct horse battery staple 42", func(f []byte) ([]byte, error) { return f, nil })
		return err
	}); err != nil {
		t.Fatal(err)
	}
	reqPlan, err := castore.PlanSigningRequest(e.sys, e.db.ReadClient().CAKey, e.sealer, e.clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := reqPlan.Apply(e.sys, tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err := ada.pki.GetPkiStatus(context.Background(), connect.NewRequest(&rpmgrv1.GetPkiStatusRequest{}))
	if err != nil {
		t.Fatalf("GetPkiStatus with a pending intermediate: %v", err)
	}
	if len(r.Msg.Keys) != 4 || r.Msg.RootPin == "" {
		t.Fatalf("status shows %d keys and pin %q, want the 4 active keys and the root's pin", len(r.Msg.Keys), r.Msg.RootPin)
	}
	if !r.Msg.RootOffline {
		t.Error("the status does not say that the root is offline")
	}
	if !r.Msg.RootKekUnknown {
		t.Error("an offline root with no audit entry of the ceremony must say that the KEK is unknown")
	}
	if r.Msg.SigningAlert != rpmgrv1.SigningAlert_SIGNING_ALERT_NEEDS_SIGNING || len(r.Msg.NextIntermediateKeyHash) != 64 {
		t.Errorf("alert %v, key hash %q: want needs-signing and the hash of the waiting key", r.Msg.SigningAlert, r.Msg.NextIntermediateKeyHash)
	}
	// 30 days before the active intermediate expires the alert is critical.
	var expires time.Time
	for _, k := range r.Msg.Keys {
		if k.Kind == rpmgrv1.CAKeyKind_CA_KEY_KIND_INTERMEDIATE {
			expires = k.NotAfter.AsTime()
		}
	}
	e.pki.Now = func() time.Time { return expires.Add(-castore.IntermediateSigningCritical) }
	if c, err := ada.pki.GetPkiStatus(context.Background(), connect.NewRequest(&rpmgrv1.GetPkiStatusRequest{})); err != nil ||
		c.Msg.SigningAlert != rpmgrv1.SigningAlert_SIGNING_ALERT_CRITICAL {
		t.Errorf("30 days before the expiry: %v %v", c, err)
	}
	e.pki.Now = nil
	// The Settings button rotates with the online root only: with an offline one it is refused, and
	// says so.
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	_, err = ada.pki.RotateIntermediate(context.Background(), connect.NewRequest(&rpmgrv1.RotateIntermediateRequest{}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("RotateIntermediate with an offline root: %v", err)
	}
}
