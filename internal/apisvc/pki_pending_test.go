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
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := castore.ExportRootOffline(e.sys, tx, e.sealer, "correct horse battery staple 42", func(f []byte) ([]byte, error) { return f, nil })
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := castore.RequestIntermediateSigning(e.sys, tx, e.sealer, e.clock)
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
}
