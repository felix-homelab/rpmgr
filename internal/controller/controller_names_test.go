// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"slices"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestControllerNames: the names a DNS target may not point at are the public URL's host and, while
// the instance settings list none, nothing more; the endpoints it advertises are named too.
func TestControllerNames(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	sys := storetest.SystemCtx(t)
	storetest.Init(t, db)
	var got []string
	_, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
		var err error
		got, err = controller.ControllerNames("https://ctl.example:8443")(sys, tx)
		return nil, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, "ctl.example") {
		t.Fatalf("names: %v", got)
	}
}
