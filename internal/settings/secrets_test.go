// SPDX-License-Identifier: Apache-2.0

package settings_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestInstanceSecret: a secret is stored sealed, read back, replaced, and removed by an empty
// value; one never set reads as empty; a database dump does not hold it.
func TestInstanceSecret(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	sys := storetest.SystemCtx(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kek, _ := secret.NewKEK(key)
	sealer, _ := secret.NewSealer(kek)
	if v, err := settings.InstanceSecret(sys, db.Client(), sealer, settings.SMTPPassword); err != nil || !v.IsZero() {
		t.Fatalf("never set: %v", err)
	}
	for _, pw := range []string{"first password", "second password"} {
		if err := settings.SetInstanceSecret(sys, db, sealer, settings.SMTPPassword, secret.New(pw)); err != nil {
			t.Fatal(err)
		}
		v, err := settings.InstanceSecret(sys, db.Client(), sealer, settings.SMTPPassword)
		if err != nil || v.Reveal() != pw { //nolint:forbidigo // the test reads back the secret it stored
			t.Fatalf("read back: %v", err)
		}
		row := db.Client().InstanceSecret.GetX(sys, settings.SMTPPassword)
		if bytes.Contains(row.ValueEnc, []byte(pw)) {
			t.Fatal("stored in plain")
		}
	}
	if err := settings.SetInstanceSecret(sys, db, sealer, settings.SMTPPassword, secret.Value{}); err != nil {
		t.Fatal(err)
	}
	if v, _ := settings.InstanceSecret(sys, db.Client(), sealer, settings.SMTPPassword); !v.IsZero() {
		t.Fatal("not removed")
	}
}
