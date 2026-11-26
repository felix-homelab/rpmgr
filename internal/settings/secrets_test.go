// SPDX-License-Identifier: Apache-2.0

package settings_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync"
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

func testKEK(t *testing.T) secret.KEK {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kek, err := secret.NewKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// TestInstanceKey: a key is made once, 32 random bytes sealed as a version 2 value with a
// secrets_meta row; every later call, with a new Sealer for the same KEK as after a restart, and
// every replica that asks at the same time reads the same key; the keys of two names differ.
func TestInstanceKey(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		sys := storetest.SystemCtx(t)
		kek := testKEK(t)
		sealer, _ := secret.NewSealer(kek)

		keys := make([][]byte, 8)
		var wg sync.WaitGroup
		for i := range keys {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Each goroutine is a replica with a Sealer of its own.
				s, _ := secret.NewSealer(kek)
				k, err := settings.InstanceKey(sys, db, s, settings.PageTokenKey)
				if err != nil {
					t.Error(err)
				}
				keys[i] = k
			}()
		}
		wg.Wait()
		if len(keys[0]) != 32 || bytes.Equal(keys[0], make([]byte, 32)) {
			t.Fatalf("key %x", keys[0])
		}
		for _, k := range keys {
			if !bytes.Equal(k, keys[0]) {
				t.Fatal("replicas made different keys")
			}
		}
		again, err := settings.InstanceKey(sys, db, sealer, settings.PageTokenKey)
		if err != nil || !bytes.Equal(again, keys[0]) {
			t.Fatalf("after a restart: %v", err)
		}
		other, err := settings.InstanceKey(sys, db, sealer, settings.PagePreviewKey)
		if err != nil || bytes.Equal(other, keys[0]) {
			t.Fatalf("preview key: %v", err)
		}

		row := db.Client().InstanceSecret.GetX(sys, settings.PageTokenKey)
		if bytes.Contains(row.ValueEnc, keys[0]) || row.ValueEnc[0] != 2 {
			t.Fatal("the key is stored in plain, or not as version 2")
		}
		if n := db.Client().SecretMeta.Query().CountX(sys); n != 2 {
			t.Fatalf("%d secrets_meta rows, want 2", n)
		}
		// Another KEK cannot read it, and does not replace it.
		if _, err := settings.InstanceKey(sys, db, func() *secret.Sealer { s, _ := secret.NewSealer(testKEK(t)); return s }(), settings.PageTokenKey); err == nil {
			t.Fatal("a key opened under another KEK")
		}
		if still := db.Client().InstanceSecret.GetX(sys, settings.PageTokenKey); !bytes.Equal(still.ValueEnc, row.ValueEnc) {
			t.Fatal("a failed read replaced the stored key")
		}
		// A key rewrapped under a new KEK is the same key.
		next := testKEK(t)
		rotated, _ := secret.NewSealer(next, kek)
		re, err := rotated.Rewrap(context.Background(), secret.Context{Table: "instance_secrets", Column: "value_enc", RowID: settings.PageTokenKey}, row.ValueEnc)
		if err != nil {
			t.Fatal(err)
		}
		db.Client().InstanceSecret.UpdateOneID(settings.PageTokenKey).SetValueEnc(re).ExecX(sys)
		after, _ := secret.NewSealer(next)
		if k, err := settings.InstanceKey(sys, db, after, settings.PageTokenKey); err != nil || !bytes.Equal(k, keys[0]) {
			t.Fatalf("after a KEK rotation: %v", err)
		}
	})
}

// TestInstanceKeyWrongLength: a stored value that is not 32 bytes is an error, not a key.
func TestInstanceKeyWrongLength(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	sys := storetest.SystemCtx(t)
	sealer, _ := secret.NewSealer(testKEK(t))
	if err := settings.SetInstanceSecret(sys, db, sealer, settings.PageTokenKey, secret.New("short")); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.InstanceKey(sys, db, sealer, settings.PageTokenKey); err == nil {
		t.Fatal("a 5-byte key accepted")
	}
}

// TestInstanceKeyRefusesOtherNames: only the two keys of the design are made here, so no other
// row of instance_secrets is filled with random bytes.
func TestInstanceKeyRefusesOtherNames(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	sys := storetest.SystemCtx(t)
	sealer, _ := secret.NewSealer(testKEK(t))
	for _, name := range []string{settings.SMTPPassword, "", "page_token_key ", "other"} {
		if _, err := settings.InstanceKey(sys, db, sealer, name); err == nil {
			t.Errorf("InstanceKey made %q", name)
		}
	}
	if n := db.Client().InstanceSecret.Query().CountX(sys); n != 0 {
		t.Fatalf("%d rows made", n)
	}
}
