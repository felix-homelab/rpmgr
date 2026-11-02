// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// TestMigrate_WebhookFormats (D162): the migration that adds a webhook's format and sealed URL
// keeps the endpoints and their deliveries of the schema before it, which become rpmgr endpoints
// with no sealed URL and still sign with their secrets, on SQLite by rebuilding the table, and
// afterwards a chat endpoint can be stored.
func TestMigrate_WebhookFormats(t *testing.T) {
	forEachStoreDB(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		full, err := migrations.Dir(db.Dialect)
		if err != nil {
			t.Fatal(err)
		}
		files, err := full.Files()
		if err != nil {
			t.Fatal(err)
		}
		var before []string
		for _, f := range files {
			if strings.HasSuffix(f.Name(), "_webhook_formats.sql") {
				break
			}
			before = append(before, f.Name(), string(f.Bytes()))
		}
		if len(before) == len(files)*2 || len(before) == 0 {
			t.Fatalf("the migration is not among %d files", len(files))
		}
		if _, err := store.Migrate(ctx, db, testDir(t, before...)); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Format("2006-01-02 15:04:05")
		org, hook := ids.New("org"), ids.New("whk")
		for _, q := range []string{
			"INSERT INTO orgs (id, name, slug, created_at) VALUES ('" + org + "', 'a', 'a', '" + now + "')",
			"INSERT INTO webhooks (id, org_id, url, secret_enc, event_types, enabled, enabled_at, created_at, version) VALUES ('" + hook + "', '" + org +
				"', 'https://hooks.example.com/a', 'sealed', '[\"route.*\"]', true, '" + now + "', '" + now + "', 3)",
			"INSERT INTO webhook_deliveries (id, webhook_id, org_id, event_id, event_type, attempt, status_code, error, sent_at) VALUES ('" +
				ids.New("whd") + "', '" + hook + "', '" + org + "', 'evt_1', 'route.update', 1, 200, '', '" + now + "')",
		} {
			if _, err := db.Writer.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}

		if n, err := store.Migrate(ctx, db, full); err != nil || n == 0 {
			t.Fatalf("%d migrations applied: %v", n, err)
		}
		for q, want := range map[string]int{
			"SELECT count(*) FROM webhooks WHERE id = '" + hook + "' AND format = 'rpmgr' AND url_enc IS NULL AND version = 3 AND enabled AND secret_enc IS NOT NULL": 1,
			"SELECT count(*) FROM webhooks WHERE id = '" + hook + "' AND url = 'https://hooks.example.com/a' AND org_id = '" + org + "'":                          1,
			"SELECT count(*) FROM webhook_deliveries WHERE webhook_id = '" + hook + "'":                                                                         1,
		} {
			if got := count(t, db, q); got != want {
				t.Errorf("%s: %d, want %d", q, got, want)
			}
		}
		// The endpoint reads through Ent and a chat endpoint is stored beside it.
		c := store.NewClient(db.Dialect, db.Writer)
		sys := orgCtx(t, org)
		row := c.Webhook.GetX(sys, hook)
		if string(row.Format) != "rpmgr" || row.URLEnc != nil && len(*row.URLEnc) != 0 {
			t.Fatalf("the migrated endpoint: %+v", row)
		}
		chat := c.Webhook.Create().SetOrgID(org).SetURL("https://discord.com").SetFormat("discord").SetURLEnc([]byte("sealed")).SetSecretEnc([]byte{}).SaveX(sys)
		if got := c.Webhook.GetX(sys, chat.ID); string(got.Format) != "discord" || string(*got.URLEnc) != "sealed" || len(got.SecretEnc) != 0 {
			t.Fatalf("the chat endpoint: %+v", got)
		}
		if _, err := db.Writer.ExecContext(ctx, "UPDATE webhooks SET format = NULL WHERE id = $1", hook); err == nil {
			t.Error("a webhook without a format was accepted")
		}
	})
}
