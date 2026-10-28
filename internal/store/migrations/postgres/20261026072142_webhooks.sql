-- Create "webhook_deliveries" table
CREATE TABLE "webhook_deliveries" ("id" character varying NOT NULL, "webhook_id" character varying NOT NULL, "org_id" character varying NULL, "event_id" character varying NOT NULL, "event_type" character varying NOT NULL DEFAULT '', "attempt" bigint NOT NULL, "status_code" bigint NOT NULL DEFAULT 0, "error" character varying NOT NULL DEFAULT '', "sent_at" timestamptz NOT NULL, "next_attempt_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "webhook_deliveries_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhookdelivery_next_attempt_at" to table: "webhook_deliveries"
CREATE INDEX "webhookdelivery_next_attempt_at" ON "webhook_deliveries" ("next_attempt_at");
-- Create index "webhookdelivery_webhook_id_event_id_attempt" to table: "webhook_deliveries"
CREATE UNIQUE INDEX "webhookdelivery_webhook_id_event_id_attempt" ON "webhook_deliveries" ("webhook_id", "event_id", "attempt");
-- Create index "webhookdelivery_webhook_id_sent_at" to table: "webhook_deliveries"
CREATE INDEX "webhookdelivery_webhook_id_sent_at" ON "webhook_deliveries" ("webhook_id", "sent_at");
-- Create "webhooks" table
CREATE TABLE "webhooks" ("id" character varying NOT NULL, "org_id" character varying NULL, "url" character varying NOT NULL, "secret_enc" bytea NOT NULL, "previous_secret_enc" bytea NULL, "previous_until" timestamptz NULL, "event_types" jsonb NULL, "enabled" boolean NOT NULL DEFAULT true, "disabled_reason" character varying NULL, "enabled_at" timestamptz NOT NULL, "last_success_at" timestamptz NULL, "failing_since" timestamptz NULL, "created_at" timestamptz NOT NULL, "version" bigint NOT NULL DEFAULT 1, PRIMARY KEY ("id"), CONSTRAINT "webhooks_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhook_enabled" to table: "webhooks"
CREATE INDEX "webhook_enabled" ON "webhooks" ("enabled");
-- Create index "webhook_org_id" to table: "webhooks"
CREATE INDEX "webhook_org_id" ON "webhooks" ("org_id");
