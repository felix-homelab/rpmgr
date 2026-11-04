-- Modify "webhooks" table
ALTER TABLE "webhooks" ADD COLUMN "mention" character varying NOT NULL DEFAULT '', ADD COLUMN "mention_when" character varying NOT NULL DEFAULT 'never', ADD COLUMN "discord_username" character varying NOT NULL DEFAULT '', ADD COLUMN "discord_avatar_url" character varying NOT NULL DEFAULT '', ADD COLUMN "thread_name" character varying NOT NULL DEFAULT '';
-- Create "webhook_messages" table
CREATE TABLE "webhook_messages" ("id" character varying NOT NULL, "webhook_id" character varying NOT NULL, "org_id" character varying NULL, "alert_key" character varying NOT NULL, "message_id" character varying NOT NULL, "thread_id" character varying NOT NULL DEFAULT '', "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "webhook_messages_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhookmessage_created_at" to table: "webhook_messages"
CREATE INDEX "webhookmessage_created_at" ON "webhook_messages" ("created_at");
-- Create index "webhookmessage_webhook_id_alert_key" to table: "webhook_messages"
CREATE UNIQUE INDEX "webhookmessage_webhook_id_alert_key" ON "webhook_messages" ("webhook_id", "alert_key");
