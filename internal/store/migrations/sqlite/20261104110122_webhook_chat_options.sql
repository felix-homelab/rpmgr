-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_webhooks" table
CREATE TABLE `new_webhooks` (`id` text NOT NULL, `org_id` text NULL, `url` text NOT NULL, `secret_enc` blob NOT NULL, `previous_secret_enc` blob NULL, `previous_until` datetime NULL, `event_types` json NULL, `enabled` bool NOT NULL DEFAULT (true), `disabled_reason` text NULL, `enabled_at` datetime NOT NULL, `last_success_at` datetime NULL, `failing_since` datetime NULL, `created_at` datetime NOT NULL, `version` integer NOT NULL DEFAULT (1), `format` text NOT NULL DEFAULT ('rpmgr'), `url_enc` blob NULL, `mention` text NOT NULL DEFAULT (''), `mention_when` text NOT NULL DEFAULT ('never'), `discord_username` text NOT NULL DEFAULT (''), `discord_avatar_url` text NOT NULL DEFAULT (''), `thread_name` text NOT NULL DEFAULT (''), PRIMARY KEY (`id`), CONSTRAINT `webhooks_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "webhooks" to new temporary table "new_webhooks"
INSERT INTO `new_webhooks` (`id`, `org_id`, `url`, `secret_enc`, `previous_secret_enc`, `previous_until`, `event_types`, `enabled`, `disabled_reason`, `enabled_at`, `last_success_at`, `failing_since`, `created_at`, `version`, `format`, `url_enc`) SELECT `id`, `org_id`, `url`, `secret_enc`, `previous_secret_enc`, `previous_until`, `event_types`, `enabled`, `disabled_reason`, `enabled_at`, `last_success_at`, `failing_since`, `created_at`, `version`, `format`, `url_enc` FROM `webhooks`;
-- Drop "webhooks" table after copying rows
DROP TABLE `webhooks`;
-- Rename temporary table "new_webhooks" to "webhooks"
ALTER TABLE `new_webhooks` RENAME TO `webhooks`;
-- Create index "webhook_org_id" to table: "webhooks"
CREATE INDEX `webhook_org_id` ON `webhooks` (`org_id`);
-- Create index "webhook_enabled" to table: "webhooks"
CREATE INDEX `webhook_enabled` ON `webhooks` (`enabled`);
-- Create "webhook_messages" table
CREATE TABLE `webhook_messages` (`id` text NOT NULL, `webhook_id` text NOT NULL, `org_id` text NULL, `alert_key` text NOT NULL, `message_id` text NOT NULL, `thread_id` text NOT NULL DEFAULT (''), `created_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `webhook_messages_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhookmessage_webhook_id_alert_key" to table: "webhook_messages"
CREATE UNIQUE INDEX `webhookmessage_webhook_id_alert_key` ON `webhook_messages` (`webhook_id`, `alert_key`);
-- Create index "webhookmessage_created_at" to table: "webhook_messages"
CREATE INDEX `webhookmessage_created_at` ON `webhook_messages` (`created_at`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
