-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_webhooks" table
CREATE TABLE `new_webhooks` (`id` text NOT NULL, `org_id` text NULL, `url` text NOT NULL, `secret_enc` blob NOT NULL, `previous_secret_enc` blob NULL, `previous_until` datetime NULL, `event_types` json NULL, `enabled` bool NOT NULL DEFAULT (true), `disabled_reason` text NULL, `enabled_at` datetime NOT NULL, `last_success_at` datetime NULL, `failing_since` datetime NULL, `created_at` datetime NOT NULL, `version` integer NOT NULL DEFAULT (1), `format` text NOT NULL DEFAULT ('rpmgr'), `url_enc` blob NULL, PRIMARY KEY (`id`), CONSTRAINT `webhooks_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "webhooks" to new temporary table "new_webhooks"
INSERT INTO `new_webhooks` (`id`, `org_id`, `url`, `secret_enc`, `previous_secret_enc`, `previous_until`, `event_types`, `enabled`, `disabled_reason`, `enabled_at`, `last_success_at`, `failing_since`, `created_at`, `version`) SELECT `id`, `org_id`, `url`, `secret_enc`, `previous_secret_enc`, `previous_until`, `event_types`, `enabled`, `disabled_reason`, `enabled_at`, `last_success_at`, `failing_since`, `created_at`, `version` FROM `webhooks`;
-- Drop "webhooks" table after copying rows
DROP TABLE `webhooks`;
-- Rename temporary table "new_webhooks" to "webhooks"
ALTER TABLE `new_webhooks` RENAME TO `webhooks`;
-- Create index "webhook_org_id" to table: "webhooks"
CREATE INDEX `webhook_org_id` ON `webhooks` (`org_id`);
-- Create index "webhook_enabled" to table: "webhooks"
CREATE INDEX `webhook_enabled` ON `webhooks` (`enabled`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
