-- Create "webhooks" table
CREATE TABLE `webhooks` (`id` text NOT NULL, `org_id` text NULL, `url` text NOT NULL, `secret_enc` blob NOT NULL, `previous_secret_enc` blob NULL, `previous_until` datetime NULL, `event_types` json NULL, `enabled` bool NOT NULL DEFAULT (true), `disabled_reason` text NULL, `enabled_at` datetime NOT NULL, `last_success_at` datetime NULL, `failing_since` datetime NULL, `created_at` datetime NOT NULL, `version` integer NOT NULL DEFAULT (1), PRIMARY KEY (`id`), CONSTRAINT `webhooks_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhook_org_id" to table: "webhooks"
CREATE INDEX `webhook_org_id` ON `webhooks` (`org_id`);
-- Create index "webhook_enabled" to table: "webhooks"
CREATE INDEX `webhook_enabled` ON `webhooks` (`enabled`);
-- Create "webhook_deliveries" table
CREATE TABLE `webhook_deliveries` (`id` text NOT NULL, `webhook_id` text NOT NULL, `org_id` text NULL, `event_id` text NOT NULL, `event_type` text NOT NULL DEFAULT (''), `attempt` integer NOT NULL, `status_code` integer NOT NULL DEFAULT (0), `error` text NOT NULL DEFAULT (''), `sent_at` datetime NOT NULL, `next_attempt_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `webhook_deliveries_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhookdelivery_webhook_id_event_id_attempt" to table: "webhook_deliveries"
CREATE UNIQUE INDEX `webhookdelivery_webhook_id_event_id_attempt` ON `webhook_deliveries` (`webhook_id`, `event_id`, `attempt`);
-- Create index "webhookdelivery_next_attempt_at" to table: "webhook_deliveries"
CREATE INDEX `webhookdelivery_next_attempt_at` ON `webhook_deliveries` (`next_attempt_at`);
-- Create index "webhookdelivery_webhook_id_sent_at" to table: "webhook_deliveries"
CREATE INDEX `webhookdelivery_webhook_id_sent_at` ON `webhook_deliveries` (`webhook_id`, `sent_at`);
