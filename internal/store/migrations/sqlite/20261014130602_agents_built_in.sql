-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_enrollment_tokens" table
CREATE TABLE `new_enrollment_tokens` (`id` text NOT NULL, `org_id` text NOT NULL, `token_hash` blob NOT NULL, `role` text NOT NULL, `labels` json NULL, `ephemeral` bool NOT NULL DEFAULT (false), `built_in` bool NOT NULL DEFAULT (false), `max_uses` integer NULL, `use_count` integer NOT NULL DEFAULT (0), `expires_at` datetime NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `last_used_at` datetime NULL, `last_used_ip` text NULL, `revoked_at` datetime NULL, `gateway_group_id` text NULL, `gateway_id` text NULL, `connector_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `enrollment_tokens_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_gateways_gateway` FOREIGN KEY (`org_id`, `gateway_id`) REFERENCES `gateways` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_connectors_connector` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "enrollment_tokens" to new temporary table "new_enrollment_tokens"
INSERT INTO `new_enrollment_tokens` (`id`, `org_id`, `token_hash`, `role`, `labels`, `ephemeral`, `max_uses`, `use_count`, `expires_at`, `created_by`, `created_at`, `last_used_at`, `last_used_ip`, `revoked_at`, `gateway_group_id`, `gateway_id`, `connector_id`) SELECT `id`, `org_id`, `token_hash`, `role`, `labels`, `ephemeral`, `max_uses`, `use_count`, `expires_at`, `created_by`, `created_at`, `last_used_at`, `last_used_ip`, `revoked_at`, `gateway_group_id`, `gateway_id`, `connector_id` FROM `enrollment_tokens`;
-- Drop "enrollment_tokens" table after copying rows
DROP TABLE `enrollment_tokens`;
-- Rename temporary table "new_enrollment_tokens" to "enrollment_tokens"
ALTER TABLE `new_enrollment_tokens` RENAME TO `enrollment_tokens`;
-- Create index "enrollment_tokens_token_hash_key" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_key` ON `enrollment_tokens` (`token_hash`);
-- Create index "enrollmenttoken_org_id_id" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollmenttoken_org_id_id` ON `enrollment_tokens` (`org_id`, `id`);
-- Create "new_connectors" table
CREATE TABLE `new_connectors` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `labels` json NULL, `spiffe_id` text NOT NULL, `pubkey_sha256` text NOT NULL, `ephemeral` bool NOT NULL DEFAULT (false), `enabled` bool NOT NULL DEFAULT (true), `transport` text NULL, `desired_version` text NULL, `built_in` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `connectors_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "connectors" to new temporary table "new_connectors"
INSERT INTO `new_connectors` (`id`, `org_id`, `version`, `name`, `labels`, `spiffe_id`, `pubkey_sha256`, `ephemeral`, `enabled`, `transport`, `desired_version`, `created_at`, `decommissioned_at`) SELECT `id`, `org_id`, `version`, `name`, `labels`, `spiffe_id`, `pubkey_sha256`, `ephemeral`, `enabled`, `transport`, `desired_version`, `created_at`, `decommissioned_at` FROM `connectors`;
-- Drop "connectors" table after copying rows
DROP TABLE `connectors`;
-- Rename temporary table "new_connectors" to "connectors"
ALTER TABLE `new_connectors` RENAME TO `connectors`;
-- Create index "connector_org_id_id" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_id` ON `connectors` (`org_id`, `id`);
-- Create index "connector_org_id_name" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_name` ON `connectors` (`org_id`, `name`) WHERE decommissioned_at IS NULL;
-- Create "new_gateways" table
CREATE TABLE `new_gateways` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `slot` integer NOT NULL, `tunnel_endpoints` json NOT NULL, `spiffe_id` text NULL, `pubkey_sha256` text NULL, `enabled` bool NOT NULL DEFAULT (true), `desired_version` text NULL, `built_in` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateways_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `gateways_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "gateways" to new temporary table "new_gateways"
INSERT INTO `new_gateways` (`id`, `org_id`, `version`, `name`, `slot`, `tunnel_endpoints`, `spiffe_id`, `pubkey_sha256`, `enabled`, `desired_version`, `created_at`, `decommissioned_at`, `gateway_group_id`) SELECT `id`, `org_id`, `version`, `name`, `slot`, `tunnel_endpoints`, `spiffe_id`, `pubkey_sha256`, `enabled`, `desired_version`, `created_at`, `decommissioned_at`, `gateway_group_id` FROM `gateways`;
-- Drop "gateways" table after copying rows
DROP TABLE `gateways`;
-- Rename temporary table "new_gateways" to "gateways"
ALTER TABLE `new_gateways` RENAME TO `gateways`;
-- Create index "gateway_org_id_id" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_id` ON `gateways` (`org_id`, `id`);
-- Create index "gateway_org_id_name" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_name` ON `gateways` (`org_id`, `name`) WHERE decommissioned_at IS NULL;
-- Create index "gateway_gateway_group_id_slot" to table: "gateways"
CREATE UNIQUE INDEX `gateway_gateway_group_id_slot` ON `gateways` (`gateway_group_id`, `slot`) WHERE decommissioned_at IS NULL;
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
